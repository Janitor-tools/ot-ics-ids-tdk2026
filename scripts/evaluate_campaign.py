#!/usr/bin/env python3
"""
evaluate_campaign.py -- Milestone 6 kiertekelo szkript.

A 2026-08-22-i, 69 epizodos S-kategorias kampany (attack_log.jsonl) es a
valodi SIEM-VM Elasticsearch-adata alapjan szamolja a TP/FN/FP-t,
makro-/mikro-F1-et es a bootstrap konfidenciaintervallumokat --
Milestone5-Terv.md C) es E) szakasza szerint, a 2026-08-23-i /grill-me
munkamenetben lezart dontesek (Q1-Q11) architekturaja szerint.

VERIFIKALT TENYEK, amikre a script epit (nem feltetelezes):
  - attack_log.jsonl: /home/ot/attack_log.jsonl (Red-Team-VM), 69 sor,
    D5/D6/D7 szerinti formatumban.
  - A kampany tenyleges idoablaka NEM a tervezett 240 perc, hanem
    ~179 perc: 2026-08-22T13:48:33.811050+00:00 (benign_generator.py
    "generator_started" meta-esemeny) -- 2026-08-22T16:47:28.943719+00:00
    ("generator_stopped"). Forrasa: benign_log.jsonl meta-sorai, a
    Red-Team-VM-en kozvetlenul lekerdezve. A ~61 perces elteres a
    Milestone5-Terv.md D8 (240 perc, befagyasztott) tervhez kepest a
    6. fejezetben kulon dokumentalando "Modszertani eltmresek"
    alfejezetben (lasd a /grill-me Q11 dontese).
  - icsnpp_modbus index: van pdu_type, function, DE nincs regiszterertek.
  - icsnpp_modbus_detailed index: van request_values/response_values,
    EGYUTT, egy tranzakcio egy dokumentumaban (a WRITE dokumentumon a
    ket mezo protokoll-szinten mindig egyezik -- ez NEM bizonyitja, hogy
    az ertek valtozott, mert a Modbus write-response echo-zza a kert
    erteket; a "tenyleges valtozas" csak az elozo READ response_values-
    ahoz kepest allapithato meg).
  - icsnpp_s7comm index: icsnpp.s7comm.function_name == "PLC Stop" a
    tenyleges, indexelt ertek T0816/A.4-re (nem csak function_code 0x29).
  - Az ES ingest pipeline `date` processzora az icsnpp.modbus.ts (Zeek
    csomagido) mezobol tolti fel a @timestamp-et, majd torli az eredeti
    ts mezot -- a @timestamp tehat esemenyido, nem ingest-ido (verifikalva
    a siem-en levo _ingest/pipeline definicioval).

ARCHITEKTURA (Q1/Q3/Q10 szerint lezarva):
  1. attack_log.jsonl helyi masolata (data/campaign_2026-08-22/) --
     ELOFELTETEL, kulon scp-vel mar behozva, ez a script nem huzza be
     automatikusan (a scp egyszeri, kezi lepes volt a /grill-me
     munkamenetben).
  2. Egyszeri SSH local port-forward tunnel a siem-hez (nem -f, hogy a
     Popen-fogantyu a script veget varhassa es garantaltan le tudja
     allitani -- lasd SSHTunnel).
  3. Tunnel-egeszsegellenorzes (GET /) heavy lekerdezesek elott.
  4. EQL + DSL lekerdezesek, MINDEGYIK a teljes, tenyleges kampanyablakra
     (nem a tervezett 240 percre), egy-egy lekerdezessel (nem
     epizodonkenti/parankenti), a join memoriaban tortenik.
  5. FP-maszkolas: minden epizod [start_ts-5s, end_ts+5s] ablaka
     kimaszkolva a teljes kampanyablakbol, technikahatarok nelkul (Q5).
  6. Bootstrap: retegzett a makro-recall-hoz (Q8), blokk-bootstrap
     (5 perces binek) az FP-szamlalashoz/precision/F1-hez (Q9), np.random
     seed=42, B=10000, determinisztikus.
  7. Kimenet: JSON (gepi) + Markdown (ember-olvashato, LaTeX-tablazatokhoz
     igazitva, kepletekkel).
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import numpy as np

# ---------------------------------------------------------------------------
# KONFIGURACIO -- verifikalt tenyekre epitve, lasd modulszintu docstring
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
LOCAL_ATTACK_LOG = REPO_ROOT / "data" / "campaign_2026-08-22" / "attack_log.jsonl"
RESULTS_DIR = REPO_ROOT / "results"

SIEM_SSH_HOST = "siem"          # ~/.ssh/config alias, a /grill-me soran mar igazoltan mukodik
ES_LOCAL_PORT = 9200
ES_BASE_URL = f"http://127.0.0.1:{ES_LOCAL_PORT}"

# VERIFIKALT: benign_generator.py meta-esemenyei, Red-Team-VM,
# /home/ot/benign_log.jsonl -- NEM a tervezett 240 perc (D8), lasd fent.
CAMPAIGN_START = "2026-08-22T13:48:33.811050+00:00"
CAMPAIGN_END = "2026-08-22T16:47:28.943719+00:00"

ATTACKER_IP = "192.168.1.50"    # nem allowlistelt tamadasi identitas
ALLOWLIST_IP = "192.168.1.51"   # D2 szerinti masodlagos, "engineering station" alias
TARGET_IP = "192.168.1.100"

WINDOW_TOLERANCE_S = 5.0        # C) szakasz szerinti +/-5s toleranciaablak
JOIN_TOLERANCE_S = 2.0          # EQL-esemeny <-> modbus_detailed dokumentum parositasi tolerancia
FP_BIN_SECONDS = 300            # blokk-bootstrap binmeret (5 perc)
BOOTSTRAP_B = 10_000
BOOTSTRAP_SEED = 42
MIN_N_FOR_CI = 10               # E) szakasz szerinti kuszob

MODBUS_INDEX = "logs-zeek.icsnpp_modbus-otlab"
MODBUS_DETAILED_INDEX = "logs-zeek.icsnpp_modbus_detailed-otlab"
S7COMM_INDEX = "logs-zeek.icsnpp_s7comm-otlab"

# Az elozetesen a 4_Rendszertervezes.tex-ben mar futtatott es igazolt naiv
# EQL-szabaly, szo szerint atveve (lasd 4_Rendszertervezes.tex:87-93).
NAIVE_EQL_QUERY = (
    'sequence by source.ip with maxspan=10s\n'
    '  [network where event.dataset == "zeek.icsnpp_modbus" '
    'and icsnpp.modbus.function == "READ_HOLDING_REGISTERS" '
    'and icsnpp.modbus.pdu_type == "REQ"]\n'
    '  [network where event.dataset == "zeek.icsnpp_modbus" '
    'and icsnpp.modbus.function == "WRITE_SINGLE_REGISTER" '
    'and icsnpp.modbus.pdu_type == "REQ"]'
)

# Technikank per szcenario -- az epizod_id elotagjabol szarmaztatva.
# has_rule=False technikaknal a recall garantaltan 0, a precision/F1
# definialatlan (N/A), lasd Q7 dontes.
SCENARIO_HAS_RULE = {"A1": True, "A2": False, "A3": False, "A4": True, "A5": False, "A6": False}
# Javitva 2026-08-25 (2.4/0.1 tetel): A.2/A.3 technika-ID-je felcserelve a hivatalos
# MITRE-definiciohoz kepest korabban forditva allt -- lasd TDK-Zarokor-Feladatlista.md.
SCENARIO_TECHNIQUE = {"A1": "T0836", "A2": "T0888", "A3": "T0846", "A4": "T0816", "A5": "T0816", "A6": "T0843"}


# ---------------------------------------------------------------------------
# SSH tunnel -- Q10 szerint: nincs '-f' (hogy a Popen-fogantyu a folyamatot
# tenylegesen kezben tartsa), garantalt leallitas try/finally-vel.
# ---------------------------------------------------------------------------

class SSHTunnel:
    def __init__(self, ssh_host: str, local_port: int, remote_port: int = 9200):
        self._cmd = [
            "ssh", "-N",
            "-L", f"{local_port}:127.0.0.1:{remote_port}",
            "-o", "ExitOnForwardFailure=yes",
            "-o", "ServerAliveInterval=15",
            ssh_host,
        ]
        self._proc: Optional[subprocess.Popen] = None

    def __enter__(self) -> "SSHTunnel":
        self._proc = subprocess.Popen(self._cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self._wait_healthy()
        return self

    def _wait_healthy(self, timeout_s: float = 15.0) -> None:
        deadline = time.monotonic() + timeout_s
        last_err: Optional[BaseException] = None
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                stderr = self._proc.stderr.read().decode(errors="replace") if self._proc.stderr else ""
                raise RuntimeError(f"SSH tunnel folyamat idő előtt leállt: {stderr}")
            try:
                with urllib.request.urlopen(f"{ES_BASE_URL}/", timeout=2) as resp:
                    if resp.status == 200:
                        return
            except (urllib.error.URLError, ConnectionError) as exc:
                last_err = exc
                time.sleep(0.5)
        raise RuntimeError(f"SSH tunnel nem allt fel {timeout_s}s alatt: {last_err}")

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=5)


def es_request(method: str, path: str, body: Optional[dict] = None) -> dict:
    url = f"{ES_BASE_URL}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                  headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ---------------------------------------------------------------------------
# Ido-segedfuggvenyek
# ---------------------------------------------------------------------------

def parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def to_es_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


CAMPAIGN_START_DT = parse_ts(CAMPAIGN_START)
CAMPAIGN_END_DT = parse_ts(CAMPAIGN_END)


# ---------------------------------------------------------------------------
# Ground truth betoltese es szures (Q2 szerint: nyers attack_log.jsonl,
# szures futasidoben, nincs kulon "ground truth" fajl)
# ---------------------------------------------------------------------------

@dataclass
class Episode:
    episode_id: str
    scenario_id: str
    technique: str
    status: str
    start: datetime
    end: datetime
    source_ip: str

    @property
    def window(self) -> tuple[datetime, datetime]:
        return (self.start - timedelta(seconds=WINDOW_TOLERANCE_S),
                self.end + timedelta(seconds=WINDOW_TOLERANCE_S))


def load_ground_truth(path: Path) -> list[Episode]:
    episodes: list[Episode] = []
    excluded_error = 0
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            scenario_id = rec["episode_id"].split("_")[0]
            if rec["status"] == "error":
                # A.1 3 ModbusIOException epizod -- jovahagyott kizaras,
                # N_effective=17 T0836-ra. Lasd ICS-Lab-Allapot-Atadas.md
                # 2026-08-22-i felhasznaloi dontese.
                excluded_error += 1
                continue
            episodes.append(Episode(
                episode_id=rec["episode_id"],
                scenario_id=scenario_id,
                technique=rec["mitre_technique_id"],
                status=rec["status"],
                start=parse_ts(rec["start_ts"]),
                end=parse_ts(rec["end_ts"]),
                source_ip=rec["source_ip"],
            ))
    print(f"[ground_truth] {len(episodes)} ervenyes epizod betoltve, "
          f"{excluded_error} 'error' statuszu epizod kizarva (N_effective csokkentese).")
    return episodes


# ---------------------------------------------------------------------------
# T0836 (A.1) -- naiv EQL + finomitott Python-utoszures (Q3 szerint)
# ---------------------------------------------------------------------------

@dataclass
class ModbusAlert:
    source_ip: str
    read_ts: datetime
    write_ts: datetime
    value_before: Optional[int] = None
    value_after: Optional[int] = None
    refined_fires: bool = False


def fetch_naive_t0836_alerts() -> list[ModbusAlert]:
    body = {
        "query": NAIVE_EQL_QUERY,
        "filter": {"range": {"@timestamp": {"gte": CAMPAIGN_START, "lte": CAMPAIGN_END}}},
        "size": 1000,
    }
    resp = es_request("POST", f"/{MODBUS_INDEX}/_eql/search", body)
    sequences = resp.get("hits", {}).get("sequences", [])
    alerts: list[ModbusAlert] = []
    for seq in sequences:
        events = seq["events"]
        read_ev, write_ev = events[0]["_source"], events[1]["_source"]
        alerts.append(ModbusAlert(
            source_ip=read_ev["source"]["ip"],
            read_ts=parse_ts(read_ev["@timestamp"]),
            write_ts=parse_ts(write_ev["@timestamp"]),
        ))
    print(f"[T0836] naiv EQL: {len(alerts)} talalt READ->WRITE szekvencia a teljes kampanyablakban.")
    return alerts


def fetch_modbus_detailed_values() -> dict[str, list[dict]]:
    """Egyetlen lekerdezes a teljes kampanyablakra -- a naiv-alertekhez
    tartozo tenyleges regiszterertekek (request_values/response_values)
    per source.ip, idorendben, memoriaban joinolashoz (Q1/Q3 batch-elv)."""
    body = {
        "size": 10000,
        "sort": [{"@timestamp": "asc"}],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": CAMPAIGN_START, "lte": CAMPAIGN_END}}},
                    {"terms": {"icsnpp.modbus_detailed.function": [
                        "READ_HOLDING_REGISTERS", "WRITE_SINGLE_REGISTER"]}},
                ]
            }
        },
    }
    resp = es_request("POST", f"/{MODBUS_DETAILED_INDEX}/_search", body)
    hits = resp["hits"]["hits"]
    if resp["hits"]["total"]["value"] > len(hits):
        print(f"[WARN] modbus_detailed: {resp['hits']['total']['value']} talalat, "
              f"csak {len(hits)} lekerve -- noveld a size-t!", file=sys.stderr)
    by_ip: dict[str, list[dict]] = {}
    for h in hits:
        src = h["_source"]
        ip = src["source"]["ip"]
        by_ip.setdefault(ip, []).append({
            "ts": parse_ts(src["@timestamp"]),
            "function": src["icsnpp"]["modbus_detailed"]["function"],
            "request_values": src["icsnpp"]["modbus_detailed"].get("request_values"),
            "response_values": src["icsnpp"]["modbus_detailed"].get("response_values"),
        })
    return by_ip


def _nearest(docs: list[dict], function: str, ts: datetime, tol_s: float) -> Optional[dict]:
    best, best_delta = None, None
    for d in docs:
        if d["function"] != function:
            continue
        delta = abs((d["ts"] - ts).total_seconds())
        if delta <= tol_s and (best_delta is None or delta < best_delta):
            best, best_delta = d, delta
    return best


def refine_t0836_alerts(alerts: list[ModbusAlert], detailed_by_ip: dict[str, list[dict]]) -> None:
    """In-place: kitolti value_before/value_after-t es a refined_fires
    flaget minden alerten. FINOMITOTT feltetel (B) szakasz tablazata):
    forras NEM allowlistelt ES a regiszterertek tenylegesen valtozott
    (a WRITE request_values-a MAS, mint az OZT MEGELOZO READ
    response_values-a -- a WRITE sajat request/response parja mindig
    egyezik, mert a Modbus write-response echo-zza a kert erteket)."""
    for a in alerts:
        docs = detailed_by_ip.get(a.source_ip, [])
        read_doc = _nearest(docs, "READ_HOLDING_REGISTERS", a.read_ts, JOIN_TOLERANCE_S)
        write_doc = _nearest(docs, "WRITE_SINGLE_REGISTER", a.write_ts, JOIN_TOLERANCE_S)
        if read_doc and read_doc.get("response_values"):
            a.value_before = read_doc["response_values"][0]
        if write_doc and write_doc.get("request_values"):
            a.value_after = write_doc["request_values"][0]
        not_allowlisted = a.source_ip != ALLOWLIST_IP
        value_changed = (a.value_before is not None and a.value_after is not None
                          and a.value_before != a.value_after)
        a.refined_fires = not_allowlisted and value_changed


# ---------------------------------------------------------------------------
# T0816 (A.4) -- nyers lookup: icsnpp.s7comm.function_name == "PLC Stop"
# ---------------------------------------------------------------------------

@dataclass
class S7Alert:
    source_ip: str
    ts: datetime


def fetch_t0816_alerts() -> list[S7Alert]:
    body = {
        "size": 1000,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": CAMPAIGN_START, "lte": CAMPAIGN_END}}},
                    {"match_phrase": {"icsnpp.s7comm.function_name": "PLC Stop"}},
                ]
            }
        },
    }
    resp = es_request("POST", f"/{S7COMM_INDEX}/_search", body)
    alerts = [S7Alert(source_ip=h["_source"]["source"]["ip"], ts=parse_ts(h["_source"]["@timestamp"]))
              for h in resp["hits"]["hits"]]
    print(f"[T0816] nyers lookup ('PLC Stop'): {len(alerts)} talalat a teljes kampanyablakban.")
    return alerts


# ---------------------------------------------------------------------------
# TP/FN parositas es FP-maszkolas (Q4/Q5 szerint)
# ---------------------------------------------------------------------------

def episode_hit(ep: Episode, alert_ts: datetime) -> bool:
    lo, hi = ep.window
    return lo <= alert_ts <= hi


def mask_fp(alert_timestamps: list[datetime], all_episodes: list[Episode]) -> list[datetime]:
    """FP = riasztas, ami a teljes kampanyablakon belul esik, DE egyetlen
    epizod [start-5s, end+5s] ablakaba sem -- technikahataroktol
    fuggetlenul maszkolva (Q5 vegleges dontes)."""
    windows = [ep.window for ep in all_episodes]
    fps = []
    for ts in alert_timestamps:
        if not any(lo <= ts <= hi for lo, hi in windows):
            fps.append(ts)
    return fps


# ---------------------------------------------------------------------------
# Bootstrap (Q8/Q9): np.random.seed(42), B=10000, determinisztikus
# ---------------------------------------------------------------------------

def percentile_ci(samples: np.ndarray, alpha: float = 0.05) -> tuple[float, float]:
    lo, hi = np.percentile(samples, [100 * alpha / 2, 100 * (1 - alpha / 2)])
    return float(lo), float(hi)


def bootstrap_recall_ci(outcomes: list[int]) -> Optional[tuple[float, float]]:
    """Epizod-szintu percentilis bootstrap egyetlen technika recall-jara."""
    n = len(outcomes)
    if n < MIN_N_FOR_CI:
        return None
    np.random.seed(BOOTSTRAP_SEED)
    arr = np.array(outcomes)
    boots = np.array([np.random.choice(arr, size=n, replace=True).mean() for _ in range(BOOTSTRAP_B)])
    return percentile_ci(boots)


def bootstrap_macro_recall_ci(resamplable: dict[str, list[int]],
                               fixed_additions: dict[str, tuple[int, int]]) -> tuple[float, float]:
    """Retegzett bootstrap a makro-recall-ra (Q8). `resamplable`: technika
    -> teljes-N epizod-kimenetel-vektor (fuggetlenul ujramintavetelezve
    minden iteracioban, sajat N-jevel). `fixed_additions`: technika ->
    (fix_tp, fix_n) -- pl. T0816-hoz az A.5 garantalt 0/3, amit NEM
    resample-elunk (N=3 < MIN_N_FOR_CI), csak konstansként hozzaadunk a
    pooled recall szamlalojahoz/nevezojehez minden iteracioban."""
    np.random.seed(BOOTSTRAP_SEED)
    techniques = sorted(set(resamplable) | set(fixed_additions))
    arrays = {t: np.array(v) for t, v in resamplable.items()}
    boots = np.empty(BOOTSTRAP_B)
    for i in range(BOOTSTRAP_B):
        per_tech_recall = []
        for t in techniques:
            tp_boot, n_boot = 0, 0
            if t in arrays:
                arr = arrays[t]
                n_boot = len(arr)
                tp_boot += int(np.random.choice(arr, size=n_boot, replace=True).sum())
            if t in fixed_additions:
                fix_tp, fix_n = fixed_additions[t]
                tp_boot += fix_tp
                n_boot += fix_n
            per_tech_recall.append(tp_boot / n_boot if n_boot else 0.0)
        boots[i] = float(np.mean(per_tech_recall))
    return percentile_ci(boots)


def build_fp_bins(all_episodes: list[Episode]) -> list[tuple[datetime, datetime]]:
    """A teljes kampanyablakot az epizod-ablakok kimaszkolasa utan
    megmaradt "jogosult" (FP-re alkalmas) szakaszokra bontja, majd
    FP_BIN_SECONDS-os binekre particionalja -- blokk-bootstrap alapja
    (Q9). Az utolso, resz-binek megtartva."""
    windows = sorted((ep.window for ep in all_episodes), key=lambda w: w[0])
    eligible: list[tuple[datetime, datetime]] = []
    cursor = CAMPAIGN_START_DT
    for lo, hi in windows:
        if lo > cursor:
            eligible.append((cursor, min(lo, CAMPAIGN_END_DT)))
        cursor = max(cursor, hi)
    if cursor < CAMPAIGN_END_DT:
        eligible.append((cursor, CAMPAIGN_END_DT))

    bins: list[tuple[datetime, datetime]] = []
    for lo, hi in eligible:
        cur = lo
        while cur < hi:
            nxt = min(cur + timedelta(seconds=FP_BIN_SECONDS), hi)
            bins.append((cur, nxt))
            cur = nxt
    return bins


def bootstrap_fp_precision_f1_ci(fp_timestamps: list[datetime], bins: list[tuple[datetime, datetime]],
                                  tp_outcomes: list[int]) -> dict:
    """Blokk-bootstrap az FP-szamra (bin-ujramintavetelezes, Q9), fuggetlen
    epizod-szintu bootstrap a TP-re -- egyuttesen adjak a precision/F1 CI-t."""
    bin_counts = []
    for lo, hi in bins:
        bin_counts.append(sum(1 for ts in fp_timestamps if lo <= ts < hi))
    bin_counts_arr = np.array(bin_counts)
    n_bins = len(bin_counts_arr)
    n_tp_episodes = len(tp_outcomes)

    np.random.seed(BOOTSTRAP_SEED)
    fp_boots = np.array([np.random.choice(bin_counts_arr, size=n_bins, replace=True).sum()
                          for _ in range(BOOTSTRAP_B)]) if n_bins else np.zeros(BOOTSTRAP_B)
    np.random.seed(BOOTSTRAP_SEED)
    tp_arr = np.array(tp_outcomes)
    tp_boots = (np.array([np.random.choice(tp_arr, size=n_tp_episodes, replace=True).sum()
                           for _ in range(BOOTSTRAP_B)]) if n_tp_episodes else np.zeros(BOOTSTRAP_B))

    with np.errstate(invalid="ignore", divide="ignore"):
        precision_boots = np.where((tp_boots + fp_boots) > 0, tp_boots / (tp_boots + fp_boots), np.nan)
        recall_point = tp_arr.mean() if n_tp_episodes else 0.0
        f1_boots = np.where(
            (precision_boots + recall_point) > 0,
            2 * precision_boots * recall_point / (precision_boots + recall_point),
            np.nan,
        )
    precision_boots = precision_boots[~np.isnan(precision_boots)]
    f1_boots = f1_boots[~np.isnan(f1_boots)]
    return {
        "fp_count": int(len(fp_timestamps)),
        "fp_ci": percentile_ci(fp_boots) if n_bins else (0.0, 0.0),
        "precision_ci": percentile_ci(precision_boots) if len(precision_boots) else None,
        "f1_ci": percentile_ci(f1_boots) if len(f1_boots) else None,
    }


# ---------------------------------------------------------------------------
# Fo kiertekelesi folyamat
# ---------------------------------------------------------------------------

def evaluate() -> dict:
    if not LOCAL_ATTACK_LOG.exists():
        raise FileNotFoundError(
            f"{LOCAL_ATTACK_LOG} nem talalhato -- eloszor scp-vel hozd be a "
            f"Red-Team-VM-rol (/home/ot/attack_log.jsonl)."
        )
    episodes = load_ground_truth(LOCAL_ATTACK_LOG)

    with SSHTunnel(SIEM_SSH_HOST, ES_LOCAL_PORT):
        naive_alerts = fetch_naive_t0836_alerts()
        detailed_by_ip = fetch_modbus_detailed_values()
        refine_t0836_alerts(naive_alerts, detailed_by_ip)
        s7_alerts = fetch_t0816_alerts()

    refined_alerts = [a for a in naive_alerts if a.refined_fires]

    results: dict = {"campaign": {
        "start": CAMPAIGN_START, "end": CAMPAIGN_END,
        "duration_minutes": round((CAMPAIGN_END_DT - CAMPAIGN_START_DT).total_seconds() / 60, 1),
        "planned_duration_minutes": 240,
        "deviation_note": (
            "A tenyleges kampanyidotartam a benign_generator.py meta-naploja "
            "alapjan ~179 perc, nem a tervezett 240 -- lasd Ch.6 'Modszertani "
            "eltmresek'. Forensics: journalctl session-31 lezarasa 16:47:28-kor, "
            "human-initiated SIGTERM, nem OOM/crash."
        ),
    }, "techniques": {}}

    t0836_eps = [e for e in episodes if e.scenario_id == "A1"]
    t0836_outcomes = [1 if any(episode_hit(ep, a.write_ts) for a in refined_alerts) else 0 for ep in t0836_eps]
    t0836_fp_naive = mask_fp([a.write_ts for a in naive_alerts], episodes)
    t0836_fp_refined = mask_fp([a.write_ts for a in refined_alerts], episodes)
    fp_bins = build_fp_bins(episodes)

    naive_metrics = bootstrap_fp_precision_f1_ci(t0836_fp_naive, fp_bins, t0836_outcomes)
    refined_metrics = bootstrap_fp_precision_f1_ci(t0836_fp_refined, fp_bins, t0836_outcomes)
    t0836_recall = sum(t0836_outcomes) / len(t0836_outcomes) if t0836_outcomes else 0.0
    t0836_recall_ci = bootstrap_recall_ci(t0836_outcomes)

    results["techniques"]["T0836"] = {
        "scenario": "A1", "n_effective": len(t0836_eps), "tp": sum(t0836_outcomes),
        "fn": len(t0836_outcomes) - sum(t0836_outcomes), "recall": t0836_recall, "recall_ci": t0836_recall_ci,
        "naive": {**naive_metrics, "precision": (sum(t0836_outcomes) / (sum(t0836_outcomes) + len(t0836_fp_naive))
                                                   if (sum(t0836_outcomes) + len(t0836_fp_naive)) else None)},
        "refined": {**refined_metrics, "precision": (sum(t0836_outcomes) / (sum(t0836_outcomes) + len(t0836_fp_refined))
                                                       if (sum(t0836_outcomes) + len(t0836_fp_refined)) else None)},
    }

    t0816_a4_eps = [e for e in episodes if e.scenario_id == "A4"]
    t0816_a5_eps = [e for e in episodes if e.scenario_id == "A5"]
    t0816_a4_outcomes = [1 if any(episode_hit(ep, a.ts) for a in s7_alerts) else 0 for ep in t0816_a4_eps]
    t0816_a5_outcomes = [0 for _ in t0816_a5_eps]  # garantalt vakfolt, nincs detekcio (A.5)
    t0816_fp = mask_fp([a.ts for a in s7_alerts], episodes)
    t0816_metrics = bootstrap_fp_precision_f1_ci(t0816_fp, fp_bins, t0816_a4_outcomes)
    t0816_tp = sum(t0816_a4_outcomes) + sum(t0816_a5_outcomes)
    t0816_n = len(t0816_a4_outcomes) + len(t0816_a5_outcomes)
    t0816_recall_ci = bootstrap_recall_ci(t0816_a4_outcomes)  # csak A.4 resample-elheto (N>=10)

    results["techniques"]["T0816"] = {
        "scenario": "A4+A5 (pooled, Q6)", "n_effective": t0816_n, "tp": t0816_tp, "fn": t0816_n - t0816_tp,
        "recall": t0816_tp / t0816_n if t0816_n else 0.0,
        "recall_ci_note": "csak A.4 (N=20) resample-elve, A.5 (N=3, garantalt 0) fix konstansként hozzaadva",
        "recall_ci_a4_only": t0816_recall_ci,
        **t0816_metrics,
        "precision": (t0816_tp / (t0816_tp + len(t0816_fp)) if (t0816_tp + len(t0816_fp)) else None),
    }

    for scenario_id, technique in (("A2", "T0888"), ("A3", "T0846"), ("A6", "T0843")):
        eps = [e for e in episodes if e.scenario_id == scenario_id]
        results["techniques"][technique] = {
            "scenario": scenario_id, "n_effective": len(eps), "tp": 0, "fn": len(eps),
            "recall": 0.0, "recall_ci": bootstrap_recall_ci([0] * len(eps)),
            "precision": None, "f1": None,
            "note": "Nincs aktiv detektalasi szabaly (Q7) -- precision/F1 N/A, nem 0.",
        }

    # Makro-F1: TECHNIKANKENTI atlag, csak aktiv-szabalyu technikak (Q7 dontes),
    # konzisztensen a makro-recall szamitassal (lasd lent), amely mindig egyetlen
    # tagot vesz technikankent. A T0836-nal a VEGSO (finomitott) szabaly szamit
    # bele az atlagba, mert ez a tenylegesen alkalmazott detekcios konfiguracio;
    # a naiv valtozat F1-je csak referenciakent, kulon van tarolva, es a
    # 6.3.1 alfejezet naiv-vs-finomitott osszevetesehez hasznalt, nem a makro-atlaghoz.
    # (Javitva 2026-08-25, konzulensi eszrevetel alapjan -- korabban a naiv es a
    # finomitott T0836-valtozat ket kulon tagkent szerepelt egy 3-tagu atlagban,
    # ami a technika-alapu makro-atlagolas definiciojaval inkonzisztens volt.)
    t0836 = results["techniques"]["T0836"]
    p836_naive = t0836["naive"]["precision"]
    r836 = t0836["recall"]
    f1_836_naive = (2 * p836_naive * r836 / (p836_naive + r836)) if (p836_naive is not None and (p836_naive + r836) > 0) else None
    p836_refined = t0836["refined"]["precision"]
    f1_836_refined = (2 * p836_refined * r836 / (p836_refined + r836)) if (p836_refined is not None and (p836_refined + r836) > 0) else None

    t0816 = results["techniques"]["T0816"]
    p816 = t0816["precision"]
    r816 = t0816["recall"]
    f1_816 = (2 * p816 * r816 / (p816 + r816)) if (p816 is not None and (p816 + r816) > 0) else None

    macro_f1_components = [("T0836", f1_836_refined), ("T0816", f1_816)]

    results["macro_f1"] = {
        "components": dict(macro_f1_components),
        "t0836_naive_f1_reference": f1_836_naive,
        "value": float(np.mean([v for _, v in macro_f1_components if v is not None])),
        "note": ("Technikankenti atlag, csak aktiv-szabalyu technikak (T0836 vegso/finomitott "
                 "szaballyal, T0816) -- Q7 dontes. A T0836 naiv valtozat F1-je "
                 "('t0836_naive_f1_reference') csak referenciakent szerepel, nem resze az atlagnak."),
    }

    # "az osszes TP/FP/FN technikahataron atively osszesitesevel" (E szakasz)
    # -- ez a szabaly-nelkuli technikak (T0846/T0888/T0843) garantalt FN-jeit
    # IS tartalmazza, kulonben a mikro-F1 hamisan jonak tunne azaltal, hogy
    # eltunteti a felderitesi katalogus felenek teljes vakfoltjat.
    micro_tp = sum(d["tp"] for d in results["techniques"].values())
    micro_fn = sum(d["fn"] for d in results["techniques"].values())
    micro_fp_refined = t0836["refined"]["fp_count"] + t0816["fp_count"]
    micro_precision = micro_tp / (micro_tp + micro_fp_refined) if (micro_tp + micro_fp_refined) else None
    micro_recall = micro_tp / (micro_tp + micro_fn) if (micro_tp + micro_fn) else None
    micro_f1 = (2 * micro_precision * micro_recall / (micro_precision + micro_recall)
                if micro_precision and micro_recall else None)
    results["micro_f1"] = {
        "rule_variant": "refined", "tp": micro_tp, "fp": micro_fp_refined, "fn": micro_fn,
        "precision": micro_precision, "recall": micro_recall, "value": micro_f1,
    }

    # Javitva 2026-08-25 (2.4/0.1 tetel): A.2 = T0888 (teljes statisztikai kezeles,
    # resamplable), A.3 = T0846 (kvalitativ, fix 0 -- lasd fenn SCENARIO_TECHNIQUE).
    resamplable = {"T0836": t0836_outcomes, "T0888": [0] * len([e for e in episodes if e.scenario_id == "A2"]),
                   "T0816": t0816_a4_outcomes}
    fixed_additions = {"T0816": (sum(t0816_a5_outcomes), len(t0816_a5_outcomes))}
    macro_recall_point = np.mean([
        t0836_recall,
        0.0,
        t0816_tp / t0816_n if t0816_n else 0.0,
        0.0,  # T0846 (A.3)
        0.0,  # T0843
    ])
    results["macro_recall"] = {
        "value": float(macro_recall_point),
        "ci": bootstrap_macro_recall_ci(resamplable, fixed_additions),
        "note": ("Retegzett bootstrap CI (Q8) csak T0836/T0888/T0816-A4 resamplinggel; "
                 "T0846/T0843/T0816-A5 fix 0 vakfoltkent szamit a pontbecslesbe, de nem "
                 "a CI-be -- lasd E) szakasz."),
    }

    return results


# ---------------------------------------------------------------------------
# Kimenet: JSON + Markdown
# ---------------------------------------------------------------------------

def write_outputs(results: dict) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    json_path = RESULTS_DIR / "campaign_2026-08-22_metrics.json"
    md_path = RESULTS_DIR / "campaign_2026-08-22_summary.md"

    json_path.write_text(json.dumps(results, indent=2, default=str, ensure_ascii=False), encoding="utf-8")

    lines = ["# Milestone 6 -- Kiertekelesi osszefoglalo (2026-08-22-i kampany)", ""]
    lines.append(f"**Tenyleges kampanyablak:** {results['campaign']['start']} -- "
                 f"{results['campaign']['end']} (~{results['campaign']['duration_minutes']} perc, "
                 f"tervezett: {results['campaign']['planned_duration_minutes']} perc)")
    lines.append("")
    lines.append(f"> {results['campaign']['deviation_note']}")
    lines.append("")
    lines.append("## Technikankenti konfuzios matrix es F1")
    lines.append("")
    lines.append("| Technika | N | TP | FN | Recall | Recall 95% CI | Precision (finomitott/nyers) | F1 |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for tech, d in results["techniques"].items():
        if tech == "T0836":
            p = d["refined"]["precision"]
            f1 = (2 * p * d["recall"] / (p + d["recall"])) if p and d["recall"] else None
            lines.append(f"| {tech} | {d['n_effective']} | {d['tp']} | {d['fn']} | "
                          f"{d['recall']:.2f} | {d['recall_ci']} | {p} | {f1} |")
        elif tech == "T0816":
            p = d["precision"]
            f1 = (2 * p * d["recall"] / (p + d["recall"])) if p and d["recall"] else None
            lines.append(f"| {tech} | {d['n_effective']} | {d['tp']} | {d['fn']} | "
                          f"{d['recall']:.2f} | {d['recall_ci_a4_only']} (csak A.4) | {p} | {f1} |")
        else:
            ci = d['recall_ci'] if d['recall_ci'] is not None else f"N/A (N={d['n_effective']}<{MIN_N_FOR_CI})"
            lines.append(f"| {tech} | {d['n_effective']} | {d['tp']} | {d['fn']} | "
                          f"{d['recall']:.2f} | {ci} | N/A (nincs szabaly) | N/A |")
    lines.append("")
    lines.append("> **Megjegyzes a degeneralt (0 szelessegu) CI-kre:** T0836 es T0816/A.4 minden "
                  "resample-elt epizodon 100%-os recallt ad, mert a valodi minta maga is 100%-os "
                  "(17/17, ill. 20/20) -- a percentilis bootstrap ilyenkor sose mintavetelez FN-t, "
                  "tehat az intervallum matematikailag korrekt modon nulla szelessegu. Ez a "
                  "percentilis bootstrap ismert korlatja tokeletes pontbecsles + kis N eseten, "
                  "NEM szoftverhiba -- a 6. fejezetben explicit jelolendo.")
    lines.append("")
    lines.append("## Osszesitett mutatok")
    lines.append("")
    lines.append(f"- **Makro-recall (pontbecsles, mind az 5 technikaval, a vakfoltokat is bele­ertve):** "
                  f"{results['macro_recall']['value']:.3f}")
    lines.append(f"- **Makro-recall 95% CI (MAS mennyiseg -- lasd lent):** {results['macro_recall']['ci']}")
    lines.append("")
    lines.append("> **KRITIKUS, a Milestone5-Terv.md E) szakasza altal explicit eloirt labjegyzet:** "
                  "a fenti ket szam **nem ugyanarra a mennyisegre** vonatkozik. A pontbecsles "
                  "(0.374) mind az ot technikat tartalmazza, a garantalt vakfoltokkal egyutt "
                  "(T0846, T0843, es T0816 A.5-resze -- mindegyik 0 recall-lal, szandekosan "
                  "lehuzva az atlagot, RQ3-demonstraciokent). A CI-sav ezzel szemben KIZAROLAG a "
                  "harom, teljes statisztikai kezelesu technikara (T0836, T0888, T0816-A.4-resz) "
                  "szamolt, retegzett makro-recall bizonytalansagat fejezi ki -- a vakfoltok "
                  "(N=3, CI-kuszob alatt) nincsenek benne a resampling-ben. A ket szamot "
                  "EGYMAS MELLETT, DE KULON ertelmezve kell kozolni a dolgozatban.")
    lines.append("")
    lines.append(f"- **Makro-F1** (technikankent, csak aktiv-szabalyu technikak -- T0836 vegso/finomitott, T0816): "
                  f"{results['macro_f1']['value']:.3f}")
    lines.append(f"- **Mikro-F1** (finomitott szabalyvariansal, MINDEN technika FN-je bennevan, "
                  f"a szabaly-nelkuliek 0 TP/0 FP mellett is): {results['micro_f1']['value']:.3f} "
                  f"(TP={results['micro_f1']['tp']}, FP={results['micro_f1']['fp']}, "
                  f"FN={results['micro_f1']['fn']})")
    lines.append("")
    lines.append("## Kepletek (attekinthetoseg, 6. fejezethez)")
    lines.append("")
    lines.append("```")
    lines.append("Recall_tech      = TP_tech / (TP_tech + FN_tech)                  [epizod-szintu]")
    lines.append("Precision_tech   = TP_tech / (TP_tech + FP_tech)                  [FP: teljes kampanyablak")
    lines.append("                                                                   minus epizod-ablakok]")
    lines.append("F1_tech          = 2 * Precision_tech * Recall_tech / (Precision_tech + Recall_tech)")
    lines.append("Makro-Recall     = mean(Recall_tech for tech in {T0836,T0846,T0816,T0888,T0843})")
    lines.append("Makro-F1         = mean(F1_tech for tech in {T0836,T0816})  [csak aktiv szabaly, T0836 = vegso/finomitott]")
    lines.append("Mikro-F1         = 2*TP_pooled*... / (pooled TP+FP+FN, technikahatarok nelkul)")
    lines.append("Bootstrap CI     = percentilis, B=10000, seed=42; retegzett a makro-recall-hoz,")
    lines.append("                   blokk (5 perces bin) a FP/precision/F1-hez")
    lines.append("```")
    md_path.write_text("\n".join(lines), encoding="utf-8")

    print(f"\nKimenet irva: {json_path}")
    print(f"Kimenet irva: {md_path}")


def main() -> None:
    results = evaluate()
    write_outputs(results)


if __name__ == "__main__":
    main()
