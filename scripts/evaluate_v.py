#!/usr/bin/env python3
"""evaluate_v.py -- V1/V2 validacios kiertekelo (prereg-v1.1, E-28).

A besorolast ELORE ROGZITETT, determinisztikus szabalykod vegzi, pontosan a
`docs/tdk/VALIDACIOS-PROTOKOLL.md` 5. fejezete szerint (B1-B6, C0/C1, 5.3-5.5),
emberi felulbiralas nelkul (D13). A regi `scripts/evaluate_campaign.py` (M6,
bootstrap-F1) VALTOZATLAN marad; innen csak a jol korulhatarolt
segedfuggvenyeket vesszuk at, hivatkozassal:
  - `parse_ts`  <- evaluate_campaign.py:185-186 (ISO-8601 -> datetime, 'Z' kezelve)
  - `es_request` / `SSHTunnel`  <- evaluate_campaign.py:130-178 (csak a --fetch agban)
A statisztika itt MAS (Jeffreys Beta-posterior, D11), nem a regi bootstrap.

Bemenet (kampanyonkent, data/campaign_*/):
  attack_log.jsonl, attack_control.jsonl, benign_log.jsonl, eve_slice.json,
  manifest.json  -- ezek a D6-artefaktumok, mar helyben.
  A Sensor nyers Zeek-naploi (C1: conn.log, http.log, s7comm_upload_download,
  capture_loss) es az ES icsnpp-adatfolyamai (C0 telemetria, C1 EQL/DSL) NEM
  reszei a D6-csomagnak; ezeket a KULON, csak olvaso `--fetch` lepes hozza be
  helyi cache-be:  data/campaign_*/zeek/  es  data/campaign_*/es/ .
  A kiertekeles a hianyzo reszeket NA-kent (nem 'None'-kent) kezeli.

Hasznalat:
  python3 scripts/evaluate_v.py                         # minden data/campaign_*/ , szaraz
  python3 scripts/evaluate_v.py --campaign-dir data/campaign_20261101T113823Z_V1_s1
  python3 scripts/evaluate_v.py --fetch data/campaign_XXXX   # CSAK olvaso begyujtes (ssh)

[SAJAT MERNOKI DONTES]-jelolesek a protokoll 5.2/5.4 szerinti pontokon; a
NYITOTT pontok a futas vegen es a .md-ben felsorolva.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import glob
import json
import math
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
DETECTION_MAP_CSV = REPO_ROOT / "results" / "m3g" / "attack_ics_v20_detection_map.csv"
STIX_V20 = REPO_ROOT / "docs" / "tdk" / "related-works" / "forrasok" / "ics-attack-20.0.json"
OUT_DIR = REPO_ROOT / "results" / "m5"

# ------------------------------------------------------------------ konfiguracio
ATTACKER_IP = "192.168.1.50"     # .50 -- tamadoi identitas (protokoll 3)
BENIGN_IP = "192.168.1.51"       # .51 -- allowlistelt benign / "engineering station"
TARGET_IP = "192.168.1.100"      # PLC
SUBNET_PREFIX = "192.168.1."     # A.3: cel barmely /24-es cim (B1)

# Epizodablak (B1, 5.2): [start_ts - 1 s, end_ts + 5 s]; a +-1 s chrony-tures bent van.
EP_PRE_S = 1.0
EP_POST_S = 5.0

# Init (D9) / restore (D2) ablak az FP-maszkolashoz. A protokoll csak PONT-ts-t
# rogzit (manifest.excluded_windows, attack_control). A kizaro ablak szelessege
# NINCS szammal rogzitve -> konfig-parameter, dokumentalt alapertekkel.
# [SAJAT MERNOKI DONTES / NYITOTT -- lasd a futas vegi NYITOTT pontokat]
INIT_RESTORE_PRE_S = 1.0
INIT_RESTORE_POST_S = 10.0

FP_SID = 2250008                 # #86 "SURICATA Modbus Data mismatch" (flow:to_client)
A3_C1_SID = 2009286              # #51, A.3 portscan (csak C1)

# 5.5 fix kizart ablakok (UTC). A jovobeli lab_up/fustteszt/init-ablakot a
# manifest adja kampanyonkent; ezek a protokoll-tablabol valo konstansok.
FIXED_EXCLUDED_WINDOWS = [
    ("2026-10-29T13:06:16Z", "2026-10-29T13:06:17Z"),
    ("2026-10-29T13:06:33Z", "2026-10-29T13:06:43Z"),
    ("2026-10-29T13:21:53Z", "2026-10-29T13:22:28Z"),
    ("2026-10-29T13:23:27Z", "2026-10-29T13:23:59Z"),
    ("2026-10-29T13:38:58.406050Z", "2026-10-29T13:40:15.225466Z"),
    ("2026-10-31T09:13:55.924242Z", "2026-10-31T09:16:10.087040Z"),
]

READ_FUNCS = {"READ_HOLDING_REGISTERS", "READ_COILS",
              "READ_DISCRETE_INPUTS", "READ_INPUT_REGISTERS"}

_IPV4_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")


def _extract_ip(s: str) -> str:
    """Az attack_log target-je lehet csupasz IP (modbus/s7comm) vagy teljes URL
    (A.5: 'http://192.168.1.100:8080'); innen az IPv4-et nyerjuk ki (B1)."""
    m = _IPV4_RE.search(s or "")
    return m.group(0) if m else (s or "")


def _as_int(v) -> Optional[int]:
    """func_code lehet int vagy hex-string ('0x1a') az ES-ben."""
    if v is None:
        return None
    if isinstance(v, int):
        return v
    try:
        return int(str(v), 0)
    except ValueError:
        return None

# Kategoria-rendezes (5.2, D0): None < Telemetry < General < Tactic < Technique.
CATEGORY_ORDER = {"None": 0, "Telemetry": 1, "General": 2, "Tactic": 3, "Technique": 4}

# --------------------------------------------------------------------- B2 tabla
# A procedurat azonosito rekord predikatuma szcenarionkent (protokoll 5.2 B2).
# A `rec` normalizalt telemetria-/nyers-rekord; a `kind` donti el a forrast:
#   'modbus'/'s7comm' = ES icsnpp (C0);  'conn'/'http'/'s7ud' = Sensor nyers (C1).
# [SAJAT MERNOKI DONTES] (D0 operacionalizalas).
B2_PREDICATES = {
    "A1":  lambda r: r["kind"] == "modbus" and r.get("func") == "WRITE_SINGLE_REGISTER" and r.get("pdu_type") == "REQ",
    "V2.1": lambda r: r["kind"] == "modbus" and r.get("func") == "WRITE_SINGLE_REGISTER" and r.get("pdu_type") == "REQ",
    "V2.5": lambda r: r["kind"] == "modbus" and r.get("func") == "WRITE_SINGLE_REGISTER" and r.get("pdu_type") == "REQ",
    "V2.4": lambda r: r["kind"] == "modbus" and r.get("func") == "WRITE_MULTIPLE_REGISTERS" and r.get("pdu_type") == "REQ",
    "A2":  lambda r: r["kind"] == "modbus" and r.get("pdu_type") == "REQ" and r.get("func") in READ_FUNCS,
    "A3":  lambda r: r["kind"] == "conn" and r.get("dest_port") in (502, 102),          # csak C1
    "A4":  lambda r: r["kind"] == "s7comm" and r.get("function_name") == "PLC Stop",
    "A5":  lambda r: r["kind"] == "http" and r.get("uri") == "/stop_plc",               # csak C1
    "A6":  lambda r: (r["kind"] == "s7comm" and _as_int(r.get("func_code")) in (0x1a, 0x1b, 0x1c))
                     or r["kind"] == "s7ud",                                            # ES vagy C1
    "V2.2": lambda r: r["kind"] == "s7comm" and r.get("function_name") == "Read Variable",
    "V2.3": lambda r: r["kind"] == "s7comm" and r.get("function_name") == "Write Variable",
}

# Melyik telemetria-forras adhat B2-rekordot a szcenariohoz, es melyik konfig:
#   'es'  = ES icsnpp (C0);  'raw' = Sensor nyers Zeek (C1).
B2_SOURCE = {
    "A1": ("es", "C0"), "V2.1": ("es", "C0"), "V2.5": ("es", "C0"), "V2.4": ("es", "C0"),
    "A2": ("es", "C0"), "A4": ("es", "C0"), "V2.2": ("es", "C0"), "V2.3": ("es", "C0"),
    "A6": ("es", "C0"),          # download ES-bol C0; a s7comm_upload_download C1 raadas
    "A3": ("raw", "C1"), "A5": ("raw", "C1"),
}

# Szcenario-kulcs az episode_id elotagjabol. V1: A1..A6. V2: az attack_runner
# episode_id-prefixe meg nem ellenorzott eles adaton -> NYITOTT (lasd lent).
V2_PREFIX_ALIAS = {"V21": "V2.1", "V22": "V2.2", "V23": "V2.3", "V24": "V2.4", "V25": "V2.5"}


def scenario_key(episode_id: str) -> str:
    tok = episode_id.split("_")[0]
    return V2_PREFIX_ALIAS.get(tok, tok)


# ================================================================= ido-segedek
def parse_ts(ts: str) -> dt.datetime:
    """ISO-8601 -> aware datetime (evaluate_campaign.py:185-186 atveve)."""
    s = ts.replace("Z", "+00:00")
    # Suricata eve: '+0000' (ketjegyu offset) -> '+00:00'
    s = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", s)
    d = dt.datetime.fromisoformat(s)
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d


def in_window(t: dt.datetime, lo: dt.datetime, hi: dt.datetime) -> bool:
    return lo <= t <= hi


# ================================================================= statisztika
# Regularizalt nem teljes beta I_x(a,b) (Lentz-fele folytonos tort) + bisekcios
# inverz; a stdlib-only fallback a D11 Jeffreys-kvantilisekhez. scipy-vel egyezik.
def _betacf(a: float, b: float, x: float) -> float:
    MAXIT, EPS, FPMIN = 300, 1e-15, 1e-300
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < FPMIN:
        d = FPMIN
    d = 1.0 / d
    h = d
    for m in range(1, MAXIT + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < FPMIN:
            d = FPMIN
        c = 1.0 + aa / c
        if abs(c) < FPMIN:
            c = FPMIN
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < FPMIN:
            d = FPMIN
        c = 1.0 + aa / c
        if abs(c) < FPMIN:
            c = FPMIN
        d = 1.0 / d
        de = d * c
        h *= de
        if abs(de - 1.0) < EPS:
            break
    return h


def betainc(a: float, b: float, x: float) -> float:
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    lbeta = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
    front = math.exp(lbeta + a * math.log(x) + b * math.log1p(-x))
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _betacf(a, b, x) / a
    return 1.0 - front * _betacf(b, a, 1.0 - x) / b


def _betaincinv_stdlib(a: float, b: float, p: float) -> float:
    if p <= 0.0:
        return 0.0
    if p >= 1.0:
        return 1.0
    lo, hi = 0.0, 1.0
    for _ in range(200):                      # ~2^-200, boven eleg
        mid = 0.5 * (lo + hi)
        if betainc(a, b, mid) < p:
            lo = mid
        else:
            hi = mid
    return 0.5 * (lo + hi)


try:
    from scipy.stats import beta as _scipy_beta  # type: ignore

    def beta_ppf(a: float, b: float, p: float) -> float:
        return float(_scipy_beta.ppf(p, a, b))

    STATS_BACKEND = "scipy"
except Exception:  # pragma: no cover - a stdlib-ut a tenyleges fallback
    def beta_ppf(a: float, b: float, p: float) -> float:
        return _betaincinv_stdlib(a, b, p)

    STATS_BACKEND = "stdlib(betaincinv-bisection)"


def beta_summary(k: int, n: int, jeffreys: bool = True) -> dict:
    """D11: posterior median + 95% egyenlo farku CI (2,5/97,5 kvantilis).
    jeffreys=True -> Beta(k+1/2, n-k+1/2) (elsodleges);
    jeffreys=False -> Beta(k+1, n-k+1) (erzekenyseg)."""
    if n <= 0:
        return {"k": k, "n": n, "median": None, "ci_lo": None, "ci_hi": None,
                "mean": None, "prior": "Jeffreys" if jeffreys else "uniform"}
    a = k + (0.5 if jeffreys else 1.0)
    b = (n - k) + (0.5 if jeffreys else 1.0)
    return {
        "k": k, "n": n,
        "median": beta_ppf(a, b, 0.5),
        "ci_lo": beta_ppf(a, b, 0.025),
        "ci_hi": beta_ppf(a, b, 0.975),
        "mean": a / (a + b),
        "prior": "Jeffreys Beta(%.1f,%.1f)" % (a, b) if jeffreys else "Beta(%d,%d)" % (a, b),
    }


def cohen_kappa_detail(rater_a: list[int], rater_b: list[int]) -> dict:
    """Sulyozatlan Cohen-kappa (5.3, #97) + p_o, p_e es ertelmezo megjegyzes.
    Hatareset: p_e = 1 (mindket jelolo konstans, zero variancia) -> a kappa NEM
    definialt (0/0), ilyenkor kappa=None, kappa_note a magyarazat. Ha csak az
    egyik jelolo konstans (p_e < 1), a kappa definialt (altalaban 0), de
    degeneralt -> kulon megjegyzes. A p_o es p_e mindig visszaadodik."""
    n = len(rater_a)
    if n == 0 or n != len(rater_b):
        return {"kappa": None, "p_observed": None, "p_expected": None,
                "kappa_note": "nincs parositott technika"}
    po = sum(1 for x, y in zip(rater_a, rater_b) if x == y) / n
    pa1 = sum(rater_a) / n
    pb1 = sum(rater_b) / n
    pe = pa1 * pb1 + (1 - pa1) * (1 - pb1)
    a_const = pa1 in (0.0, 1.0)
    b_const = pb1 in (0.0, 1.0)
    if pe >= 1.0:
        return {"kappa": None, "p_observed": po, "p_expected": pe,
                "kappa_note": "nem definialt (p_e=1, zero variancia)"}
    kappa = (po - pe) / (1.0 - pe)
    note = "degeneralt: egyik ertekelo konstans" if (a_const or b_const) else None
    return {"kappa": kappa, "p_observed": po, "p_expected": pe, "kappa_note": note}


def cohen_kappa(rater_a: list[int], rater_b: list[int]) -> Optional[float]:
    """Visszafele-kompatibilis: csak a kappa-ertek (p_e=1 eseten None)."""
    return cohen_kappa_detail(rater_a, rater_b)["kappa"]


# ============================================================ epizod-betoltes
class Episode:
    __slots__ = ("episode_id", "scenario", "technique", "status", "effect_status",
                 "start", "end", "source_ip", "target", "campaign_id", "seed")

    def __init__(self, rec: dict, campaign_id: str):
        self.episode_id = rec["episode_id"]
        self.scenario = scenario_key(rec["episode_id"])
        self.technique = rec["mitre_technique_id"]
        self.status = rec["status"]
        self.effect_status = (rec.get("parameters") or {}).get("effect_status")
        self.start = parse_ts(rec["start_ts"])
        self.end = parse_ts(rec["end_ts"])
        self.source_ip = rec["source_ip"]
        self.target = _extract_ip(rec["target"])
        self.campaign_id = campaign_id
        self.seed = rec.get("seed")

    def window(self) -> tuple[dt.datetime, dt.datetime]:
        return (self.start - dt.timedelta(seconds=EP_PRE_S),
                self.end + dt.timedelta(seconds=EP_POST_S))

    def matches_target(self, dest_ip: str) -> bool:
        if self.scenario == "A3":
            return dest_ip.startswith(SUBNET_PREFIX)        # /24 (B1)
        return dest_ip == self.target

    def b1_connect(self, src_ip: str, dest_ip: str, t: dt.datetime) -> bool:
        lo, hi = self.window()
        return in_window(t, lo, hi) and src_ip == self.source_ip and self.matches_target(dest_ip)


# ============================================================ forras-betoltok
def load_jsonl(path: Path) -> list[dict]:
    out = []
    if not path.exists():
        return out
    for line in path.open(encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line or line[0] != "{":
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def load_episodes(cdir: Path, campaign_id: str) -> list[Episode]:
    eps = []
    for rec in load_jsonl(cdir / "attack_log.jsonl"):
        if "episode_id" not in rec:
            continue
        eps.append(Episode(rec, campaign_id))
    return eps


def load_excluded_windows(cdir: Path, manifest: dict) -> list[tuple[dt.datetime, dt.datetime]]:
    """Init (D9) + restore (D2) ablakok az attack_control-bol es a manifestbol,
    plusz az 5.5 fix ablakok. [ts - PRE, ts + POST] (lasd konfig)."""
    wins: list[tuple[dt.datetime, dt.datetime]] = []
    for lo, hi in FIXED_EXCLUDED_WINDOWS:
        wins.append((parse_ts(lo), parse_ts(hi)))
    seen_ts = set()
    for rec in load_jsonl(cdir / "attack_control.jsonl"):
        ts = rec.get("ts")
        if ts and rec.get("kind") in ("init_baseline", "restore_plc"):
            t = parse_ts(ts)
            seen_ts.add(ts)
            wins.append((t - dt.timedelta(seconds=INIT_RESTORE_PRE_S),
                         t + dt.timedelta(seconds=INIT_RESTORE_POST_S)))
    for ew in manifest.get("excluded_windows", []):
        ts = ew.get("ts")
        if ts and ts not in seen_ts:
            t = parse_ts(ts)
            wins.append((t - dt.timedelta(seconds=INIT_RESTORE_PRE_S),
                         t + dt.timedelta(seconds=INIT_RESTORE_POST_S)))
    return wins


def load_suricata_alerts(cdir: Path, source: str = "live") -> list[dict]:
    """Suricata-alertek (C0). source='live' -> eve_slice.json (elo capture);
    source='replay' -> replay_c0/eve.json (#84 offline replay, a telepitett C0
    szabalykeszlettel -- a 'valodi' C0 riasztasszint). Normalizalt rekordok."""
    out = []
    path = (cdir / "replay_c0" / "eve.json") if source == "replay" else (cdir / "eve_slice.json")
    if not path.exists():
        return out
    for line in path.open(encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line or line[0] != "{":
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if r.get("event_type") != "alert":
            continue
        a = r.get("alert", {})
        out.append({
            "ts": parse_ts(r["timestamp"]),
            "src_ip": r.get("src_ip"), "dest_ip": r.get("dest_ip"),
            "dest_port": r.get("dest_port"),
            "sid": a.get("signature_id"), "signature": a.get("signature", ""),
            "category": a.get("category", ""), "source": "suricata",
        })
    return out


def load_es_telemetry(cdir: Path) -> Optional[list[dict]]:
    """ES icsnpp telemetria a cache-bol (C0 Telemetry). None = nincs begyujtve (NA)."""
    esdir = cdir / "es"
    if not esdir.is_dir():
        return None
    recs: list[dict] = []
    for fn, kind in (("icsnpp_modbus.jsonl", "modbus"), ("icsnpp_s7comm.jsonl", "s7comm")):
        p = esdir / fn
        if not p.exists():
            continue
        for r in load_jsonl(p):
            recs.append({**r, "kind": kind, "ts": parse_ts(r["ts"]) if isinstance(r.get("ts"), str) else r.get("ts")})
    return recs


def load_raw_zeek(cdir: Path) -> Optional[dict]:
    """Sensor nyers Zeek-naplok a cache-bol (C1). None = nincs begyujtve (NA)."""
    zdir = cdir / "zeek"
    if not zdir.is_dir():
        return None
    out = {"conn": [], "http": [], "s7ud": []}
    mapping = {"conn.log": "conn", "http.log": "http", "s7comm_upload_download.log": "s7ud"}
    for fn, kind in mapping.items():
        p = zdir / fn
        if not p.exists():
            continue
        for r in load_jsonl(p):
            rr = dict(r)
            rr["kind"] = kind
            if isinstance(rr.get("ts"), str):
                rr["ts"] = parse_ts(rr["ts"])
            out[kind].append(rr)
    return out


def load_benign(cdir: Path):
    """Benign .51: kerések (poll) es a generator aktiv intervalluma (meta)."""
    recs = load_jsonl(cdir / "benign_log.jsonl")
    reqs, start, stop = [], None, None
    for r in recs:
        ts = r.get("ts")
        if not ts:
            continue
        t = parse_ts(ts)
        if r.get("cycle") == "meta":
            if r.get("status") == "generator_started":
                start = t
            elif r.get("status") == "generator_stopped":
                stop = t
        else:
            reqs.append(t)                     # minden nem-meta rekord = egy benign keres
    if start is None and reqs:
        start = min(reqs)
    if stop is None and reqs:
        stop = max(reqs)
    return reqs, start, stop


# ============================================================ B3 szint (riasztas)
_TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_TACTIC_RE = re.compile(r"\bTA\d{4}\b")


def alert_level(signature: str, tech_names: set[str], tactic_names: set[str]) -> str:
    """B3: Technique / Tactic / General a szabalynev/uzenet alapjan."""
    s = signature or ""
    sl = s.lower()
    if _TECH_RE.search(s) or any(tn in sl for tn in tech_names):
        return "Technique"
    if _TACTIC_RE.search(s) or any(tn in sl for tn in tactic_names):
        return "Tactic"
    return "General"


# ============================================================ epizod-besorolas
def classify_episode(ep: Episode, alerts: list[dict], es_tel: Optional[list[dict]],
                     raw: Optional[dict], config: str,
                     tech_names: set[str], tactic_names: set[str]) -> dict:
    """B1-B5 egy epizodra, egy konfiguraciora (C0 vagy C1).
    Visszaad: category, seen in {True,False,'NA'}, highest_alert, b2_hit, available."""
    src_scope = B2_SOURCE.get(ep.scenario, ("es", "C0"))
    b2_stream, b2_config = src_scope

    # --- B2 (Telemetry): a konfighoz tartozo forrasbol ---
    b2_available = True
    b2_hit = False
    pred = B2_PREDICATES.get(ep.scenario)
    if pred is None:
        b2_available = False
    else:
        if b2_stream == "es":
            # ES telemetria C0-ban es C1-ben is lathato
            if es_tel is None:
                b2_available = False
            else:
                for r in es_tel:
                    t = r.get("ts")
                    if t and ep.b1_connect(r.get("source.ip") or r.get("src_ip", ""),
                                           r.get("dest.ip") or r.get("dest_ip", ""), t) and pred(r):
                        b2_hit = True
                        break
            # A6: a nyers s7comm_upload_download (C1) is adhat B2-t
            if ep.scenario == "A6" and config == "C1":
                if raw is None:
                    b2_available = False
                elif not b2_hit:
                    for r in raw.get("s7ud", []):
                        t = r.get("ts")
                        if t and ep.b1_connect(r.get("src_ip", ""), r.get("dest_ip", ""), t) and pred(r):
                            b2_hit = True
                            break
        else:  # 'raw' -> csak C1
            if config != "C1":
                b2_available = True          # C0-ban ehhez a szcenariohoz nincs telemetria: ervenyes 'nincs'
            elif raw is None:
                b2_available = False
            else:
                bucket = {"A3": "conn", "A5": "http"}.get(ep.scenario)
                for r in raw.get(bucket, []):
                    t = r.get("ts")
                    if t and ep.b1_connect(r.get("src_ip", ""), r.get("dest_ip", ""), t) and pred(r):
                        b2_hit = True
                        break

    # --- B3 (riasztasok): Suricata C0-ban; EQL/DSL + SID2009286 C1-ben ---
    # Itt csak a Suricata eve-alertek elerhetok (C0). Az EQL/DSL (C1) ES-bol jon.
    highest = "None"
    alerts_available = True
    for a in alerts:
        t = a.get("ts")
        if not (t and ep.b1_connect(a.get("src_ip", ""), a.get("dest_ip", ""), t)):
            continue
        lvl = alert_level(a.get("signature", ""), tech_names, tactic_names)
        if CATEGORY_ORDER[lvl] > CATEGORY_ORDER[highest]:
            highest = lvl
    # C1: az EQL/DSL-riasztas forrasa az ES; ha nincs begyujtve -> az alert-ut NA.
    eql_available = (config != "C1") or (es_tel is not None)

    # --- B4 kategoria (elso teljesulo) ---
    if highest in ("Technique", "Tactic", "General"):
        category = highest
        seen = True
    elif b2_hit:
        category = "Telemetry"
        seen = True
    else:
        # Nincs pozitiv jel. 'None' CSAK akkor biztos, ha minden relevans forras elerheto.
        all_available = b2_available and alerts_available and eql_available
        if all_available:
            category, seen = "None", False
        else:
            category, seen = "NA", "NA"

    return {"episode_id": ep.episode_id, "scenario": ep.scenario, "config": config,
            "category": category, "seen": seen, "highest_alert": highest, "b2_hit": b2_hit,
            "b2_available": b2_available, "eql_available": eql_available}


# ============================================================ FP (5.4, E-28)
def compute_fp(alerts: list[dict], episodes: list[Episode],
               excluded: list[tuple[dt.datetime, dt.datetime]],
               benign_reqs: list[dt.datetime],
               benign_start: Optional[dt.datetime], benign_stop: Optional[dt.datetime]) -> dict:
    """E-28: SID 2250008 a benign (.51) sessionon, epizod-/init-/restore-ablakon
    kivul. Nevezo: epizodokon kivuli benign-ido (s) + benign kerések szama."""
    ep_windows = [ep.window() for ep in episodes]
    mask = ep_windows + excluded

    def masked(t: dt.datetime) -> bool:
        return any(lo <= t <= hi for lo, hi in mask)

    def is_benign_session(a: dict) -> bool:
        s, d = a.get("src_ip"), a.get("dest_ip")
        involves_51 = (s == BENIGN_IP or d == BENIGN_IP)
        involves_50 = (s == ATTACKER_IP or d == ATTACKER_IP)
        return involves_51 and not involves_50

    fp_alerts = [a for a in alerts
                 if a.get("sid") == FP_SID and is_benign_session(a) and not masked(a["ts"])]
    fp_requests = [t for t in benign_reqs if not masked(t)]

    # benign-ido: az aktiv intervallum minusz a kizart ablakok atfedese
    benign_time_s = None
    if benign_start and benign_stop and benign_stop > benign_start:
        total = (benign_stop - benign_start).total_seconds()
        overlap = 0.0
        for lo, hi in _merge_windows(mask):
            a = max(lo, benign_start)
            b = min(hi, benign_stop)
            if b > a:
                overlap += (b - a).total_seconds()
        benign_time_s = max(0.0, total - overlap)

    return {
        "fp_count": len(fp_alerts),
        "sid": FP_SID,
        "denominator_benign_requests": len(fp_requests),
        "denominator_benign_time_s": benign_time_s,
        "fp_per_request": (len(fp_alerts) / len(fp_requests)) if fp_requests else None,
        "fp_per_hour": (len(fp_alerts) / (benign_time_s / 3600.0)) if benign_time_s else None,
    }


def _merge_windows(windows: list[tuple[dt.datetime, dt.datetime]]):
    if not windows:
        return []
    ws = sorted(windows, key=lambda w: w[0])
    merged = [list(ws[0])]
    for lo, hi in ws[1:]:
        if lo <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    return [(a, b) for a, b in merged]


# ============================================================ 5.3 kulso jelzo
def load_tech_tactic_names() -> tuple[set[str], set[str]]:
    """ATT&CK technika- es taktikanevek (STIX v20) a B3 nev-illesztesehez."""
    tech, tactic = set(), set()
    if not STIX_V20.exists():
        return tech, tactic
    data = json.loads(STIX_V20.read_text(encoding="utf-8"))
    for o in data.get("objects", data):
        if o.get("type") == "attack-pattern" and o.get("name"):
            if len(o["name"]) >= 6:
                tech.add(o["name"].lower())
        elif o.get("type") == "x-mitre-tactic" and o.get("name"):
            if len(o["name"]) >= 6:
                tactic.add(o["name"].lower())
    return tech, tactic


def mitre_network_analytic_map() -> dict[str, bool]:
    """5.3/D13: technika -> van-e NSM:/netflow:/otids: elotagu log source-u
    analitika. A CSV adja a technika->analytic_stix_ids leképezest, a STIX az
    analitika log source-neveit (kis/nagybetu-erzeketlen elotag-illesztes)."""
    result: dict[str, bool] = {}
    if not (DETECTION_MAP_CSV.exists() and STIX_V20.exists()):
        return result
    data = json.loads(STIX_V20.read_text(encoding="utf-8"))
    analytic_net: dict[str, bool] = {}
    prefixes = ("nsm:", "netflow:", "otids:")
    for o in data.get("objects", data):
        if o.get("type") != "x-mitre-analytic":
            continue
        is_net = any((lsr.get("name", "").lower().startswith(prefixes))
                     for lsr in o.get("x_mitre_log_source_references", []))
        analytic_net[o["id"]] = is_net
    with DETECTION_MAP_CSV.open(encoding="utf-8") as f:
        for row in csv.DictReader(f):
            ids = [x for x in (row.get("analytic_stix_ids") or "").split(";") if x]
            result[row["technique_id"]] = any(analytic_net.get(i, False) for i in ids)
    return result


def external_signal(episodes_by_tech_seen_c1: dict[str, bool]) -> dict:
    """D13: technikankent binaris osszevetes + sulyozatlan Cohen-kappa.
    Nalunk = LÁTTA a C1-ben; MITRE = van NSM/netflow/otids analitika."""
    mitre = mitre_network_analytic_map()
    techs = sorted(episodes_by_tech_seen_c1.keys())
    rows, ours, theirs = [], [], []
    for t in techs:
        us = episodes_by_tech_seen_c1[t]           # True/False/None(NA)
        mt = mitre.get(t)
        row = {"technique": t, "ours_c1_seen": us, "mitre_network_analytic": mt}
        rows.append(row)
        if us is None or mt is None:
            continue                                # NA -> kimarad a kappabol
        ours.append(1 if us else 0)
        theirs.append(1 if mt else 0)
    detail = cohen_kappa_detail(ours, theirs)
    raw = (sum(1 for a, b in zip(ours, theirs) if a == b) / len(ours)) if ours else None
    return {"rows": rows, "n_paired": len(ours),
            "cohen_kappa_unweighted": detail["kappa"],
            "p_observed": detail["p_observed"],
            "p_expected": detail["p_expected"],
            "kappa_note": detail["kappa_note"],
            "raw_agreement": raw}


# ============================================================ kampany-betoltes
def load_campaign(cdir: Path, c0_source: str = "live") -> Optional[dict]:
    manifest_path = cdir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    campaign_id = manifest.get("campaign_id", cdir.name)
    aborted = str(manifest.get("status", "")).upper() == "ABORTED"
    episodes = load_episodes(cdir, campaign_id)
    return {
        "dir": cdir, "campaign_id": campaign_id, "manifest": manifest, "aborted": aborted,
        "episodes": episodes,
        "excluded": load_excluded_windows(cdir, manifest),
        "alerts": load_suricata_alerts(cdir, c0_source),
        "es_tel": load_es_telemetry(cdir),
        "raw": load_raw_zeek(cdir),
        "benign": load_benign(cdir),
    }


# ============================================================ aggregalas
def aggregate(campaigns: list[dict], tech_names, tactic_names,
              exclude: Optional[set] = None) -> dict:
    """Elsodleges: szcenario x konfiguracio, a K kampanyt osszevonva.
    Masodlagos: kampanyonkent. Az executed_effect/executed_no_effect kulon sor.
    `exclude` (ha nem None): (campaign_id, episode_id) parok halmaza -> E-39
    erzekenysegi elemzes (a fo elemzes valtozatlan marad)."""
    # per-epizod besorolas (C0 es C1), kizarva error + ABORTED
    classified = []            # list of dicts
    tech_seen_c1: dict[str, dict] = {}    # technika -> {seen_true, known}
    per_campaign_fp = {}
    for c in campaigns:
        if c["aborted"]:
            continue
        reqs, bstart, bstop = c["benign"]
        valid_eps = [e for e in c["episodes"] if e.status != "error"]
        per_campaign_fp[c["campaign_id"]] = compute_fp(
            c["alerts"], valid_eps, c["excluded"], reqs, bstart, bstop)
        for ep in valid_eps:
            for cfg in ("C0", "C1"):
                res = classify_episode(ep, c["alerts"], c["es_tel"], c["raw"], cfg,
                                       tech_names, tactic_names)
                res["campaign_id"] = c["campaign_id"]
                res["episode_id"] = ep.episode_id
                res["technique"] = ep.technique
                res["effect_status"] = ep.effect_status
                res["status"] = ep.status
                classified.append(res)
                if cfg == "C1":
                    d = tech_seen_c1.setdefault(ep.technique, {"true": 0, "known": 0})
                    if res["seen"] == "NA":
                        pass
                    else:
                        d["known"] += 1
                        if res["seen"]:
                            d["true"] += 1

    def summarize(rows: list[dict]) -> dict:
        known = [r for r in rows if r["seen"] != "NA"]
        k = sum(1 for r in known if r["seen"] is True)
        n = len(known)
        na = len(rows) - n
        cat = {}
        for r in rows:
            cat[r["category"]] = cat.get(r["category"], 0) + 1
        return {"n_rows": len(rows), "n_known": n, "k_seen": k, "n_na": na,
                "category_dist": cat,
                "posterior_jeffreys": beta_summary(k, n, True),
                "posterior_uniform": beta_summary(k, n, False)}

    # elsodleges: (szcenario, config) [+ effect_status ha van], kampanyok osszevonva
    primary = {}
    for r in classified:
        eff = r.get("effect_status")
        key = (r["scenario"], r["config"], eff if eff else "-")
        primary.setdefault(key, []).append(r)
    primary_out = []
    for (scn, cfg, eff), rows in sorted(primary.items()):
        s = summarize(rows)
        s.update({"scenario": scn, "config": cfg, "effect_status": eff})
        primary_out.append(s)

    # masodlagos: (kampany, szcenario, config)
    secondary = {}
    for r in classified:
        key = (r["campaign_id"], r["scenario"], r["config"])
        secondary.setdefault(key, []).append(r)
    secondary_out = []
    for (cid, scn, cfg), rows in sorted(secondary.items()):
        s = summarize(rows)
        s.update({"campaign_id": cid, "scenario": scn, "config": cfg})
        secondary_out.append(s)

    # D13 kulso jelzo (C1 LÁTTA technikankent)
    tech_seen_bool = {}
    for t, d in tech_seen_c1.items():
        tech_seen_bool[t] = (d["true"] > 0) if d["known"] > 0 else None
    ext = external_signal(tech_seen_bool)

    out = {"primary": primary_out, "secondary": secondary_out,
           "fp_per_campaign": per_campaign_fp, "external_signal": ext,
           "tech_seen_c1": tech_seen_c1}
    if exclude is not None:
        out["e39"] = e39_analysis(classified, exclude)
    return out


# ============================================================ E-39 erzekenyseg
def _tech_config_kn(classified: list[dict], exclude: Optional[set] = None) -> dict:
    """Technika x konfiguracio -> {k, n, na}; a LÁTTA-arany az `error` nelkul (a
    `classified` mar csak nem-error), az `exclude`-ban szereplo (campaign_id,
    episode_id) parokat kihagyva."""
    exclude = exclude or set()
    groups: dict[tuple, dict] = {}
    for r in classified:
        if (r.get("campaign_id"), r.get("episode_id")) in exclude:
            continue
        g = groups.setdefault((r["technique"], r["config"]), {"k": 0, "n": 0, "na": 0})
        if r["seen"] == "NA":
            g["na"] += 1
        else:
            g["n"] += 1
            if r["seen"] is True:
                g["k"] += 1
    return groups


def e39_analysis(classified: list[dict], exclude: set) -> dict:
    """Fo elemzes (minden nem-error epizod) vs. erzekenysegi elemzes (az
    eloallapot-sertes miatt kizart epizodok nelkul), technika x konfiguracio
    szerint, posterior + 95% CI egymas mellett, eltares-jelolessel."""
    main = _tech_config_kn(classified, None)
    sens = _tech_config_kn(classified, exclude)
    rows = []
    for (tech, cfg) in sorted(set(main) | set(sens)):
        m = main.get((tech, cfg), {"k": 0, "n": 0, "na": 0})
        s = sens.get((tech, cfg), {"k": 0, "n": 0, "na": 0})
        rows.append({
            "technique": tech, "config": cfg,
            "main": {"k": m["k"], "n": m["n"], "na": m["na"],
                     "posterior_jeffreys": beta_summary(m["k"], m["n"], True)},
            "sensitivity": {"k": s["k"], "n": s["n"], "na": s["na"],
                            "posterior_jeffreys": beta_summary(s["k"], s["n"], True)},
            "changed": (m["k"] != s["k"]) or (m["n"] != s["n"]),
        })
    return {"excluded_count": len(exclude),
            "excluded": sorted(f"{cid}:{eid}" for cid, eid in exclude),
            "by_technique_config": rows}


# ============================================================ kimenet
def write_outputs(result: dict, open_points: list[str]) -> tuple[Path, Path]:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    utc = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_path = OUT_DIR / f"eredmenyek_{utc}.json"
    md_path = OUT_DIR / f"eredmenyek_{utc}.md"
    json_path.write_text(json.dumps(result, indent=2, default=str, ensure_ascii=False), encoding="utf-8")

    L = []
    L.append(f"# V1/V2 kiertekeles (prereg-v1.1, E-28) -- {utc}")
    L.append("")
    L.append(f"- Statisztikai backend: `{STATS_BACKEND}`")
    L.append(f"- Kampanyok: {', '.join(result['meta']['campaigns'])}")
    L.append(f"- Kizart (ABORTED) kampanyok: {', '.join(result['meta']['aborted']) or '-'}")
    L.append("")
    L.append("## Elsodleges: szcenario x konfiguracio (kampanyok osszevonva)")
    L.append("")
    L.append("| Szcenario | Konfig | effect | n (ismert) | LÁTTA k | NA | kategoriak | posterior median [95% CI] |")
    L.append("|---|---|---|---|---|---|---|---|")
    for s in result["aggregate"]["primary"]:
        pj = s["posterior_jeffreys"]
        post = (f"{pj['median']:.3f} [{pj['ci_lo']:.3f}, {pj['ci_hi']:.3f}]"
                if pj["median"] is not None else "NA")
        cat = ", ".join(f"{k}:{v}" for k, v in sorted(s["category_dist"].items()))
        L.append(f"| {s['scenario']} | {s['config']} | {s['effect_status']} | "
                 f"{s['n_known']} | {s['k_seen']} | {s['n_na']} | {cat} | {post} |")
    L.append("")
    L.append("## Masodlagos: kampanyonkent")
    L.append("")
    L.append("| Kampany | Szcenario | Konfig | n (ismert) | LÁTTA k | NA | posterior median [95% CI] |")
    L.append("|---|---|---|---|---|---|---|")
    for s in result["aggregate"]["secondary"]:
        pj = s["posterior_jeffreys"]
        post = (f"{pj['median']:.3f} [{pj['ci_lo']:.3f}, {pj['ci_hi']:.3f}]"
                if pj["median"] is not None else "NA")
        L.append(f"| {s['campaign_id']} | {s['scenario']} | {s['config']} | "
                 f"{s['n_known']} | {s['k_seen']} | {s['n_na']} | {post} |")
    L.append("")
    L.append("## FP (5.4, E-28) kampanyonkent")
    L.append("")
    L.append("| Kampany | SID | FP | benign kerések | benign-ido (s) | FP/keres | FP/ora |")
    L.append("|---|---|---|---|---|---|---|")
    for cid, fp in result["aggregate"]["fp_per_campaign"].items():
        bt = f"{fp['denominator_benign_time_s']:.0f}" if fp["denominator_benign_time_s"] else "NA"
        fpr = f"{fp['fp_per_request']:.4f}" if fp["fp_per_request"] is not None else "NA"
        fph = f"{fp['fp_per_hour']:.2f}" if fp["fp_per_hour"] is not None else "NA"
        L.append(f"| {cid} | {fp['sid']} | {fp['fp_count']} | {fp['denominator_benign_requests']} | {bt} | {fpr} | {fph} |")
    L.append("")
    L.append("## 5.3 Kulso jelzo (D13, Cohen-kappa)")
    L.append("")
    ext = result["aggregate"]["external_signal"]
    L.append(f"- Parosított technikak: {ext['n_paired']}")
    kap = ext["cohen_kappa_unweighted"]
    L.append(f"- Sulyozatlan Cohen-kappa: {kap:.3f}" if kap is not None
             else "- Sulyozatlan Cohen-kappa: null (nem definialt)")
    po, pe = ext.get("p_observed"), ext.get("p_expected")
    L.append(f"- p_o (megfigyelt egyezes): {po:.3f}" if po is not None else "- p_o: NA")
    L.append(f"- p_e (vart egyezes): {pe:.3f}" if pe is not None else "- p_e: NA")
    if ext.get("raw_agreement") is not None:
        L.append(f"- Nyers egyezesi arany: {ext['raw_agreement']:.3f}")
    if ext.get("kappa_note"):
        L.append(f"- Megjegyzes: {ext['kappa_note']}")
    L.append("")
    L.append("| Technika | nalunk (C1 LÁTTA) | MITRE NSM/netflow/otids |")
    L.append("|---|---|---|")
    for row in ext["rows"]:
        us = "NA" if row["ours_c1_seen"] is None else ("LÁTTA" if row["ours_c1_seen"] else "NEM")
        mt = "NA" if row["mitre_network_analytic"] is None else ("IGEN" if row["mitre_network_analytic"] else "NEM")
        L.append(f"| {row['technique']} | {us} | {mt} |")
    L.append("")
    e39 = result["aggregate"].get("e39")
    if e39 is not None:
        L.append("## Erzekenysegi elemzes (E-39) -- eloallapot-sertes (value_before != 1009)")
        L.append("")
        L.append(f"- Kizart epizodok (fo elemzesben BENNE, itt a nelkuluk): {e39['excluded_count']}")
        if e39["excluded"]:
            L.append(f"  - {', '.join(e39['excluded'])}")
        L.append("")
        L.append("| Technika | Konfig | fo k/n | fo median [95% CI] | erz. k/n | erz. median [95% CI] | eltares |")
        L.append("|---|---|---|---|---|---|---|")
        for row in e39["by_technique_config"]:
            mp, sp = row["main"]["posterior_jeffreys"], row["sensitivity"]["posterior_jeffreys"]
            mpost = (f"{mp['median']:.3f} [{mp['ci_lo']:.3f}, {mp['ci_hi']:.3f}]"
                     if mp["median"] is not None else "NA")
            spost = (f"{sp['median']:.3f} [{sp['ci_lo']:.3f}, {sp['ci_hi']:.3f}]"
                     if sp["median"] is not None else "NA")
            mark = "**ELTER**" if row["changed"] else "="
            L.append(f"| {row['technique']} | {row['config']} | "
                     f"{row['main']['k']}/{row['main']['n']} | {mpost} | "
                     f"{row['sensitivity']['k']}/{row['sensitivity']['n']} | {spost} | {mark} |")
        L.append("")
    L.append("## NYITOTT pontok")
    L.append("")
    for p in open_points:
        L.append(f"- {p}")
    md_path.write_text("\n".join(L), encoding="utf-8")
    return json_path, md_path


# ============================================================ --fetch (CSAK olvaso)
# A Sensoron futtatott, CSAK OLVASO Zeek-szuro (stdin-rol a program, argv: base,
# ep0, ep1, nap1, nap2). Vegignezi az archiv (/opt/zeek/logs/<nap>/*.gz) es a
# current/spool naplokat, JSON vagy TSV, az [ep0,ep1] epoch-ablakra szur,
# normalizal (ts ISO, src_ip, dest_ip, dest_port, uri, func, pdu_type,
# function_name, function_code), JSONL-t ir az stdout-ra. A capture_loss-t
# nyersen (szurve) adja vissza. Semmit nem ir/modosit a Sensoron.
SENSOR_ZEEK_FILTER = r'''
import sys, glob, gzip, json, datetime
base, ep0, ep1 = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
days = sys.argv[4:]
paths = []
for d in days:
    paths += sorted(glob.glob("/opt/zeek/logs/%s/%s.*.log.gz" % (d, base)))
    paths += sorted(glob.glob("/opt/zeek/logs/%s/%s.log.gz" % (d, base)))
paths += ["/opt/zeek/logs/current/%s.log" % base, "/opt/zeek/spool/zeek/%s.log" % base]
def _open(p):
    return gzip.open(p, "rt", errors="replace") if p.endswith(".gz") else open(p, "rt", errors="replace")
def norm(ts, r):
    iso = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat()
    o = {"ts": iso, "src_ip": r.get("id.orig_h"), "dest_ip": r.get("id.resp_h"),
         "dest_port": r.get("id.resp_p")}
    if r.get("uri") is not None: o["uri"] = r["uri"]
    if r.get("function") is not None: o["func"] = r["function"]
    if r.get("pdu_type") is not None: o["pdu_type"] = r["pdu_type"]
    if r.get("function_name") is not None: o["function_name"] = r["function_name"]
    if r.get("function_code") is not None: o["func_code"] = r["function_code"]
    return o
tsv_fields = None
seen = 0
for p in paths:
    try:
        f = _open(p)
    except OSError:
        continue
    with f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            if line[0] == "{":
                try:
                    r = json.loads(line)
                except Exception:
                    continue
            elif line[0] == "#":
                if line.startswith("#fields"):
                    tsv_fields = line.split("\t")[1:]
                continue
            else:
                if not tsv_fields:
                    continue
                r = dict(zip(tsv_fields, line.split("\t")))
            ts = r.get("ts")
            try:
                ts = float(ts)
            except (TypeError, ValueError):
                continue
            if ep0 <= ts <= ep1:
                if base == "capture_loss":
                    r["ts_iso"] = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat()
                    sys.stdout.write(json.dumps(r, ensure_ascii=False) + "\n")
                else:
                    sys.stdout.write(json.dumps(norm(ts, r), ensure_ascii=False) + "\n")
                seen += 1
sys.stderr.write("SEEN %s %d (paths: %d)\n" % (base, seen, len(paths)))
'''

SSH_OPTS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
ZEEK_LOGS = ["conn", "http", "modbus", "modbus_detailed", "s7comm",
             "s7comm_upload_download", "s7comm_read_szl", "capture_loss"]
ES_INDICES = {
    "icsnpp_modbus": "logs-zeek.icsnpp_modbus-otlab",
    "icsnpp_modbus_detailed": "logs-zeek.icsnpp_modbus_detailed-otlab",
    "icsnpp_s7comm": "logs-zeek.icsnpp_s7comm-otlab",
    "icsnpp_cotp": "logs-zeek.icsnpp_cotp-otlab",
}


def _sample(path: Path) -> str:
    try:
        for line in path.open(encoding="utf-8"):
            line = line.strip()
            if line:
                return line[:300]
    except OSError:
        pass
    return "(ures)"


def fetch_campaign(cdir: Path) -> None:
    """CSAK OLVASO begyujtes: Sensor nyers Zeek-naplok + ES icsnpp a kampany
    VM-ablakara. A redteamhez NEM nyul (csak sensor + siem, menedzsmenthalozat).
    Utvonal-/mezofeltetelezesek (elso futaskor kiirva ellenorzesre):
      - Zeek: /opt/zeek/logs/<nap>/<base>.*.log.gz (archiv) + /opt/zeek/logs/current/
        + /opt/zeek/spool/zeek/<base>.log; JSON vagy TSV; ts = epoch (Unix, UTC);
        mezok: id.orig_h/id.resp_h/id.resp_p, uri, function/pdu_type (modbus),
        function_name/function_code (s7comm). Olvasas sudo -n python3-mal (mint az
        eve_slice, run_campaign.sh). [SAJAT MERNOKI DONTES / NYITOTT: ellenorizni]
      - ES: ssh siem + curl -s localhost:9200/<index>/_search, @timestamp range
        (M2c modszer, results/lab-health-2026-10-29.txt:1075). Ha auth kell -> STOP.
    """
    win = (cdir / "window.txt")
    w0 = w1 = None
    if win.exists():
        for line in win.read_text(encoding="utf-8").splitlines():
            if line.startswith("window_start:"):
                w0 = line.split(":", 1)[1].strip()
            elif line.startswith("window_end:"):
                w1 = line.split(":", 1)[1].strip()
    if not (w0 and w1):
        raise SystemExit("A --fetch-hez window.txt (window_start/window_end) kell.")
    d0, d1 = parse_ts(w0), parse_ts(w1)
    ep0, ep1 = d0.timestamp(), d1.timestamp()
    days = sorted({d0.strftime("%Y-%m-%d"), d1.strftime("%Y-%m-%d")})
    zeekdir, esdir = cdir / "zeek", cdir / "es"
    zeekdir.mkdir(exist_ok=True)
    esdir.mkdir(exist_ok=True)
    print(f"[--fetch] kampany: {cdir.name}")
    print(f"[--fetch] VM-ablak: {w0} .. {w1}  (epoch {ep0:.3f}..{ep1:.3f}; napok: {', '.join(days)})")
    counts = {}

    # --- 1) Sensor nyers Zeek (csak olvaso, sudo -n python3 stdin-filterrel) ---
    print("\n[--fetch] Sensor nyers Zeek-naplok (ssh sensor, sudo -n python3, CSAK OLVASO):")
    for base in ZEEK_LOGS:
        cmd = (["ssh"] + SSH_OPTS + ["sensor",
               f"sudo -n python3 - {base} {ep0:.6f} {ep1:.6f} " + " ".join(days)])
        try:
            r = subprocess.run(cmd, input=SENSOR_ZEEK_FILTER.encode(),
                               capture_output=True, timeout=120)
        except subprocess.TimeoutExpired:
            print(f"   {base:28s} IDOTULLEPES -- kihagyva")
            continue
        err = r.stderr.decode(errors="replace")
        if r.returncode != 0 and not r.stdout:
            low = err.lower()
            if "sudo" in low and ("password" in low or "a terminal" in low or "askpass" in low):
                raise SystemExit(f"[--fetch] STOP: a sensoron a 'sudo -n python3' jelszot ker.\n"
                                 f"   Szukseges: a Zeek-naplok olvasasahoz jogosultsag. stderr: {err.strip()}")
            print(f"   {base:28s} HIBA (rc={r.returncode}): {err.strip()[:160]}")
            continue
        out = cdir / "zeek" / f"{base}.log"
        out.write_bytes(r.stdout)
        n = sum(1 for ln in r.stdout.decode(errors='replace').splitlines() if ln.strip())
        counts[f"zeek/{base}.log"] = n
        print(f"   {base:28s} {n:6d} rekord  [{err.strip()}]")
        print(f"        minta: {_sample(out)}")

    # --- 2) ES icsnpp (C0 Telemetry), curl localhost:9200 a siem-en (sudo nelkul) ---
    print("\n[--fetch] ES icsnpp-adatfolyamok (ssh siem + curl localhost:9200, M2c modszer):")
    for name, index in ES_INDICES.items():
        query = json.dumps({
            "size": 10000, "sort": [{"@timestamp": "asc"}],
            "query": {"range": {"@timestamp": {"gte": w0, "lte": w1}}},
        })
        curl = ("curl -s -H 'Content-Type: application/json' "
                f"-XPOST 'localhost:9200/{index}/_search' -d '{query}'")
        cmd = ["ssh"] + SSH_OPTS + ["siem", curl]
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=120)
        except subprocess.TimeoutExpired:
            print(f"   {name:28s} IDOTULLEPES -- kihagyva")
            continue
        body = r.stdout.decode(errors="replace")
        low = body.lower()
        if ('"status":401' in body or "security_exception" in low or "unauthorized" in low
                or "missing authentication" in low):
            raise SystemExit(f"[--fetch] STOP: az ES hitelesitest ker ({index}).\n"
                             f"   Szukseges: ES-hozzaferes (user/jelszo vagy API-kulcs) a siem localhost:9200-hoz.\n"
                             f"   Valasz-reszlet: {body[:200]}")
        try:
            doc = json.loads(body)
            hits = doc.get("hits", {}).get("hits", [])
            total = doc.get("hits", {}).get("total", {})
            total = total.get("value") if isinstance(total, dict) else total
        except json.JSONDecodeError:
            print(f"   {name:28s} NEM-JSON valasz: {body[:160]}")
            continue
        norm = []
        for h in hits:
            s = h.get("_source", {})
            ic = s.get("icsnpp", {})
            ts = s.get("@timestamp")
            if name == "icsnpp_modbus" or name == "icsnpp_modbus_detailed":
                m = ic.get("modbus") or ic.get("modbus_detailed") or {}
                norm.append({"ts": ts, "src_ip": (s.get("source") or {}).get("ip"),
                             "dest_ip": (s.get("destination") or {}).get("ip"),
                             "dest_port": (s.get("destination") or {}).get("port"),
                             "func": m.get("function"), "pdu_type": m.get("pdu_type")})
            elif name == "icsnpp_s7comm":
                m = ic.get("s7comm") or {}
                norm.append({"ts": ts, "src_ip": (s.get("source") or {}).get("ip"),
                             "dest_ip": (s.get("destination") or {}).get("ip"),
                             "function_name": m.get("function_name"),
                             "func_code": m.get("function_code")})
            else:  # cotp -- provenancia
                norm.append({"ts": ts, "src_ip": (s.get("source") or {}).get("ip"),
                             "dest_ip": (s.get("destination") or {}).get("ip")})
        out = cdir / "es" / f"{name}.jsonl"
        out.write_text("".join(json.dumps(x, ensure_ascii=False) + "\n" for x in norm), encoding="utf-8")
        counts[f"es/{name}.jsonl"] = len(norm)
        warn = " [FIGYELEM: total>hits, noveld a size-t]" if (isinstance(total, int) and total > len(hits)) else ""
        print(f"   {name:28s} {len(norm):6d} rekord (ES total={total}){warn}")
        print(f"        minta: {_sample(out)}")

    print("\n[--fetch] rekordszamok fajlonkent:")
    for k, v in counts.items():
        print(f"   {v:6d}  {k}")
    print("[--fetch] kesz -- a cache a data/%s/{zeek,es}/ alatt (megvaltoztathatatlan, E-05)." % cdir.name)


# ============================================================ fo
def collect_open_points(campaigns: list[dict]) -> list[str]:
    pts = [
        "Az init (D9) / restore (D2) ablak szelessege a protokollban csak PONT-ts; "
        f"itt [ts-{INIT_RESTORE_PRE_S}s, ts+{INIT_RESTORE_POST_S}s] a konfig-alapertek "
        "[SAJAT MERNOKI DONTES] -- a pontos szelesseg protokoll-dontest igenyel.",
        "A V2 szcenariok episode_id-elotagja eles adaton meg nem ellenorzott (V2_PREFIX_ALIAS "
        "felteszi a 'V21'..'V25' alakot); a V2-kampany beerkezesekor ellenorzendo.",
        "C0 Suricata = az offline pcap-replay (#84); a szaraz probaban a helyi eve_slice.json "
        "(eles capture) a kozelito forras -- a tenyleges C0-hoz a --fetch/replay kell.",
        "A B3 nev-illesztes (technika/taktika nev a szabaly szovegeben) >=6 karakteres nevekre "
        "szukit a hamis talalatok ellen [SAJAT MERNOKI DONTES].",
        "FP-iranyszemantika (E-28/#86 flow:to_client): a .51-session alertjeit szamoljuk "
        "(src==.51 VAGY dest==.51, .50 nelkul), mert a decoder-esemeny a PLC valaszara tuzel.",
        "D13 Cohen-kappa DEGENERALT, ha a MITRE-oldal minden technikara IGEN (nulla "
        "variancia) -> a kappa 0 fuggetlenul az egyezestol; a protokoll szerint a jelzo "
        "'csak jelzokent' ertelmezendo (5.3). Az egyoldalu egyezesi arany (pl. 4/5) "
        "informativabb ebben az esetben.",
    ]
    return pts


def main() -> None:
    ap = argparse.ArgumentParser(description="V1/V2 kiertekelo (prereg-v1.1, E-28)")
    ap.add_argument("--campaign-dir", action="append", default=None,
                    help="egy kampany-konyvtar; tobbszor is megadhato (alapbol minden data/campaign_*/)")
    ap.add_argument("--fetch", metavar="DIR", default=None,
                    help="CSAK olvaso begyujtes egy kampanyra (Sensor nyers Zeek + ES); nem modosit VM-et")
    ap.add_argument("--sensitivity-exclude", nargs="?", const="AUTO", default=None,
                    metavar="JSON",
                    help="E-39 erzekenysegi elemzes: a megadott epizodok nelkul is kiertekel. "
                         "Ertek nelkul: kampanyonkent a data/<kampany>/e39_precondition_violations.json; "
                         "vagy egy JSON-fajl ({campaign_id:[episode_id,...]} vagy [{campaign_id,episode_id},...]).")
    ap.add_argument("--c0-source", choices=("live", "replay"), default="live",
                    help="a C0 Suricata-alertek forrasa: 'live' = eve_slice.json (elo capture, kozelito); "
                         "'replay' = replay_c0/eve.json (#84 offline replay, a valodi C0 riasztasszint).")
    args = ap.parse_args()

    if args.fetch:
        fetch_campaign(Path(args.fetch))
        return

    if args.campaign_dir:
        dirs = [Path(d) for d in args.campaign_dir]
    else:
        dirs = sorted(Path(p) for p in glob.glob(str(REPO_ROOT / "data" / "campaign_*"))
                      if (Path(p) / "attack_log.jsonl").exists())
    if not dirs:
        raise SystemExit("Nincs kiertekelheto kampany (data/campaign_*/attack_log.jsonl).")

    tech_names, tactic_names = load_tech_tactic_names()
    campaigns = [load_campaign(d, args.c0_source) for d in dirs]
    campaigns = [c for c in campaigns if c]

    exclude = None
    if args.sensitivity_exclude is not None:
        exclude = set()
        if args.sensitivity_exclude == "AUTO":
            for c in campaigns:
                f = c["dir"] / "e39_precondition_violations.json"
                if not f.exists():
                    continue
                data = json.loads(f.read_text(encoding="utf-8"))
                viol = data.get("violations", []) if isinstance(data, dict) else data
                for v in viol:
                    eid = v["episode_id"] if isinstance(v, dict) else v
                    exclude.add((c["campaign_id"], eid))
        else:
            data = json.loads(Path(args.sensitivity_exclude).read_text(encoding="utf-8"))
            if isinstance(data, dict):
                for cid, ids in data.items():
                    for eid in ids:
                        exclude.add((cid, eid))
            else:
                for v in data:
                    exclude.add((v["campaign_id"], v["episode_id"]))

    agg = aggregate(campaigns, tech_names, tactic_names, exclude)
    result = {
        "meta": {
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "prereg": "v1.1", "stats_backend": STATS_BACKEND,
            "c0_source": args.c0_source,
            "campaigns": [c["campaign_id"] for c in campaigns if not c["aborted"]],
            "aborted": [c["campaign_id"] for c in campaigns if c["aborted"]],
            "config": {"EP_PRE_S": EP_PRE_S, "EP_POST_S": EP_POST_S,
                       "INIT_RESTORE_PRE_S": INIT_RESTORE_PRE_S,
                       "INIT_RESTORE_POST_S": INIT_RESTORE_POST_S, "FP_SID": FP_SID},
        },
        "aggregate": agg,
    }
    open_points = collect_open_points(campaigns)
    json_path, md_path = write_outputs(result, open_points)
    print(f"Kimenet: {json_path}")
    print(f"Kimenet: {md_path}")


if __name__ == "__main__":
    main()
