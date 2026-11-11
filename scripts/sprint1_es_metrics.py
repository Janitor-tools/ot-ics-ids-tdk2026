#!/usr/bin/env python3
"""
sprint1_es_metrics.py -- a konzulensi zarokor-munkacsomag Sprint 1
tetelei kozul az Elasticsearch-adatbol szamithato negy tetelt szamolja
a 2026-08-22-i kampany mar rogzitett indexeinek ujralekerdezesevel
(NEM uj meresi kor):

  1.1 Detekcios kesleltetes (median, p95, technikankent) -- attack-to-alert
      definicioval: epizod kezdete (attack_log.jsonl start_ts) -> a
      riasztast kivalto esemeny @timestamp-je. NEM tartalmazza a
      Filebeat/ES ingest-kesleltetest (az kulon, mar dokumentalt korlat,
      lasd ICS-Lab-Allapot-Atadas.md Milestone 4 lezarasa -- ott nincs
      event.ingested mezo egyik pipeline-ban sem, igy az nem
      visszaszamolhato a mar rogzitett kampanyadatbol).
  1.2 maxspan=10s erzekenysegi gorbe (2/5/10/30/60s) a T0836 naiv EQL-
      szekvenciaszabalyra.
  1.3 A T0836 finomitott szabaly ket megkulonbozteto felteteletenek
      (allowlist, ertek-valtozas) 2x2 ablacioja.
  1.5 Technika-konfuzios matrix (RQ1 kulcsmetrikaja) -- szuk definicioval:
      csak az aktiv szabalyu technikak (T0836, T0816) kereszt-teves
      tuzelese szamit, a harom vakfolt-technika (T0846/T0888/T0843)
      explicit "nincs aktiv szabaly" oszlopkent jelenik meg, nem
      kitalalt adatkent.

Ujrahasznositja az evaluate_campaign.py mar validalt es commitolt
segedfuggvenyeit (SSHTunnel, es_request, ground truth betoltes stb.) --
azt magat nem modositja.

ELOFELTETEL: elo SSH-hozzaferes a labor-hoz (lasd ~/.ssh/config, alias
"siem"), es a data/campaign_2026-08-22/attack_log.jsonl helyi masolata
(ugyanaz, amit az evaluate_campaign.py is hasznal).

Kimenet: results/campaign_2026-08-22_sprint1_metrics.json +
results/campaign_2026-08-22_sprint1_summary.md
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluate_campaign import (  # noqa: E402
    ALLOWLIST_IP,
    BOOTSTRAP_B,
    BOOTSTRAP_SEED,
    CAMPAIGN_END,
    CAMPAIGN_START,
    Episode,
    JOIN_TOLERANCE_S,
    LOCAL_ATTACK_LOG,
    MODBUS_DETAILED_INDEX,
    MODBUS_INDEX,
    RESULTS_DIR,
    SIEM_SSH_HOST,
    S7COMM_INDEX,
    ES_LOCAL_PORT,
    SSHTunnel,
    _nearest,
    episode_hit,
    es_request,
    fetch_modbus_detailed_values,
    fetch_t0816_alerts,
    load_ground_truth,
    parse_ts,
    percentile_ci,
)

MAXSPAN_VALUES_S = [2, 5, 10, 30, 60]


# ---------------------------------------------------------------------------
# 1.2 -- maxspan-erzekenysegi gorbe: a naiv EQL-szekvencia ujrafuttatasa
# eltero maxspan ertekekkel. A lekerdezes maga a mar rogzitett Zeek-
# esemenyeken fut, nem uj csomagrogzitest igenyel -- a maxspan pusztan
# lekerdezes-idejű join-tolerancia, nem ujra-capture.
# ---------------------------------------------------------------------------

def fetch_naive_t0836_alerts_with_maxspan(maxspan_s: int) -> list[dict]:
    query = (
        f"sequence by source.ip with maxspan={maxspan_s}s\n"
        '  [network where event.dataset == "zeek.icsnpp_modbus" '
        'and icsnpp.modbus.function == "READ_HOLDING_REGISTERS" '
        'and icsnpp.modbus.pdu_type == "REQ"]\n'
        '  [network where event.dataset == "zeek.icsnpp_modbus" '
        'and icsnpp.modbus.function == "WRITE_SINGLE_REGISTER" '
        'and icsnpp.modbus.pdu_type == "REQ"]'
    )
    body = {
        "query": query,
        "filter": {"range": {"@timestamp": {"gte": CAMPAIGN_START, "lte": CAMPAIGN_END}}},
        "size": 1000,
    }
    resp = es_request("POST", f"/{MODBUS_INDEX}/_eql/search", body)
    sequences = resp.get("hits", {}).get("sequences", [])
    alerts = []
    for seq in sequences:
        events = seq["events"]
        read_ev, write_ev = events[0]["_source"], events[1]["_source"]
        alerts.append({
            "source_ip": read_ev["source"]["ip"],
            "read_ts": parse_ts(read_ev["@timestamp"]),
            "write_ts": parse_ts(write_ev["@timestamp"]),
        })
    return alerts


def compute_maxspan_sensitivity(episodes: list[Episode], detailed_by_ip: dict) -> dict:
    """Minden maxspan-ertekre ujrafuttatja a naiv szekvenciat, majd a mar
    igazolt finomito post-filtert (allowlist + ertek-valtozas) alkalmazza
    -- igy a gorbe a VEGLEGESEN hasznalt, finomitott szabaly maxspan-
    erzekenyseget mutatja, nem a soha be nem vezetett naiv valtozatet."""
    t0836_eps = [e for e in episodes if e.scenario_id == "A1"]
    results = {}
    for span in MAXSPAN_VALUES_S:
        alerts = fetch_naive_t0836_alerts_with_maxspan(span)
        refined = []
        for a in alerts:
            docs = detailed_by_ip.get(a["source_ip"], [])
            read_doc = _nearest(docs, "READ_HOLDING_REGISTERS", a["read_ts"], JOIN_TOLERANCE_S)
            write_doc = _nearest(docs, "WRITE_SINGLE_REGISTER", a["write_ts"], JOIN_TOLERANCE_S)
            value_before = read_doc["response_values"][0] if read_doc and read_doc.get("response_values") else None
            value_after = write_doc["request_values"][0] if write_doc and write_doc.get("request_values") else None
            not_allowlisted = a["source_ip"] != ALLOWLIST_IP
            value_changed = value_before is not None and value_after is not None and value_before != value_after
            if not_allowlisted and value_changed:
                refined.append(a)
        outcomes = [1 if any(episode_hit(ep, a["write_ts"]) for a in refined) else 0 for ep in t0836_eps]
        tp = sum(outcomes)
        fp = sum(1 for a in refined if not any(episode_hit(ep, a["write_ts"]) for ep in episodes))
        precision = tp / (tp + fp) if (tp + fp) else None
        recall = tp / len(outcomes) if outcomes else None
        f1 = (2 * precision * recall / (precision + recall)) if precision and recall else None
        results[str(span)] = {"n_naive_sequences": len(alerts), "tp": tp, "fp": fp,
                               "precision": precision, "recall": recall, "f1": f1}
    return results


# ---------------------------------------------------------------------------
# 1.3 -- 2x2 ablacio: allowlist es ertek-valtozas feltetel kulon-kulon,
# egyutt es egyik sem. A "naiv" (10s maxspan) szekvenciahalmazon dolgozik,
# ugyanazon a detailed_by_ip adaton, amit a fo evaluate_campaign.py is
# hasznal a finomitashoz.
# ---------------------------------------------------------------------------

def compute_2x2_ablation(episodes: list[Episode], naive_alerts: list[dict],
                          detailed_by_ip: dict) -> dict:
    t0836_eps = [e for e in episodes if e.scenario_id == "A1"]
    enriched = []
    for a in naive_alerts:
        docs = detailed_by_ip.get(a["source_ip"], [])
        read_doc = _nearest(docs, "READ_HOLDING_REGISTERS", a["read_ts"], JOIN_TOLERANCE_S)
        write_doc = _nearest(docs, "WRITE_SINGLE_REGISTER", a["write_ts"], JOIN_TOLERANCE_S)
        value_before = read_doc["response_values"][0] if read_doc and read_doc.get("response_values") else None
        value_after = write_doc["request_values"][0] if write_doc and write_doc.get("request_values") else None
        enriched.append({
            "write_ts": a["write_ts"],
            "not_allowlisted": a["source_ip"] != ALLOWLIST_IP,
            "value_changed": value_before is not None and value_after is not None and value_before != value_after,
        })

    def cell(use_allowlist: bool, use_value: bool) -> dict:
        fires = []
        for a in enriched:
            cond = True
            if use_allowlist:
                cond = cond and a["not_allowlisted"]
            if use_value:
                cond = cond and a["value_changed"]
            if cond:
                fires.append(a["write_ts"])
        outcomes = [1 if any(episode_hit(ep, ts) for ts in fires) else 0 for ep in t0836_eps]
        tp = sum(outcomes)
        fp = sum(1 for ts in fires if not any(episode_hit(ep, ts) for ep in episodes))
        precision = tp / (tp + fp) if (tp + fp) else None
        recall = tp / len(outcomes) if outcomes else None
        f1 = (2 * precision * recall / (precision + recall)) if precision and recall else None
        return {"fp": fp, "tp": tp, "precision": precision, "recall": recall, "f1": f1}

    return {
        "neither (naiv)": cell(False, False),
        "allowlist_only": cell(True, False),
        "value_change_only": cell(False, True),
        "both (finomitott)": cell(True, True),
    }


# ---------------------------------------------------------------------------
# 1.1 -- detekcios kesleltetes: epizod-kezdet -> a riasztast kivalto
# esemeny @timestamp-je. Csak azokra a technikakra ertelmezheto, amelyeknel
# van tenyleges TP (T0836, T0816/A.4) -- a harom vakfolt-technikara N/A.
# ---------------------------------------------------------------------------

def compute_detection_latency(episodes: list[Episode], refined_t0836_write_ts: list[datetime],
                               s7_alert_ts: list[datetime]) -> dict:
    def latencies_for(eps: list[Episode], alert_timestamps: list[datetime]) -> list[float]:
        out = []
        for ep in eps:
            hits = [ts for ts in alert_timestamps if episode_hit(ep, ts)]
            if hits:
                first_hit = min(hits)
                out.append((first_hit - ep.start).total_seconds())
        return out

    t0836_eps = [e for e in episodes if e.scenario_id == "A1"]
    t0816_a4_eps = [e for e in episodes if e.scenario_id == "A4"]

    def summarize(values: list[float]) -> Optional[dict]:
        if not values:
            return None
        arr = np.array(values)
        return {"n": len(values), "median_s": float(np.median(arr)),
                "p95_s": float(np.percentile(arr, 95)),
                "min_s": float(arr.min()), "max_s": float(arr.max())}

    t0836_lat = latencies_for(t0836_eps, refined_t0836_write_ts)
    t0816_lat = latencies_for(t0816_a4_eps, s7_alert_ts)

    return {
        "definicio": ("attack-to-alert: epizod kezdete (attack_log.jsonl start_ts) -> a "
                      "riasztast kivalto esemeny @timestamp-je. NEM azonos a Filebeat/ES "
                      "ingest-kesleltetessel (lasd Milestone 4, kulon dokumentalt korlat, "
                      "nincs event.ingested mezo a tarolt adatban)."),
        "T0836": summarize(t0836_lat),
        "T0816_A4": summarize(t0816_lat),
        "T0846": None, "T0888": None, "T0843": None, "T0816_A5": None,
        "note_vakfoltok": "N/A -- nincs aktiv szabaly / garantalt FN, nincs mibol kesleltetest szamolni.",
    }


# ---------------------------------------------------------------------------
# 1.5 -- technika-konfuzios matrix, szuk definicio: minden epizodra
# megnezzuk, hogy a KET aktiv szabaly (T0836-rule, T0816-rule) kozul
# melyik (ha barmelyik) tuzelt az epizod ablakaban -- fuggetlenul attol,
# hogy az adott epizod ground-truth technikaja megegyezik-e a szabalyeval.
# ---------------------------------------------------------------------------

def compute_confusion_matrix(episodes: list[Episode], refined_t0836_write_ts: list[datetime],
                              s7_alert_ts: list[datetime]) -> dict:
    labels = ["T0836", "T0816", "nincs_aktiv_szabaly (T0846/T0888/T0843)"]
    matrix: dict[str, dict[str, int]] = {t: {lab: 0 for lab in labels + ["egyik_sem_tuzelt"]}
                                          for t in sorted({e.technique for e in episodes})}
    for ep in episodes:
        t0836_fired = any(episode_hit(ep, ts) for ts in refined_t0836_write_ts)
        t0816_fired = any(episode_hit(ep, ts) for ts in s7_alert_ts)
        if ep.technique in ("T0846", "T0888", "T0843"):
            matrix[ep.technique]["nincs_aktiv_szabaly (T0846/T0888/T0843)"] += 1
            continue
        if t0836_fired:
            matrix[ep.technique]["T0836"] += 1
        elif t0816_fired:
            matrix[ep.technique]["T0816"] += 1
        else:
            matrix[ep.technique]["egyik_sem_tuzelt"] += 1
    return {
        "definicio_scope": ("Szuk definicio: csak a ket aktiv szabaly (T0836, T0816) "
                             "kereszt-teves tuzelese szamit konfuzionak. T0846/T0888/T0843 "
                             "strukturalisan nem tudnak semmilyen szabalyt kivaltani (nincs "
                             "rajuk epulo detekcio), ezert ezekre a matrix nem 'egyik_sem_tuzelt' "
                             "cellat mutat, hanem explicit kulon oszlopot -- a vakfolt tulajdonsag "
                             "nem tevesztendo ossze egy tenyleges, mert nulla, kereszt-tuzeles "
                             "hianyaval."),
        "matrix": matrix,
    }


# ---------------------------------------------------------------------------
# Fo folyamat
# ---------------------------------------------------------------------------

def main() -> None:
    if not LOCAL_ATTACK_LOG.exists():
        raise FileNotFoundError(f"{LOCAL_ATTACK_LOG} nem talalhato.")
    episodes = load_ground_truth(LOCAL_ATTACK_LOG)

    with SSHTunnel(SIEM_SSH_HOST, ES_LOCAL_PORT):
        naive_alerts_10s = fetch_naive_t0836_alerts_with_maxspan(10)
        detailed_by_ip = fetch_modbus_detailed_values()
        s7_alerts = fetch_t0816_alerts()
        maxspan_results = compute_maxspan_sensitivity(episodes, detailed_by_ip)

    refined_write_ts = []
    for a in naive_alerts_10s:
        docs = detailed_by_ip.get(a["source_ip"], [])
        read_doc = _nearest(docs, "READ_HOLDING_REGISTERS", a["read_ts"], JOIN_TOLERANCE_S)
        write_doc = _nearest(docs, "WRITE_SINGLE_REGISTER", a["write_ts"], JOIN_TOLERANCE_S)
        value_before = read_doc["response_values"][0] if read_doc and read_doc.get("response_values") else None
        value_after = write_doc["request_values"][0] if write_doc and write_doc.get("request_values") else None
        not_allowlisted = a["source_ip"] != ALLOWLIST_IP
        value_changed = value_before is not None and value_after is not None and value_before != value_after
        if not_allowlisted and value_changed:
            refined_write_ts.append(a["write_ts"])

    s7_ts = [a.ts for a in s7_alerts]

    results = {
        "1.1_detection_latency": compute_detection_latency(episodes, refined_write_ts, s7_ts),
        "1.2_maxspan_sensitivity": maxspan_results,
        "1.3_ablation_2x2": compute_2x2_ablation(episodes, naive_alerts_10s, detailed_by_ip),
        "1.5_confusion_matrix": compute_confusion_matrix(episodes, refined_write_ts, s7_ts),
    }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    json_path = RESULTS_DIR / "campaign_2026-08-22_sprint1_metrics.json"
    json_path.write_text(json.dumps(results, indent=2, default=str, ensure_ascii=False), encoding="utf-8")
    print(f"Kimenet irva: {json_path}")


if __name__ == "__main__":
    main()
