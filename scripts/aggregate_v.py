#!/usr/bin/env python3
"""aggregate_v.py -- M5 OSSZESITO (aggregate) a V1/V2 kiertekelesekhez (prereg-v1.1).

Bemenet: tobb `results/m5/eredmenyek_*.json` (kampanyonkent egy, az evaluate_v.py
kimenete). Kimenet: `results/m5/osszesitett_<UTC>.{json,md}`:
  (a) kampanyonkenti tabla (szcenario x konfiguracio, a prereg elsodleges egysege);
  (b) a V1 K kampany OSSZEVONT tablaja TECHNIKA x {C0,C1}-re (LÁTTA/n, Jeffreys
      Beta-posterior + 95% CI, a prereg modszerevel: pool k/n -> egy posterior);
  (c) FP (E-28) osszevont: talalat / benign keres / benign-ido, variansonkent;
  (d) D13 kulso jelzo: sulyozatlan Cohen-kappa + nyers egyezesi arany, osszevontan.

A V2 kampanyt KULON kezeli a posterior-tablaknal (b, c): nem vonja ossze a V1-gyel.
A D13 (d) ezzel szemben a prereg 5.3/NYK-8 szerint a V1 + V2 EGYEDI technikain egyszerre
ertelmezett (ha mindketto jelen van); jelenleg csak V1 kampanyok vannak.

Osszevonas MODJA (prereg, NEM dontes itt):
  - `VALIDACIOS-PROTOKOLL.md`:177-181  a LÁTTA-arany k/n; posterior Beta(k+1/2, n-k+1/2);
    "Aggregalas: ... a K=3 kampanyt osszevonva" -> epizod-POOL egy Beta-posteriorba
    (nem kampanyonkenti atlag);
  - `DONTESEK.md`:243  "elsodleges: szcenario x konfiguracio, a K=3 kampanyt osszevonva".
A posterior/CI szamitas az evaluate_v.beta_summary-bol jon (egyetlen igazsagforras,
mar tesztelt). Fuggoseg: csak a stdlib + az evaluate_v.py-ban mar hasznaltak.

Hasznalat:
  python3 scripts/aggregate_v.py results/m5/eredmenyek_*.json
  python3 scripts/aggregate_v.py results/m5/eredmenyek_20261101T145736Z.json  # 1 kampany
"""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evaluate_v as ev  # noqa: E402  -- beta_summary, cohen_kappa, OUT_DIR, REPO_ROOT

REPO_ROOT = ev.REPO_ROOT
OUT_DIR = ev.OUT_DIR

# --------------------------------------------------------------------------
# Szcenario -> ATT&CK v20 technika. A prereg-v1.1 3.1/3.2 szcenariotablajanak szo
# szerinti atirasa (`docs/tdk/VALIDACIOS-PROTOKOLL.md`:52-69): a szcenario-definicio
# a prereg-ben FIX, ezert ez transzkripcio, nem [SAJAT MERNOKI DONTES]. A C1-oldalt a
# betoltes futasidoben osszeveti a JSON `tech_seen_c1`-evel (self-check, lasd lent).
SCENARIO_TECHNIQUE = {
    "A1": "T0836", "A2": "T0888", "A3": "T0846.001", "A4": "T0816", "A5": "T0816",
    "A6": "T0843",
    "V2.1": "T0836", "V2.2": "T0893", "V2.3": "T0821", "V2.4": "T0836", "V2.5": "T0836",
}

_VARIANT_RE = re.compile(r"_(V\d+)_")


def variant_of(campaign_id: str) -> str:
    """A kampany-variansa (V1 / V2) a campaign_id-bol (campaign_<UTC>_V1_s1)."""
    m = _VARIANT_RE.search(campaign_id or "")
    return m.group(1) if m else "V?"


def technique_of(scenario: str) -> str:
    return SCENARIO_TECHNIQUE.get(scenario, scenario)


# ============================================================ betoltes
def load_results(paths: list[Path]) -> dict:
    """Beolvassa az eredmeny_*.json-okat, es kampany-szinten normalizal.

    Visszaad:
      secondary_rows: [{campaign_id, variant, scenario, technique, config,
                        k_seen, n_known, n_na, category_dist}]
      fp_by_campaign: {campaign_id: {variant, fp_count, sid, denom_requests,
                        denom_time_s}}
      mitre_by_tech:  {technique: bool|None}       (D13 MITRE-oldal)
      src_tech_seen_c1: {campaign_id-halmazra osszevont} -> itt csak a JSON-szintu
                        tech_seen_c1-eket gyujtjuk kereszt-ellenorzeshez:
                        [{techniques: {tech: {true, known}}}]
      src_secondary / src_fp / src_external: a forras-JSON ertekek a 4. pont
                        egyezes-ellenorzesehez (kampanyonkent).
    """
    secondary_rows: list[dict] = []
    fp_by_campaign: dict[str, dict] = {}
    mitre_by_tech: dict[str, object] = {}
    src_tech_seen_c1_blocks: list[dict] = []
    src_secondary: dict[tuple, dict] = {}
    src_fp: dict[str, dict] = {}
    src_external: list[dict] = []
    src_e39: list[dict] = []
    e39_excluded: list[str] = []

    for p in paths:
        doc = json.loads(Path(p).read_text(encoding="utf-8"))
        agg = doc.get("aggregate", {})

        for row in agg.get("secondary", []):
            cid = row["campaign_id"]
            scn = row["scenario"]
            rec = {
                "campaign_id": cid, "variant": variant_of(cid),
                "scenario": scn, "technique": technique_of(scn),
                "config": row["config"],
                "k_seen": row["k_seen"], "n_known": row["n_known"],
                "n_na": row.get("n_na", 0),
                "category_dist": row.get("category_dist", {}),
            }
            secondary_rows.append(rec)
            # forras-ertek a 4. pont egyezes-ellenorzesehez (posterior median/CI)
            pj = row.get("posterior_jeffreys", {})
            src_secondary[(cid, scn, row["config"])] = {
                "k_seen": row["k_seen"], "n_known": row["n_known"],
                "median": pj.get("median"), "ci_lo": pj.get("ci_lo"), "ci_hi": pj.get("ci_hi"),
            }

        for cid, fp in agg.get("fp_per_campaign", {}).items():
            fp_by_campaign[cid] = {
                "variant": variant_of(cid),
                "fp_count": fp.get("fp_count", 0),
                "sid": fp.get("sid"),
                "denom_requests": fp.get("denominator_benign_requests", 0),
                "denom_time_s": fp.get("denominator_benign_time_s"),
            }
            src_fp[cid] = fp

        ext = agg.get("external_signal", {})
        for row in ext.get("rows", []):
            t = row["technique"]
            m = row.get("mitre_network_analytic")
            if t in mitre_by_tech and mitre_by_tech[t] != m:
                print(f"[FIGYELEM] MITRE-ellentmondas a {t} technikanal a JSON-ok kozott: "
                      f"{mitre_by_tech[t]} vs {m}", file=sys.stderr)
            if m is not None:
                mitre_by_tech[t] = m
            elif t not in mitre_by_tech:
                mitre_by_tech[t] = None
        if ext:
            src_external.append({"kappa": ext.get("cohen_kappa_unweighted"),
                                 "n_paired": ext.get("n_paired"),
                                 "rows": ext.get("rows", [])})

        tsc1 = agg.get("tech_seen_c1", {})
        if tsc1:
            src_tech_seen_c1_blocks.append(tsc1)

        e39 = agg.get("e39")
        if e39:
            cids = doc.get("meta", {}).get("campaigns", [])
            var = variant_of(cids[0]) if cids else None
            for r in e39.get("by_technique_config", []):
                src_e39.append({
                    "variant": var, "technique": r["technique"], "config": r["config"],
                    "main_k": r["main"]["k"], "main_n": r["main"]["n"],
                    "sens_k": r["sensitivity"]["k"], "sens_n": r["sensitivity"]["n"],
                })
            e39_excluded.extend(e39.get("excluded", []))

    return {
        "secondary_rows": secondary_rows,
        "fp_by_campaign": fp_by_campaign,
        "mitre_by_tech": mitre_by_tech,
        "src_tech_seen_c1_blocks": src_tech_seen_c1_blocks,
        "src_secondary": src_secondary,
        "src_fp": src_fp,
        "src_external": src_external,
        "src_e39": src_e39,
        "e39_excluded": sorted(set(e39_excluded)),
    }


# ============================================================ (b) technika-pool
def pool_by_technique(secondary_rows: list[dict], variant: str) -> list[dict]:
    """A `variant` (pl. 'V1') kampanyainak epizodjait TECHNIKA x konfiguracio szerint
    POOL-ozza: k = sum(k_seen), n = sum(n_known); majd Jeffreys/uniform Beta-posterior
    (ev.beta_summary). A prereg 5.4 szerinti k/n-pool (nem kampanyonkenti atlag)."""
    groups: dict[tuple, dict] = {}
    for r in secondary_rows:
        if r["variant"] != variant:
            continue
        key = (r["technique"], r["config"])
        g = groups.setdefault(key, {"k": 0, "n": 0, "na": 0,
                                    "scenarios": set(), "campaigns": set(),
                                    "category_dist": {}})
        g["k"] += r["k_seen"]
        g["n"] += r["n_known"]
        g["na"] += r["n_na"]
        g["scenarios"].add(r["scenario"])
        g["campaigns"].add(r["campaign_id"])
        for cat, cnt in r["category_dist"].items():
            g["category_dist"][cat] = g["category_dist"].get(cat, 0) + cnt
    out = []
    for (tech, cfg), g in sorted(groups.items()):
        k, n = g["k"], g["n"]
        out.append({
            "technique": tech, "config": cfg,
            "k_seen": k, "n_known": n, "n_na": g["na"],
            "k_campaigns": len(g["campaigns"]),
            "scenarios": sorted(g["scenarios"]),
            "category_dist": g["category_dist"],
            "posterior_jeffreys": ev.beta_summary(k, n, True),
            "posterior_uniform": ev.beta_summary(k, n, False),
        })
    return out


# ============================================================ (c) FP-pool
def pool_fp(fp_by_campaign: dict[str, dict], variant: str) -> dict:
    """A `variant` kampanyainak FP-jet osszevonja: Sum talalat / Sum keres /
    Sum benign-ido (E-28). FP/keres es FP/ora az osszegekbol szamolva."""
    fps = [fp for fp in fp_by_campaign.values() if fp["variant"] == variant]
    if not fps:
        return {}
    fp_count = sum(fp["fp_count"] for fp in fps)
    denom_req = sum(fp["denom_requests"] for fp in fps)
    times = [fp["denom_time_s"] for fp in fps if fp["denom_time_s"] is not None]
    denom_time = sum(times) if times else None
    sid = next((fp["sid"] for fp in fps if fp["sid"] is not None), None)
    return {
        "variant": variant, "sid": sid, "n_campaigns": len(fps),
        "fp_count": fp_count,
        "denominator_benign_requests": denom_req,
        "denominator_benign_time_s": denom_time,
        "fp_per_request": (fp_count / denom_req) if denom_req else None,
        "fp_per_hour": (fp_count / (denom_time / 3600.0)) if denom_time else None,
    }


# ============================================================ (d) D13 kappa
def pool_external_signal(secondary_rows: list[dict], mitre_by_tech: dict) -> dict:
    """D13 (prereg 5.3/NYK-8): technikankent 'nalunk = LÁTTA a C1-ben' (az OSSZES
    betoltott kampanyra poolozva, V1+V2 egyutt), MITRE = van NSM/netflow/otids
    analitika. Sulyozatlan Cohen-kappa + nyers egyezesi arany; a degeneracio okat
    is kozli (konstans MITRE-oldal -> nulla variancia -> kappa=0)."""
    # C1 LÁTTA technikankent, minden kampanyt osszevonva (a VARIANS itt NEM szamit)
    c1: dict[str, dict] = {}
    for r in secondary_rows:
        if r["config"] != "C1":
            continue
        d = c1.setdefault(r["technique"], {"true": 0, "known": 0})
        d["true"] += r["k_seen"]
        d["known"] += r["n_known"]

    techs = sorted(set(c1) | set(mitre_by_tech))
    rows, ours_bits, theirs_bits = [], [], []
    for t in techs:
        d = c1.get(t, {"true": 0, "known": 0})
        ours = (d["true"] > 0) if d["known"] > 0 else None
        mt = mitre_by_tech.get(t)
        rows.append({"technique": t, "ours_c1_seen": ours,
                     "ours_k": d["true"], "ours_n": d["known"],
                     "mitre_network_analytic": mt})
        if ours is None or mt is None:
            continue
        ours_bits.append(1 if ours else 0)
        theirs_bits.append(1 if mt else 0)

    detail = ev.cohen_kappa_detail(ours_bits, theirs_bits)
    kappa = detail["kappa"]
    raw_agree = (sum(1 for a, b in zip(ours_bits, theirs_bits) if a == b) / len(ours_bits)
                 if ours_bits else None)
    # degeneracio-ok: valamelyik oldal konstans -> nulla variancia -> kappa null/0
    reason = None
    if ours_bits:
        if len(set(theirs_bits)) == 1:
            reason = ("a MITRE-oldal konstans (minden technikara %s) -> nulla variancia "
                      "-> a kappa fuggetlen az egyezestol (5.3: 'csak jelzokent'); a nyers "
                      "egyezesi arany informativabb" % ("IGEN" if theirs_bits[0] else "NEM"))
        elif len(set(ours_bits)) == 1:
            reason = ("a mi oldalunk konstans (minden technikara %s) -> nulla variancia"
                      % ("LÁTTA" if ours_bits[0] else "NEM"))
    return {
        "rows": rows,
        "n_paired": len(ours_bits),
        "cohen_kappa_unweighted": kappa,
        "p_observed": detail["p_observed"],
        "p_expected": detail["p_expected"],
        "kappa_note": detail["kappa_note"],
        "raw_agreement": raw_agree,
        "raw_agreement_frac": (f"{sum(1 for a,b in zip(ours_bits,theirs_bits) if a==b)}/{len(ours_bits)}"
                               if ours_bits else None),
        "degeneracy_reason": reason,
    }


# ============================================================ E-39 osszevonas
def pool_e39(src_e39: list[dict], variant: str) -> list[dict]:
    """E-39 erzekenysegi elemzes a `variant` kampanyaira osszevonva: technika x
    konfiguracio szerint a fo (main) es az erzekenysegi (sens) k/n osszegezve,
    majd ujraszamolt Beta-posterior; eltares-jeloles."""
    groups: dict[tuple, dict] = {}
    for r in src_e39:
        if r["variant"] != variant:
            continue
        g = groups.setdefault((r["technique"], r["config"]),
                              {"mk": 0, "mn": 0, "sk": 0, "sn": 0})
        g["mk"] += r["main_k"]; g["mn"] += r["main_n"]
        g["sk"] += r["sens_k"]; g["sn"] += r["sens_n"]
    out = []
    for (t, cfg) in sorted(groups):
        g = groups[(t, cfg)]
        out.append({
            "technique": t, "config": cfg,
            "main": {"k": g["mk"], "n": g["mn"],
                     "posterior_jeffreys": ev.beta_summary(g["mk"], g["mn"], True)},
            "sensitivity": {"k": g["sk"], "n": g["sn"],
                            "posterior_jeffreys": ev.beta_summary(g["sk"], g["sn"], True)},
            "changed": (g["mk"] != g["sk"]) or (g["mn"] != g["sn"]),
        })
    return out


# ============================================================ (a) kampanyonkent
def per_campaign_table(secondary_rows: list[dict]) -> list[dict]:
    """(a) A prereg elsodleges egysege kampanyonkent: szcenario x konfiguracio.
    A posteriort ujraszamolja (ev.beta_summary), igy a forras-JSON-nal egyeznie kell
    (ez a 4. pont egyik egyezes-ellenorzese)."""
    out = []
    for r in sorted(secondary_rows, key=lambda x: (x["campaign_id"], x["scenario"], x["config"])):
        k, n = r["k_seen"], r["n_known"]
        out.append({
            "campaign_id": r["campaign_id"], "variant": r["variant"],
            "scenario": r["scenario"], "technique": r["technique"], "config": r["config"],
            "k_seen": k, "n_known": n, "n_na": r["n_na"],
            "posterior_jeffreys": ev.beta_summary(k, n, True),
        })
    return out


# ============================================================ 4. pont: egyezes
def _approx(a, b, tol=1e-9) -> bool:
    if a is None and b is None:
        return True
    if a is None or b is None:
        return False
    return abs(a - b) <= tol


def verify_equivalence(data: dict, per_camp: list[dict], ext: dict) -> list[str]:
    """4. pont: az osszevont ertekeknek egyezniuk kell a forras-kiertekelessel.
    - (a) a kampanyonkenti (szcenario x config) k/n + posterior == forras secondary;
    - (d) C1 technika-pool k/n == a forras JSON-ok tech_seen_c1 osszege (ez igazolja
      a SCENARIO_TECHNIQUE lelepezest is);
    - (d) a kappa == a forras external_signal kappaja (ha pontosan 1 forras-blokk van).
    Visszaad: ember-olvashato PASS/FAIL sorok listaja."""
    lines = []
    ok = True

    # (a) per-campaign secondary == forras
    n_checked = 0
    for r in per_camp:
        key = (r["campaign_id"], r["scenario"], r["config"])
        src = data["src_secondary"].get(key)
        if src is None:
            lines.append(f"  [FAIL] (a) hianyzo forras-sor: {key}")
            ok = False
            continue
        pj = r["posterior_jeffreys"]
        same = (r["k_seen"] == src["k_seen"] and r["n_known"] == src["n_known"]
                and _approx(pj["median"], src["median"]) and _approx(pj["ci_lo"], src["ci_lo"])
                and _approx(pj["ci_hi"], src["ci_hi"]))
        n_checked += 1
        if not same:
            ok = False
            lines.append(f"  [FAIL] (a) elteres {key}: ujra k/n={r['k_seen']}/{r['n_known']} "
                         f"med={pj['median']} vs forras k/n={src['k_seen']}/{src['n_known']} "
                         f"med={src['median']}")
    lines.append(f"  [{'PASS' if ok else 'FAIL'}] (a) kampanyonkenti szcenario x config "
                 f"k/n + posterior == forras secondary ({n_checked} sor)")

    # (d) C1 technika-pool == forras tech_seen_c1 osszege
    pooled_c1: dict[str, dict] = {}
    for rr in data["secondary_rows"]:
        if rr["config"] != "C1":
            continue
        d = pooled_c1.setdefault(rr["technique"], {"true": 0, "known": 0})
        d["true"] += rr["k_seen"]
        d["known"] += rr["n_known"]
    src_c1: dict[str, dict] = {}
    for block in data["src_tech_seen_c1_blocks"]:
        for t, d in block.items():
            s = src_c1.setdefault(t, {"true": 0, "known": 0})
            s["true"] += d.get("true", 0)
            s["known"] += d.get("known", 0)
    c1_ok = (pooled_c1 == src_c1)
    if not c1_ok:
        ok = False
        lines.append(f"  [FAIL] (d) C1 technika-pool != tech_seen_c1: "
                     f"pool={pooled_c1} vs forras={src_c1}")
    lines.append(f"  [{'PASS' if c1_ok else 'FAIL'}] (d) C1 technika-pool (SCENARIO_TECHNIQUE) "
                 f"== forras tech_seen_c1 osszege  [{pooled_c1}]")

    # (d) kappa == forras kappa (csak ha pontosan egy forras-external-blokk van)
    if len(data["src_external"]) == 1:
        src_k = data["src_external"][0]["kappa"]
        agg_k = ext["cohen_kappa_unweighted"]
        k_ok = _approx(src_k, agg_k)
        if not k_ok:
            ok = False
        lines.append(f"  [{'PASS' if k_ok else 'FAIL'}] (d) Cohen-kappa == forras "
                     f"(osszevont={agg_k} vs forras={src_k})")
    else:
        lines.append(f"  [INFO] (d) kappa-egyezes kihagyva: {len(data['src_external'])} "
                     f"forras-external-blokk (tobb kampany -> nincs trivialis referencia)")

    lines.append(f"  ==> OSSZESEN: {'PASS' if ok else 'FAIL'}")
    return lines


# ============================================================ kimenet
def build_result(data: dict) -> dict:
    variants = sorted({r["variant"] for r in data["secondary_rows"]})
    per_camp = per_campaign_table(data["secondary_rows"])
    pooled = {v: pool_by_technique(data["secondary_rows"], v) for v in variants}
    fp = {v: pool_fp(data["fp_by_campaign"], v) for v in variants}
    fp = {v: x for v, x in fp.items() if x}
    ext = pool_external_signal(data["secondary_rows"], data["mitre_by_tech"])
    e39 = {v: pool_e39(data.get("src_e39", []), v) for v in variants}
    e39 = {v: x for v, x in e39.items() if x}
    campaigns = sorted({r["campaign_id"] for r in data["secondary_rows"]})
    return {
        "meta": {
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "prereg": "v1.1",
            "stats_backend": ev.STATS_BACKEND,
            "campaigns": campaigns,
            "variants": variants,
            "scenario_technique_map": SCENARIO_TECHNIQUE,
            "note": ("(b)/(c) variansonkent kulon (V1 nem vonodik ossze V2-vel); "
                     "(d) D13 a V1+V2 egyedi technikain egyutt (prereg 5.3/NYK-8)."),
        },
        "per_campaign": per_camp,
        "pooled_by_technique": pooled,
        "fp_pooled": fp,
        "external_signal": ext,
        "e39": e39,
        "e39_excluded": data.get("e39_excluded", []),
    }


def _fmt_post(pj: dict) -> str:
    if pj.get("median") is None:
        return "NA"
    return f"{pj['median']:.3f} [{pj['ci_lo']:.3f}, {pj['ci_hi']:.3f}]"


def write_outputs(result: dict, verify_lines: list[str]) -> tuple[Path, Path]:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    utc = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_path = OUT_DIR / f"osszesitett_{utc}.json"
    md_path = OUT_DIR / f"osszesitett_{utc}.md"
    json_path.write_text(json.dumps(result, indent=2, default=str, ensure_ascii=False),
                         encoding="utf-8")

    L = []
    m = result["meta"]
    L.append(f"# M5 osszesito (prereg-v1.1, E-28) -- {utc}")
    L.append("")
    L.append(f"- Statisztikai backend: `{m['stats_backend']}`")
    L.append(f"- Kampanyok ({len(m['campaigns'])}): {', '.join(m['campaigns']) or '-'}")
    L.append(f"- Variansok: {', '.join(m['variants']) or '-'}")
    L.append(f"- Megjegyzes: {m['note']}")
    L.append("")

    # (a)
    L.append("## (a) Kampanyonkent -- szcenario x konfiguracio (prereg elsodleges egyseg)")
    L.append("")
    L.append("| Kampany | Szcenario | Technika | Konfig | LÁTTA k | n | NA | posterior median [95% CI] |")
    L.append("|---|---|---|---|---|---|---|---|")
    for r in result["per_campaign"]:
        L.append(f"| {r['campaign_id']} | {r['scenario']} | {r['technique']} | {r['config']} | "
                 f"{r['k_seen']} | {r['n_known']} | {r['n_na']} | {_fmt_post(r['posterior_jeffreys'])} |")
    L.append("")

    # (b)
    L.append("## (b) Osszevont -- TECHNIKA x konfiguracio (variansonkent, K kampany poolozva)")
    L.append("")
    for v in result["meta"]["variants"]:
        rows = result["pooled_by_technique"].get(v, [])
        kcnt = max((r["k_campaigns"] for r in rows), default=0)
        L.append(f"### {v} (K={kcnt} kampany, epizod-pool -> egy Beta-posterior)")
        L.append("")
        L.append("| Technika | Konfig | szcenariok | LÁTTA k | n | NA | posterior median [95% CI] | uniform (erzekenyseg) |")
        L.append("|---|---|---|---|---|---|---|---|")
        for r in rows:
            L.append(f"| {r['technique']} | {r['config']} | {','.join(r['scenarios'])} | "
                     f"{r['k_seen']} | {r['n_known']} | {r['n_na']} | "
                     f"{_fmt_post(r['posterior_jeffreys'])} | {_fmt_post(r['posterior_uniform'])} |")
        L.append("")

    # (c)
    L.append("## (c) FP (5.4, E-28) osszevont -- variansonkent")
    L.append("")
    L.append("| Varians | SID | kampany | FP | benign keres | benign-ido (s) | FP/keres | FP/ora |")
    L.append("|---|---|---|---|---|---|---|---|")
    for v, fp in result["fp_pooled"].items():
        bt = f"{fp['denominator_benign_time_s']:.0f}" if fp["denominator_benign_time_s"] else "NA"
        fpr = f"{fp['fp_per_request']:.4f}" if fp["fp_per_request"] is not None else "NA"
        fph = f"{fp['fp_per_hour']:.2f}" if fp["fp_per_hour"] is not None else "NA"
        L.append(f"| {v} | {fp['sid']} | {fp['n_campaigns']} | {fp['fp_count']} | "
                 f"{fp['denominator_benign_requests']} | {bt} | {fpr} | {fph} |")
    L.append("")

    # (d)
    ext = result["external_signal"]
    L.append("## (d) D13 kulso jelzo -- Cohen-kappa + nyers egyezes (osszevont, V1+V2 egyutt)")
    L.append("")
    L.append(f"- Parosított technikak: {ext['n_paired']}")
    kap = ext["cohen_kappa_unweighted"]
    L.append(f"- Sulyozatlan Cohen-kappa: {kap:.3f}" if kap is not None
             else "- Sulyozatlan Cohen-kappa: null (nem definialt)")
    po, pe = ext.get("p_observed"), ext.get("p_expected")
    L.append(f"- p_o (megfigyelt egyezes): {po:.3f}" if po is not None else "- p_o: NA")
    L.append(f"- p_e (vart egyezes): {pe:.3f}" if pe is not None else "- p_e: NA")
    L.append(f"- Nyers egyezesi arany: {ext['raw_agreement_frac']} "
             f"({ext['raw_agreement']:.3f})" if ext["raw_agreement"] is not None
             else "- Nyers egyezesi arany: NA")
    if ext.get("kappa_note"):
        L.append(f"- Megjegyzes (kappa): {ext['kappa_note']}")
    if ext["degeneracy_reason"]:
        L.append(f"- Degeneracio: {ext['degeneracy_reason']}")
    L.append("")
    L.append("| Technika | nalunk (C1 LÁTTA) | k/n (C1) | MITRE NSM/netflow/otids |")
    L.append("|---|---|---|---|")
    for row in ext["rows"]:
        us = "NA" if row["ours_c1_seen"] is None else ("LÁTTA" if row["ours_c1_seen"] else "NEM")
        mt = "NA" if row["mitre_network_analytic"] is None else ("IGEN" if row["mitre_network_analytic"] else "NEM")
        L.append(f"| {row['technique']} | {us} | {row['ours_k']}/{row['ours_n']} | {mt} |")
    L.append("")

    # (e) E-39 erzekenysegi elemzes
    if result.get("e39"):
        L.append("## (e) Erzekenysegi elemzes (E-39) -- eloallapot-sertes (value_before != 1009)")
        L.append("")
        exc = result.get("e39_excluded", [])
        L.append(f"- Kizart epizodok (fo elemzesben BENNE, itt a nelkuluk): {len(exc)}")
        if exc:
            L.append(f"  - {', '.join(exc)}")
        L.append("")
        for v in result["meta"]["variants"]:
            rows = result["e39"].get(v, [])
            if not rows:
                continue
            L.append(f"### {v} (osszevont)")
            L.append("")
            L.append("| Technika | Konfig | fo k/n | fo median [95% CI] | erz. k/n | erz. median [95% CI] | eltares |")
            L.append("|---|---|---|---|---|---|---|")
            for r in rows:
                mark = "**ELTER**" if r["changed"] else "="
                L.append(f"| {r['technique']} | {r['config']} | "
                         f"{r['main']['k']}/{r['main']['n']} | {_fmt_post(r['main']['posterior_jeffreys'])} | "
                         f"{r['sensitivity']['k']}/{r['sensitivity']['n']} | {_fmt_post(r['sensitivity']['posterior_jeffreys'])} | {mark} |")
            L.append("")

    # 4. pont egyezes-ellenorzes
    L.append("## 4. pont -- egyezes-ellenorzes (osszevont == forras kiertekeles)")
    L.append("")
    L.append("```")
    L.extend(verify_lines)
    L.append("```")
    md_path.write_text("\n".join(L), encoding="utf-8")
    return json_path, md_path


# ============================================================ fo
def main() -> None:
    ap = argparse.ArgumentParser(description="M5 osszesito a V1/V2 kiertekelesekhez (prereg-v1.1)")
    ap.add_argument("inputs", nargs="*",
                    help="eredmeny_*.json fajlok (alapbol results/m5/eredmenyek_*.json)")
    args = ap.parse_args()

    if args.inputs:
        paths: list[Path] = []
        for pat in args.inputs:
            matched = [Path(x) for x in glob.glob(pat)]
            paths.extend(matched if matched else [Path(pat)])
    else:
        paths = [Path(x) for x in sorted(glob.glob(str(OUT_DIR / "eredmenyek_*.json")))]
    paths = [p for p in paths if p.exists()]
    if not paths:
        raise SystemExit("Nincs bemeneti eredmeny_*.json.")

    print("Bemeneti eredmeny-JSON-ok:")
    for p in paths:
        print(f"  {p}")

    data = load_results(paths)
    if not data["secondary_rows"]:
        raise SystemExit("A bemeneti JSON-okban nincs aggregate.secondary sor.")

    result = build_result(data)
    per_camp = result["per_campaign"]
    verify_lines = verify_equivalence(data, per_camp, result["external_signal"])

    json_path, md_path = write_outputs(result, verify_lines)
    print("\n4. pont -- egyezes-ellenorzes:")
    for ln in verify_lines:
        print(ln)
    print(f"\nKimenet: {json_path}")
    print(f"Kimenet: {md_path}")


if __name__ == "__main__":
    main()
