"""M3-G(a): ATT&CK for ICS v19.2 / v20.0 detektálási szerkezet (csak stdlib, hálózat nélkül).

Használat (a repó gyökeréből):
    python -I results/m3g/attack_ics_structure.py \
        docs/tdk/related-works/forrasok/ics-attack-19.2.json \
        docs/tdk/related-works/forrasok/ics-attack-20.0.json \
        results/m3g

A bemeneti fájlok sha256-ját a futás elején ellenőrzi a #73/#74 .meta.json-jában
rögzített értékkel; eltérés esetén leáll.

Kimenet (az utolsó argumentumként megadott mappába):
    attack_ics_structure.txt               – szöveges jelentés (1–5., 7., 8. pont)
    attack_ics_v19_2_detection_map.csv     – technika → DET → AN → DC (v19.2)
    attack_ics_v20_detection_map.csv       – technika → DET → AN → DC (v20.0)
"""
import collections
import csv
import hashlib
import json
import os
import re
import sys

EXPECTED_SHA256 = {
    "ics-attack-19.2.json": "08b83d2cea6b6d6752468ef0e62e2ab2a53c9443ef72c439ecccb07ab9e89da9",
    "ics-attack-20.0.json": "c9ca0ce523a1b5e512060a390415e8aefe8f6d32c5f82d7de81264960c1e1183",
}
STUDIED_IDS = ["T0836", "T0846", "T0846.001", "T0888", "T0816", "T0843", "T0843.001",
               "T1692.001", "T0893", "T0821", "T0849", "T0834", "T1694"]
EXTRA_V19 = ["T0855"]
DETECTION_TYPES = ["x-mitre-data-component", "x-mitre-data-source",
                   "x-mitre-detection-strategy", "x-mitre-analytic"]
# FELTÉTELEZÉS: név alapú heurisztika, nem a MITRE besorolása.
NETWORK_HEURISTIC_TEXT = ("network_dc_FELTETELEZES = IGEN, ha az x-mitre-data-component 'name' mezője "
                          "kis- és nagybetű-érzéketlenül tartalmazza a következők egyikét: "
                          "'network', 'traffic', 'flow', 'connection'; különben NEM. "
                          "Név alapú heurisztika (FELTÉTELEZÉS), nem a MITRE besorolása.")
NETWORK_RE = re.compile(r"network|traffic|flow|connection", re.IGNORECASE)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ext_id(o):
    for r in o.get("external_references", []):
        if r.get("source_name") in ("mitre-attack", "mitre-ics-attack") and r.get("external_id"):
            return r["external_id"]
    return ""


def active(o):
    return not o.get("revoked", False) and not o.get("x_mitre_deprecated", False)


def is_network(name):
    return "IGEN" if NETWORK_RE.search(name or "") else "NEM"


class Bundle:
    def __init__(self, path):
        with open(path, encoding="utf-8") as f:
            self.objects = json.load(f)["objects"]
        self.by_id = {o["id"]: o for o in self.objects}
        self.rels = [o for o in self.objects if o["type"] == "relationship"]

    def of_type(self, t):
        return [o for o in self.objects if o["type"] == t]

    def ap_by_ext(self, tid):
        return [o for o in self.of_type("attack-pattern") if ext_id(o) == tid]

    def chain(self, ap):
        """technika ← detects ← DET; DET.x_mitre_analytic_refs → AN;
        AN.x_mitre_log_source_references[].x_mitre_data_component_ref → DC.
        Csak aktív (nem revoked, nem deprecated) kapcsolt objektumok."""
        dets, ans, dcs, dropped = [], [], [], 0
        for r in self.rels:
            if r.get("relationship_type") != "detects" or r.get("target_ref") != ap["id"]:
                continue
            if r.get("revoked") or r.get("x_mitre_deprecated"):
                dropped += 1
                continue
            src = self.by_id.get(r["source_ref"])
            if src is None or src["type"] != "x-mitre-detection-strategy":
                continue
            if not active(src):
                dropped += 1
                continue
            if src not in dets:
                dets.append(src)
        for d in dets:
            for aref in d.get("x_mitre_analytic_refs", []):
                a = self.by_id.get(aref)
                if a is None:
                    continue
                if not active(a):
                    dropped += 1
                    continue
                if a not in ans:
                    ans.append(a)
        for a in ans:
            for ls in a.get("x_mitre_log_source_references", []):
                dc = self.by_id.get(ls.get("x_mitre_data_component_ref"))
                if dc is None:
                    continue
                if not active(dc):
                    dropped += 1
                    continue
                if dc not in dcs:
                    dcs.append(dc)
        return dets, ans, dcs, dropped


def report_version(label, b, out):
    p = lambda *a: print(*a, file=out)
    p(f"################ {label} ################")
    p(f"objektumok összesen: {len(b.objects)}")
    p("\n## 1. Objektumtípusonkénti darabszám (összes / revoked=true / x_mitre_deprecated=true)")
    types = collections.Counter(o["type"] for o in b.objects)
    for t, n in sorted(types.items()):
        xs = [o for o in b.objects if o["type"] == t]
        p(f"{t:32s} {n:5d}  revoked={sum(1 for o in xs if o.get('revoked') is True):4d}"
          f"  deprecated={sum(1 for o in xs if o.get('x_mitre_deprecated') is True):4d}")

    p("\n## 2. Relationship-típus × (forrástípus → céltípus) (összes / ebből revoked / deprecated)")
    rc = collections.Counter()
    rr = collections.Counter()
    rd = collections.Counter()
    for r in b.rels:
        s = b.by_id.get(r["source_ref"], {}).get("type", "?" + r["source_ref"].split("--")[0])
        t = b.by_id.get(r["target_ref"], {}).get("type", "?" + r["target_ref"].split("--")[0])
        k = (r.get("relationship_type"), s, t)
        rc[k] += 1
        rr[k] += bool(r.get("revoked"))
        rd[k] += bool(r.get("x_mitre_deprecated"))
    for k in sorted(rc):
        p(f"{k[0]:16s} {k[1]:28s} -> {k[2]:28s} {rc[k]:5d}  revoked={rr[k]:3d}  deprecated={rd[k]:3d}")

    p("\n## 3. Detektálási objektumtípusok jelenléte és 1-1 minta (az id szerint első aktív objektum, nyersen)")
    for t in DETECTION_TYPES:
        xs = sorted(b.of_type(t), key=lambda o: o["id"])
        p(f"{t}: {'VAN' if xs else 'NINCS'} ({len(xs)} db)")
        act = [o for o in xs if active(o)] or xs
        if act:
            p(json.dumps(act[0], ensure_ascii=False, indent=2))

    p("\n## 4. Kötési mezők (a fájlban talált mezőnevek és értéktípusok)")
    for t in DETECTION_TYPES + ["attack-pattern"]:
        keys = collections.Counter(k for o in b.of_type(t) for k in o)
        refk = sorted(k for k in keys if k.endswith("_ref") or k.endswith("_refs")
                      or k.endswith("_references") or k == "x_mitre_log_sources")
        p(f"{t}: hivatkozó/kötő mezők = {refk}")
    lsr_keys = collections.Counter()
    lsr_target_types = collections.Counter()
    for a in b.of_type("x-mitre-analytic"):
        for ls in a.get("x_mitre_log_source_references", []):
            lsr_keys.update(ls.keys())
            lsr_target_types[b.by_id.get(ls.get("x_mitre_data_component_ref"), {}).get("type", "FELOLDATLAN")] += 1
    p(f"x-mitre-analytic.x_mitre_log_source_references[] elemkulcsai: {dict(lsr_keys)}")
    p(f"  ... x_mitre_data_component_ref céltípusai: {dict(lsr_target_types)}")
    for a in sorted(b.of_type("x-mitre-analytic"), key=ext_id):
        for ls in a.get("x_mitre_log_source_references", []):
            if ls.get("x_mitre_data_component_ref") not in b.by_id:
                p(f"  FELOLDATLAN: {ext_id(a)} -> {ls.get('x_mitre_data_component_ref')} | name={ls.get('name')}")
    plats = collections.Counter(repr(a.get("x_mitre_platforms")) for a in b.of_type("x-mitre-analytic"))
    p(f"x-mitre-analytic.x_mitre_platforms értékei (repr): {dict(plats)}")
    no_det = [ext_id(o) for o in b.of_type("attack-pattern") if active(o) and not b.chain(o)[0]]
    p(f"aktív attack-pattern aktív detektálási stratégia nélkül: {len(no_det)} {sorted(no_det)}")
    ar_types = collections.Counter(b.by_id.get(r, {}).get("type", "FELOLDATLAN")
                                   for d in b.of_type("x-mitre-detection-strategy")
                                   for r in d.get("x_mitre_analytic_refs", []))
    p(f"x-mitre-detection-strategy.x_mitre_analytic_refs céltípusai: {dict(ar_types)}")
    dcls_keys = collections.Counter(k for dc in b.of_type("x-mitre-data-component")
                                    for ls in dc.get("x_mitre_log_sources", []) for k in ls)
    p(f"x-mitre-data-component.x_mitre_log_sources[] elemkulcsai: {dict(dcls_keys)}")
    dc_ds = collections.Counter(k for dc in b.of_type("x-mitre-data-component")
                                for k in dc if "data_source" in k)
    p(f"x-mitre-data-component adatforrás-hivatkozó mezői: {dict(dc_ds) or 'NINCS'}")

    p("\n## 5. 'detects' relációk forrástípus szerint")
    det = collections.Counter()
    for r in b.rels:
        if r.get("relationship_type") == "detects":
            det[(b.by_id.get(r["source_ref"], {}).get("type"), b.by_id.get(r["target_ref"], {}).get("type"),
                 "revoked" if r.get("revoked") else ("deprecated" if r.get("x_mitre_deprecated") else "aktív"))] += 1
    for k, n in sorted(det.items(), key=str):
        p(f"detects: {k[0]} -> {k[1]} [{k[2]}]: {n}")
    n_dc = sum(n for k, n in det.items() if k[0] == "x-mitre-data-component" and k[1] == "attack-pattern")
    p(f"x-mitre-data-component --detects--> attack-pattern összesen: {n_dc}")


def write_csv(b, path):
    rows = 0
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["technique_id", "name", "detection_strategy_ids", "analytic_ids",
                    "data_component_ids", "data_component_names", "network_dc_FELTETELEZES",
                    "attack_pattern_stix_id", "detection_strategy_stix_ids", "analytic_stix_ids",
                    "data_component_stix_ids"])
        aps = sorted((o for o in b.of_type("attack-pattern") if active(o)), key=ext_id)
        for ap in aps:
            dets, ans, dcs, _ = b.chain(ap)
            w.writerow([ext_id(ap), ap["name"],
                        ";".join(ext_id(d) for d in dets),
                        ";".join(ext_id(a) for a in ans),
                        ";".join(ext_id(d) for d in dcs),
                        ";".join(d["name"] for d in dcs),
                        ";".join(f"{d['name']}={is_network(d['name'])}" for d in dcs),
                        ap["id"],
                        ";".join(d["id"] for d in dets),
                        ";".join(a["id"] for a in ans),
                        ";".join(d["id"] for d in dcs)])
            rows += 1
    return rows


def studied(label, b, ids, out):
    p = lambda *a: print(*a, file=out)
    p(f"\n## 7. Vizsgált ID-k – {label}")
    for tid in ids:
        aps = b.ap_by_ext(tid)
        if not aps:
            p(f"{tid}: NINCS a fájlban")
            continue
        for ap in aps:
            state = "revoked" if ap.get("revoked") else ("deprecated" if ap.get("x_mitre_deprecated") else "aktív")
            p(f"{tid} | {ap['name']} | {state} | {ap['id']}")
            if ap.get("revoked"):
                for r in b.rels:
                    if r.get("relationship_type") == "revoked-by" and r["source_ref"] == ap["id"]:
                        t = b.by_id.get(r["target_ref"], {})
                        p(f"   revoked-by -> {ext_id(t)} {t.get('name')} {r['target_ref']}")
                # a revoked technikára mutató 'detects' relációk, szűrés nélkül
                for r in b.rels:
                    if r.get("relationship_type") == "detects" and r["target_ref"] == ap["id"]:
                        s = b.by_id.get(r["source_ref"], {})
                        p(f"   detects <- {s.get('type')} {ext_id(s)} {s.get('name')} "
                          f"(rel revoked={r.get('revoked', False)}, src revoked={s.get('revoked', False)}, "
                          f"src deprecated={s.get('x_mitre_deprecated', False)})")
                continue
            dets, ans, dcs, dropped = b.chain(ap)
            for d in dets:
                p(f"   DET {ext_id(d)} | {d['name']}")
                for aref in d.get("x_mitre_analytic_refs", []):
                    a = b.by_id.get(aref)
                    if a is None:
                        p(f"      AN FELOLDATLAN {aref}")
                        continue
                    plat = ",".join(a.get("x_mitre_platforms", []))
                    p(f"      AN {ext_id(a)} [{plat}]{'' if active(a) else ' (nem aktív)'}")
                    for ls in a.get("x_mitre_log_source_references", []):
                        dc = b.by_id.get(ls.get("x_mitre_data_component_ref"), {})
                        p(f"         DC {ext_id(dc)} {dc.get('name')} | name={ls.get('name')} | "
                          f"channel={ls.get('channel')} | network_dc_FELTETELEZES={is_network(dc.get('name'))}")
            if not dets:
                p("   (nincs aktív detektálási stratégia)")
            if dropped:
                p(f"   kiszűrt nem aktív kapcsolt objektum/reláció: {dropped}")


def network_list(label, b, out):
    p = lambda *a: print(*a, file=out)
    p(f"\n## 8. network_dc_FELTETELEZES – {label}")
    p(NETWORK_HEURISTIC_TEXT)
    dcs = sorted(b.of_type("x-mitre-data-component"), key=ext_id)
    yes = [d for d in dcs if is_network(d["name"]) == "IGEN"]
    p(f"IGEN-re besorolt adatkomponensek ({len(yes)} / {len(dcs)}):")
    for d in yes:
        flag = "" if active(d) else " (nem aktív)"
        p(f"   {ext_id(d)} | {d['name']}{flag}")
    p("NEM-re besorolt adatkomponensek:")
    for d in dcs:
        if is_network(d["name"]) == "NEM":
            p(f"   {ext_id(d)} | {d['name']}{'' if active(d) else ' (nem aktív)'}")


def diff(b19, b20, out):
    p = lambda *a: print(*a, file=out)
    p("\n################ v19.2 → v20.0 különbség (detektálási szerkezet) ################")
    for t in DETECTION_TYPES + ["attack-pattern", "relationship"]:
        k19 = set(k for o in b19.of_type(t) for k in o)
        k20 = set(k for o in b20.of_type(t) for k in o)
        p(f"{t}: db {len(b19.of_type(t))} → {len(b20.of_type(t))}; "
          f"új mezők: {sorted(k20 - k19) or '-'}; eltűnt mezők: {sorted(k19 - k20) or '-'}")
    for t in ["x-mitre-detection-strategy", "x-mitre-analytic", "x-mitre-data-component"]:
        i19 = {o["id"] for o in b19.of_type(t)}
        i20 = {o["id"] for o in b20.of_type(t)}
        p(f"{t}: csak v19.2-ben {len(i19 - i20)}, csak v20.0-ban {len(i20 - i19)}, közös {len(i19 & i20)}")
    me = collections.Counter(k for a in b20.of_type("x-mitre-analytic")
                             for m in a.get("x_mitre_mutable_elements", []) for k in m)
    p(f"v20.0 x-mitre-analytic.x_mitre_mutable_elements[] elemkulcsai: {dict(me) or '-'}")


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    p19, p20, outdir = sys.argv[1:]
    for path in (p19, p20):
        got = sha256(path)
        exp = EXPECTED_SHA256[os.path.basename(path)]
        if got != exp:
            sys.exit(f"HASH-ELTÉRÉS: {path} {got} != {exp}")
    b19, b20 = Bundle(p19), Bundle(p20)
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "attack_ics_structure.txt"), "w", encoding="utf-8") as out:
        print(f"Bemenet: {p19} sha256={EXPECTED_SHA256['ics-attack-19.2.json']}", file=out)
        print(f"Bemenet: {p20} sha256={EXPECTED_SHA256['ics-attack-20.0.json']}\n", file=out)
        report_version("ics-attack-19.2.json", b19, out)
        studied("v19.2", b19, STUDIED_IDS + EXTRA_V19, out)
        network_list("v19.2", b19, out)
        print(file=out)
        report_version("ics-attack-20.0.json", b20, out)
        studied("v20.0", b20, STUDIED_IDS, out)
        network_list("v20.0", b20, out)
        diff(b19, b20, out)
        n19 = write_csv(b19, os.path.join(outdir, "attack_ics_v19_2_detection_map.csv"))
        n20 = write_csv(b20, os.path.join(outdir, "attack_ics_v20_detection_map.csv"))
        print(f"\nCSV-sorok (aktív attack-pattern): v19.2={n19}, v20.0={n20}", file=out)


if __name__ == "__main__":
    main()
