"""M3-G(b): CTID Sensor Mappings to ATT&CK – szerkezet és ICS-lefedés (csak stdlib, hálózat nélkül).

Használat (a repó gyökeréből):
    python -I results/m3g/ctid_sensor_mappings_scan.py <klón-gyökér> results/m3g/ctid_sensor_mappings_scan.txt

A klón (<USER_HOME>/projects\\_ext\\ctid-sensor-mappings) a repón kívül van; ez a szkript csak olvassa.
"""
import collections
import csv
import json
import os
import re
import subprocess
import sys

ICS_TID_RE = re.compile(r"\bT(08\d\d|09\d\d|16\d\d|17\d\d)(\.\d{3})?\b")
ANY_TID_RE = re.compile(r"\bT\d{4}(\.\d{3})?\b")
GREP_RE = re.compile(r"modbus|s7comm|s7-comm|\bs7\b|ics-attack|\bics\b|suricata|wazuh", re.IGNORECASE)
TEXT_EXT = {".json", ".csv", ".md", ".rst", ".py", ".toml", ".txt", ".yaml", ".yml", ".cfg"}


def main():
    root, out_path = sys.argv[1:3]
    rev = subprocess.run(["git", "-C", root, "log", "-1", "--format=%H %cI"],
                         capture_output=True, text=True, check=True).stdout.strip()
    out = open(out_path, "w", encoding="utf-8")
    p = lambda *a: print(*a, file=out)
    p(f"klón: {root}")
    p(f"commit: {rev}")

    p("\n## STIX-leképezések (mappings/stix/*/*.json): objektumtípusok és mezők szenzoronként")
    stix_dir = os.path.join(root, "mappings", "stix")
    for dom in sorted(os.listdir(stix_dir)):
        for fn in sorted(os.listdir(os.path.join(stix_dir, dom))):
            with open(os.path.join(stix_dir, dom, fn), encoding="utf-8") as f:
                objs = json.load(f).get("objects", [])
            types = collections.Counter(o.get("type") for o in objs)
            sm = [o for o in objs if o.get("type") == "x-mitre-sensor-mapping"]
            dcs = collections.Counter(o.get("data_component") for o in sm)
            keys = sorted(set(k for o in sm for k in o))
            p(f"[{dom}] {fn}: {dict(types)}")
            p(f"    x-mitre-sensor-mapping mezők: {keys}")
            p(f"    adatkomponensek ({len(dcs)}): {dict(sorted(dcs.items(), key=str))}")

    p("\n## CSV-bemenetek (mappings/input/*/csv/*.csv): sorok és adatkomponensek szenzoronként")
    in_dir = os.path.join(root, "mappings", "input")
    for dom in sorted(d for d in os.listdir(in_dir) if os.path.isdir(os.path.join(in_dir, d))):
        csv_dir = os.path.join(in_dir, dom, "csv")
        for fn in sorted(os.listdir(csv_dir)):
            with open(os.path.join(csv_dir, fn), encoding="utf-8-sig", newline="") as f:
                rows = list(csv.DictReader(f))
            dcs = collections.Counter(r.get("ATT&CK DATA COMPONENT") for r in rows)
            p(f"[{dom}] {fn}: {len(rows)} sor, {len(dcs)} adatkomponens")

    p("\n## Technika-ID-k a teljes klónban (.git nélkül, szöveges fájlok)")
    any_ids, ics_hits, grep_hits = collections.Counter(), [], []
    for dp, dn, fns in os.walk(root):
        dn[:] = [d for d in dn if d != ".git"]
        for fn in fns:
            if os.path.splitext(fn)[1].lower() not in TEXT_EXT:
                continue
            path = os.path.join(dp, fn)
            rel = os.path.relpath(path, root).replace("\\", "/")
            with open(path, encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f, 1):
                    for m in ANY_TID_RE.finditer(line):
                        any_ids[rel] += 1
                    for m in ICS_TID_RE.finditer(line):
                        ics_hits.append(f"{rel}:{i}: {m.group(0)}")
                    if GREP_RE.search(line):
                        grep_hits.append(f"{rel}:{i}: {line.strip()[:200]}")
    p(f"bármely T####-minta fájlonként: {dict(sorted(any_ids.items()))}")
    p(f"T08xx/T09xx/T16xx/T17xx találat: {len(ics_hits)}")
    for h in ics_hits:
        p("   " + h)
    p(f"\n## grep (kis/nagybetű-érzéketlen): modbus | s7comm | s7-comm | \\bs7\\b | ics-attack | \\bics\\b | suricata | wazuh – {len(grep_hits)} találat")
    for h in grep_hits:
        p("   " + h)
    out.close()


if __name__ == "__main__":
    main()
