"""M3-H2: forrásleltár-ellenőrzés az „átnézve”-jelölés után (csak stdlib; a results/m3g/count_leltar.py alapján).

Használat (a repó gyökeréből):
    python -I results/m3h/count_leltar.py docs/tdk/forras-leltar.md > results/m3h/count_leltar.txt

A fő táblázat sorai: "| <szám> | ..." alakú sorok az "## Összesítő" címsor előtt.
Oszlopok (12): # | szerző | év | cím | DOI/URL | típus | Hadmérnök | Informatics | bib-kulcs | helyi fájl | mit támaszt alá | átnézve.
"""
import re
import sys
from collections import Counter


def tartomanyok(ids):
    ids, out = sorted(ids), []
    for i in ids:
        if out and i == out[-1][1] + 1:
            out[-1][1] = i
        else:
            out.append([i, i])
    return ", ".join(str(a) if a == b else f"{a}–{b}" for a, b in out)


def main():
    lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
    end = next(i for i, l in enumerate(lines) if l.startswith("## Összesítő"))
    rows = [(i + 1, l) for i, l in enumerate(lines[:end]) if re.match(r"^\| \d+ \|", l)]
    bad, recs = [], []
    for ln, l in rows:
        cells = [c.strip() for c in l.split("|")[1:-1]]
        if len(cells) != 12:
            bad.append((ln, len(cells)))
            continue
        recs.append(cells)
    ids = [int(c[0]) for c in recs]
    print(f"táblázatsorok: {len(rows)}; 12 oszlopos: {len(recs)}; nem 12 oszlopos: {bad if bad else 'nincs'}")
    print(f"sorszámok: {min(ids)}–{max(ids)}; hiányzó: {sorted(set(range(min(ids), max(ids) + 1)) - set(ids)) or 'nincs'}; "
          f"ismétlődő: {sorted({i for i in ids if ids.count(i) > 1}) or 'nincs'}")
    print("átnézve – darabszám kategóriánként:")
    by = {}
    for c in recs:
        by.setdefault(c[11], []).append(int(c[0]))
    cnt = Counter({k: len(v) for k, v in by.items()})
    for k, n in cnt.most_common():
        print(f"  {k}: {n} (ID: {tartomanyok(by[k])})")
    print(f"összesen: {sum(cnt.values())}")


if __name__ == "__main__":
    main()
