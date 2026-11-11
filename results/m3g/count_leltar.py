"""M3-G(g): forrásleltár-számláló (csak stdlib).

Használat (a repó gyökeréből):
    python -I results/m3g/count_leltar.py docs/tdk/forras-leltar.md > results/m3g/count_leltar.txt

A fő táblázat sorai: "| <szám> | ..." alakú sorok az "## Összesítő" címsor előtt.
Oszlopok (12): # | szerző | év | cím | DOI/URL | típus | Hadmérnök | Informatics | bib-kulcs | helyi fájl | mit támaszt alá | átnézve.
"""
import re
import sys


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
    h = lambda c: c[6] != ""
    inf = lambda c: c[7] != ""
    bib = lambda c: c[8] != ""
    cnt = lambda f: sum(1 for c in recs if f(c))
    m = {
        "Összes egyedi mű": len(recs),
        "ebből lektorált": cnt(lambda c: c[5] == "lektorált"),
        "csak Hadmérnökben": cnt(lambda c: h(c) and not inf(c) and not bib(c)),
        "csak Informaticsban": cnt(lambda c: inf(c) and not h(c) and not bib(c)),
        "csak references.bib-ben": cnt(lambda c: bib(c) and not h(c) and not inf(c)),
        "mindháromban": cnt(lambda c: h(c) and inf(c) and bib(c)),
        "Informatics ∩ references.bib, Hadmérnök nélkül": cnt(lambda c: inf(c) and bib(c) and not h(c)),
        "Hadmérnök ∩ references.bib, Informatics nélkül": cnt(lambda c: h(c) and bib(c) and not inf(c)),
        "Hadmérnök ∩ Informatics, references.bib nélkül": cnt(lambda c: h(c) and inf(c) and not bib(c)),
        "egyik bemenetben sem (M3-F/M3-G elsődleges forrás)": cnt(lambda c: not h(c) and not inf(c) and not bib(c)),
        "Hadmérnök összesen": cnt(h),
        "Informatics összesen": cnt(inf),
        "references.bib összesen": cnt(bib),
        "átnézve = NEM": cnt(lambda c: c[11] == "NEM"),
    }
    for k, v in m.items():
        print(f"{k}: {v}")
    parts = ["csak Hadmérnökben", "csak Informaticsban", "csak references.bib-ben", "mindháromban",
             "Informatics ∩ references.bib, Hadmérnök nélkül", "Hadmérnök ∩ references.bib, Informatics nélkül",
             "Hadmérnök ∩ Informatics, references.bib nélkül", "egyik bemenetben sem (M3-F/M3-G elsődleges forrás)"]
    print("partíció: " + " + ".join(str(m[p]) for p in parts) + f" = {sum(m[p] for p in parts)} (összes: {m['Összes egyedi mű']})")


if __name__ == "__main__":
    main()
