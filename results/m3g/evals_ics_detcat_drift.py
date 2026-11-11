"""M3-G(c2): Wayback-drift – a TRITON Detection Categories szakasz összevetése snapshotok között (csak stdlib).

Használat (a repó gyökeréből):
    python -I results/m3g/evals_ics_detcat_drift.py <alap.txt> <összevetendő.txt> [...] > results/m3g/evals_ics_detcat_drift.txt

A szakasz: a "The evaluation focuses on articulating" kezdetű sortól a "Terms and Conditions" sor előttiig
(az alapfájlban :42–159). A .txt-k a forrasok/ alatti szövegkivonatok.
Kétféle összevetés: (1) soronként (difflib.unified_diff), (2) szóközre normalizált, összefűzött szöveg.
"""
import difflib
import os
import re
import sys

START = "The evaluation focuses on articulating"
END = "Terms and Conditions"


def section(path):
    lines = open(path, encoding="utf-8").read().splitlines()
    s = next(i for i, l in enumerate(lines) if l.startswith(START))
    e = next(i for i, l in enumerate(lines) if i > s and l.startswith(END))
    return s + 1, e, lines[s:e]


def main():
    base, others = sys.argv[1], sys.argv[2:]
    bs, be, bl = section(base)
    print(f"alap: {os.path.basename(base)} :{bs}–{be}")
    for o in others:
        s, e, ol = section(o)
        print(f"\n== {os.path.basename(o)} :{s}–{e}")
        d = list(difflib.unified_diff(bl, ol, os.path.basename(base), os.path.basename(o), lineterm="", n=0))
        norm = lambda ls: re.sub(r"\s+", " ", " ".join(ls)).strip()
        same_norm = norm(bl) == norm(ol)
        print(f"soronként: {'AZONOS' if not d else 'ELTÉR'}; szóközre normalizálva: {'AZONOS' if same_norm else 'ELTÉR'}")
        for l in d:
            print(l)
        if not same_norm:
            nd = difflib.ndiff(norm(bl).split(" "), norm(ol).split(" "))
            print("szószintű eltérések (ndiff, csak a +/- sorok):")
            for l in nd:
                if l[:1] in "+-":
                    print("   " + l)


if __name__ == "__main__":
    main()
