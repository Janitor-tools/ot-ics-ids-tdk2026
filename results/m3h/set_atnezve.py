"""M3-H2: az „átnézve” oszlop beállítása a közös átnézés döntése alapján (2026-10-31; csak stdlib).

Használat (a repó gyökeréből):
    python -I results/m3h/set_atnezve.py docs/tdk/forras-leltar.md

Csak a fő táblázat ("## Összesítő" előtti "| <szám> | ..." sorok) 12. oszlopát írja át, a felsorolt ID-knál.
"""
import re
import sys

IGEN = "IGEN (2026-10-31)"
META = "IGEN – csak metaadat (2026-10-31)"
NEM103 = "NEM – nem releváns, a #103 kiváltja (2026-10-31)"
UJ = {i: IGEN for i in [43, 51, 70, *range(72, 95), *range(99, 107), 108, 109]}
UJ.update({i: META for i in [95, 96, 97, 98, 107, 110]})
UJ[71] = NEM103


def main():
    path = sys.argv[1]
    text = open(path, encoding="utf-8", newline="").read()
    lines = text.split("\n")
    end = next(i for i, l in enumerate(lines) if l.startswith("## Összesítő"))
    done = set()
    for i in range(end):
        m = re.match(r"^\| (\d+) \|", lines[i])
        if not m or int(m.group(1)) not in UJ:
            continue
        cells = lines[i].split("|")
        assert len(cells) == 14 and cells[0] == "" and cells[-1] == "", (i + 1, len(cells))
        cells[12] = f" {UJ[int(m.group(1))]} "
        lines[i] = "|".join(cells)
        done.add(int(m.group(1)))
    assert done == set(UJ), sorted(set(UJ) - done)
    open(path, "w", encoding="utf-8", newline="").write("\n".join(lines))
    print(f"módosított sorok: {len(done)}")


if __name__ == "__main__":
    main()
