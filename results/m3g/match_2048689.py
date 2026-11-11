"""M3-G(f): a SID 2048689 content-mintáinak gépi keresése a python-snap7 3.1.2 kérésbájtjaiban (csak stdlib).

Használat (a repó gyökeréből):
    python -I results/m3g/match_2048689.py results/m3g/sensor_suricata_homenet.txt results/m3g/snap7_request_bytes.txt

Bemenet:
  - a szabály teljes sora az (e2) szakaszból (sensor `suricata.rules`:57356);
  - a redteamen kapcsolat nélkül épített S7-PDU-k hexben (`snap7_request_bytes.txt`).
A TPKT/COTP-csomagolás a `python-snap7-3.1.2-connection.py` alapján készül:
  _build_cotp_dt :393–404 → 02 F0 80 + data; _build_tpkt :277–287 → 03 00 <len16> + payload; send_data :177–181.
Csak a bájtminták előfordulását és offsetjét vizsgálja; a Suricata buffer- és flow-szemantikáját nem modellezi.
"""
import re
import struct
import sys

COTP_DT = 0xF0


def rule_line(path):
    lines = [l for l in open(path, encoding="utf-8") if "sid:2048689;" in l and l.split(":", 1)[0].isdigit()]
    if not lines:
        sys.exit("a 2048689-es teljes szabálysor nem található")
    return lines[-1].strip()


def contents(rule):
    """(minta bájtjai, a content utáni módosítók) listája, a szabály sorrendjében."""
    out = []
    parts = re.split(r'(content:"[^"]*";)', rule)
    for i, p in enumerate(parts):
        m = re.fullmatch(r'content:"([^"]*)";', p)
        if not m:
            continue
        hexpart = re.fullmatch(r"\|([0-9A-Fa-f ]+)\|", m.group(1))
        if not hexpart:
            sys.exit(f"nem tisztán hex content: {m.group(1)}")
        mods = parts[i + 1].split("content:")[0].strip() if i + 1 < len(parts) else ""
        out.append((bytes.fromhex(hexpart.group(1).replace(" ", "")), mods))
    return out


def wrap(pdu):
    cotp = struct.pack(">BBB", 2, COTP_DT, 0x80) + pdu
    return struct.pack(">BBH", 3, 0, len(cotp) + 4) + cotp


def find_all(hay, needle):
    res, i = [], hay.find(needle)
    while i != -1:
        res.append(i)
        i = hay.find(needle, i + 1)
    return res


def common_prefix(a, b):
    n = 0
    while n < min(len(a), len(b)) and a[n] == b[n]:
        n += 1
    return n


def main():
    rule = rule_line(sys.argv[1])
    pdus = {}
    for l in open(sys.argv[2], encoding="utf-8"):
        m = re.fullmatch(r"(cpu_state|read_szl_0x0424_0) ([0-9a-f]+)\s*", l)
        if m:
            pdus[m.group(1)] = bytes.fromhex(m.group(2))
    print(f"szabály ({sys.argv[1]}): {rule}")
    cs = contents(rule)
    for k, (c, mods) in enumerate(cs, 1):
        print(f"content#{k}: {c.hex(' ')} | módosítók: {mods}")
    for name, pdu in pdus.items():
        for label, buf in (("S7-PDU (build_*)", pdu), ("TPKT+COTP+PDU (send_data szerint)", wrap(pdu))):
            print(f"\n[{name}] {label}: {buf.hex(' ')} ({len(buf)} bájt)")
            print(f"   első bájt: {buf[0]:02x}; TPKT-fejléccel kezdődik (03 00): {buf[:2] == bytes([3, 0])}")
            for k, (c, mods) in enumerate(cs, 1):
                offs = find_all(buf, c)
                print(f"   content#{k} előfordulás offsetjei: {offs if offs else 'NINCS'}"
                      f"; a 0. offseten egyező előtag: {common_prefix(buf, c)}/{len(c)} bájt")
            if len(cs) >= 2:
                c1, c2 = cs[0][0], cs[1][0]
                o1 = find_all(buf, c1)
                o2 = find_all(buf, c2)
                ok = [(a, b) for a in o1 for b in o2 if 0 <= b - (a + len(c1)) and b + len(c2) - (a + len(c1)) <= 16]
                print(f"   content#1@0 (startswith): {0 in o1}; content#2 within:16 a content#1 után: {ok if ok else 'NINCS'}")
            # a content#1 minta melletti eltérő pozíciók a PDU elején (bájtonként)
            c1 = cs[0][0]
            diff = [(i, f"{buf[i]:02x}", f"{c1[i]:02x}") for i in range(min(len(buf), len(c1))) if buf[i] != c1[i]]
            print(f"   content#1 vs. buf[0:{len(c1)}] eltérő bájtok (offset, buf, minta): {diff}")


if __name__ == "__main__":
    main()
