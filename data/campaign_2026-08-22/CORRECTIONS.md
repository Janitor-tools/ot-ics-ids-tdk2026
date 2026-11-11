# Javítási napló – kampány 2026-08-22

## Fájlok

| Fájl | Szerep | sha256 (LF-es tartalom = git blob) |
|---|---|---|
| `attack_log.original.jsonl` | **Eredeti** nyers adat, ahogy az `attack_runner.py` (`fe59748`) a Red-Team-VM-en megírta. Megegyezik a `8684bd8` commitbeli `attack_log.jsonl`-lel és a Red-Team-VM `/home/ot/attack_log.jsonl` példányával. | `9f0543de4340a8d4b0bf8b679f1bea88a07636df1986505fd0a6a80265c0600f` |
| `attack_log.jsonl` | **Javított** változat (technika-ID-csere). Ezt olvassa a `scripts/evaluate_campaign.py`. | `72fef663eb493ef4b72402f25df585afa49aa6e08994e75cfa0e3112db7fbcd6` |
| `benign_log.jsonl` | Eredeti, nem javított. Megegyezik a Red-Team-VM `/home/ot/benign_log.jsonl` példányával (`2a4e9a7`). | `c07c78d81c884e953d2b738d01d15d7175879098b2d8637b6f9dd8dd0bb15902` |

Megjegyzés: a repóban `core.autocrlf=true` van, ezért Windows-os munkapéldányban a fájl CRLF-es is lehet. A fenti hash-ek az LF-es tartalomra vonatkoznak (`git show <commit>:<fájl> | sha256sum`).

## A javítás

- Commit: `482f560` (2026-08-25), „Sprint 2 (2.4/0.1): T0846/T0888 technika-ID-csere vegrehajtva”.
- Indoklás (MITRE ATT&CK for ICS definíciók):
  - **A.2** – egyetlen ismert eszköz regisztereinek enumerációja (gyors, több funkciókódos olvasási sorozat egy kapcsolaton belül) = **T0888** (Remote System Information Discovery), nem T0846.
  - **A.3** – a /24 OT-alhálózat TCP connect-sweepje az 502-es és 102-es portra = **T0846** (Remote System Discovery), nem T0888.
- Érintett sorok: 23 (20 db `A2_*`, 3 db `A3_*` epizód). Más mező nem változott.

## Mechanikus transzformáció (eredeti → javított)

```bash
SED='s/A2_T0846_/A2_TXXXX_/g; s/A3_T0888_/A3_TYYYY_/g; /"A2_TXXXX_/s/"mitre_technique_id": "T0846"/"mitre_technique_id": "T0888"/; /"A3_TYYYY_/s/"mitre_technique_id": "T0888"/"mitre_technique_id": "T0846"/; s/A2_TXXXX_/A2_T0888_/g; s/A3_TYYYY_/A3_T0846_/g'
sed -e "$SED" attack_log.original.jsonl | sha256sum
```

Igazolás (újrafuttatva 2026-10-29-én):

```
original:              9f0543de4340a8d4b0bf8b679f1bea88a07636df1986505fd0a6a80265c0600f
sed(original):         72fef663eb493ef4b72402f25df585afa49aa6e08994e75cfa0e3112db7fbcd6
HEAD:attack_log.jsonl: 72fef663eb493ef4b72402f25df585afa49aa6e08994e75cfa0e3112db7fbcd6
```

A transzformáció bájtra az `attack_log.jsonl`-t adja, tehát a javítás kizárólag a címkecsere.

## Szabály

**Új kampányok nyers adata megváltoztathatatlan; javítás csak külön leképezési fájlban.**
Ezt a kampányt (2026-08-22) a fenti módon kezeljük: az eredeti visszaállítva (`attack_log.original.jsonl`), a javított fájl és a kiértékelő változatlan. Lásd `docs/tdk/ELTERESNAPLO.md` E-05.
