# Nyílt forráskódú ICS/OT behatolásdetektálási keretrendszer Modbus TCP és S7comm protokollokhoz, MITRE ATT&CK for ICS leképezéssel

**Szerző:** Szabados József  
**Intézmény:** Óbudai Egyetem, Neumann János Informatikai Kar (NIK)  
**Esemény:** 64. Tudományos Diákköri Konferencia (TDK), 2026  
**Konzulens:** Vörösné Dr. Bánáti-Baumann Anna

---

## English Summary

This repository contains the reproducibility materials for a BSc/MSc thesis (TDK 2026) that builds an open-source ICS/OT intrusion detection framework for Modbus TCP and S7comm protocols, with systematic MITRE ATT&CK for ICS mapping. It includes the 97-technique detectability classification (42 observable / 21 dataset-verifiable / 34 non-network-observable), attack and benign traffic generators, evaluation scripts, campaign manifests and results, and preregistered validation protocols.

---

## Mappastruktúra

| Mappa / fájl | Tartalom | Dolgozat hivatkozás |
|---|---|---|
| `chapters/data/mitre_ics_techniques_v19.2.csv` | A 97 ICS ATT&CK technika hálózati detektálhatósági besorolása (42 A / 21 K / 34 C) | 2.3.2. alfejezet, A. melléklet |
| `chapters/data/mitre-verifikacio-2026-08-30.txt` | MITRE-verifikációs napló | 6. fejezet |
| `scripts/attack_runner.py` | Támadásgenerátor (Modbus TCP + S7comm epizódok) | 5.4. alfejezet |
| `scripts/benign_generator.py` | Benign háttérforgalom-generátor | 5.4. alfejezet |
| `scripts/evaluate_v.py` | Kiértékelő: epizód–rekord párosítás, LÁTTA/NEM LÁTTA besorolás | 3. fejezet (módszertan), 6. fejezet |
| `scripts/evaluate_campaign.py` | Kampányszintű kiértékelő | 6. fejezet |
| `scripts/aggregate_v.py` | Többkampányos összesítő (Bayes, konfidencia-intervallumok) | 6. fejezet |
| `scripts/run_campaign.sh` | Kampányvezénylő (indítás, begyűjtés, manifest) | 5.4. alfejezet |
| `scripts/lab_up.sh` | Labor-indító szkript | 5.2. alfejezet |
| `scripts/deploy_red_team_scripts.sh` | Red Team szkriptek telepítése a VM-ekre | 5.4. alfejezet |
| `scripts/sprint1_es_metrics.py` | Sprint 1 Elasticsearch-metrikák | 6.A fejezet |
| `scripts/tdk2026_ci_fix.py` | CI-javító segédszkript | — |
| `tests/` | Egységtesztek (`test_evaluate_v.py`, `test_aggregate_v.py`) | — |
| `data/campaign_2026-08-22/` | Fejlesztési kampány (C0) naplói | 6.A fejezet |
| `data/campaign_2026103*_V1_s1/` | Füstteszt kampány | 5.5. alfejezet |
| `data/campaign_20261101*_V1_s*/` | Validációs kampányok V1 s1–s3 | 6.B fejezet |
| `data/campaign_20261101T174612Z_V2_s1/` | Validációs kampány V2 s1 | 6.B fejezet |
| `results/m5/` | Összesített eredmények (JSON + Markdown) | 6.B fejezet |
| `results/m3g/` | MITRE-struktúra elemzés, detekciós kategória drift, Zeek/Suricata verifikáció | 3. és 6. fejezet |
| `results/m3h/` | Leltár-számlálás | 3. fejezet |
| `results/m4b/` | Hatásjelkalibráció | 5.5. alfejezet |
| `results/m4c/` | Füstteszt eredmények | 5.5. alfejezet |
| `results/lab-health-2026-10-29.txt` | Laborállapot-felmérés | 5.2. alfejezet |
| `results/lab-baseline-2026-10-29.sha256` | Komponens-hash baseline | 5.2. alfejezet |
| `results/campaign_2026-08-22_*.json` | Fejlesztési kampány metrikák | 6.A fejezet |
| `docs/tdk/VALIDACIOS-PROTOKOLL.md` | Validációs protokoll (aktuális) | 3. fejezet |
| `docs/tdk/VALIDACIOS-PROTOKOLL-prereg-v1.md` | Validációs protokoll (prereg-v1, mérés előtt rögzítve) | 3. fejezet |
| `docs/tdk/VALIDACIOS-PROTOKOLL-prereg-v1.1.md` | Validációs protokoll (prereg-v1.1, kétágú hatásjel) | 3. fejezet |
| `docs/tdk/DONTESEK.md` | Módszertani döntésnapló (aktuális) | 3. fejezet |
| `docs/tdk/DONTESEK-prereg-v1.md` | Döntésnapló (prereg-v1) | 3. fejezet |
| `docs/tdk/DONTESEK-prereg-v1.1.md` | Döntésnapló (prereg-v1.1) | 3. fejezet |
| `docs/tdk/ELTERESNAPLO.md` | Eltérésnapló (E-01–E-38) | 5.7. alfejezet, 7. fejezet |
| `docs/tdk/ELTERESNAPLO-prereg-v1.1.md` | Eltérésnapló (prereg-v1.1 állapot) | — |

## Rögzített komponensverziók

| Komponens | Verzió |
|---|---|
| Ubuntu Server | 22.04.5 LTS |
| Elasticsearch / Kibana | 8.19.19 |
| Wazuh Manager | 4.14.7 |
| Zeek | 8.0.9 |
| icsnpp-modbus | v2.0.0 (`16428919`) |
| icsnpp-s7comm | `a2f93024` |
| Suricata | 8.0.6 |
| Filebeat | 8.19.19 |
| OpenPLC_v3 | `b5d41356` |
| python-snap7 | 3.1.2 |
| pymodbus | 3.14.0 |
| ATT&CK for ICS | v20.0 (attack-stix-data `c2494b29`) |

## A kísérleti környezet reprodukálhatósági korlátai

A kísérleti környezet **kézzel épült** (lásd dolgozat 5.7.1. alfejezet): nincs egylépéses telepítőszkript. A `scripts/lab_up.sh` a már felépített, négy VM-ből álló laborkörnyezetet indítja és ellenőrzi, de nem hozza létre azt a semmiből. A komponensek telepítési lépéseinek részletes, de kézi dokumentációja a dolgozat B. mellékletében található.

A pcap-fájlok (<2 MB/kampány) a repóban megtalálhatók. Nagyméretű pcap-fájlok kérésre elérhetők.

## Előregisztrált validációs protokoll

A mérés előtt rögzített validációs protokoll két verziója:

- **prereg-v1** (2026-10-31, `d4517ec`): `docs/tdk/VALIDACIOS-PROTOKOLL-prereg-v1.md`
- **prereg-v1.1** (2026-10-31, `7bbdd52`): `docs/tdk/VALIDACIOS-PROTOKOLL-prereg-v1.1.md` — kétágú hatásjel a kalibráció alapján (E-24)

Az eltérésnapló (`docs/tdk/ELTERESNAPLO.md`) dokumentálja a protokolltól való minden eltérést (E-01–E-38).

## Licenc

- **Kód** (scripts/, tests/): [MIT License](LICENSE-CODE)
- **Adat és dokumentáció** (data/, results/, chapters/data/, docs/): [CC BY 4.0](LICENSE-DATA)

## Hivatkozás

```bibtex
@misc{szabados2026icsids,
    author  = {Szabados, József},
    title   = {Nyílt forráskódú ICS/OT behatolásdetektálási keretrendszer
               Modbus TCP és S7comm protokollokhoz,
               MITRE ATT\&CK for ICS leképezéssel},
    year    = {2026},
    note    = {64.\ Tudományos Diákköri Konferencia, Óbudai Egyetem NIK},
    url     = {https://github.com/Janitor-tools/ot-ics-ids-tdk2026}
}
```
