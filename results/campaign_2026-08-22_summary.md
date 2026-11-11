# Milestone 6 -- Kiertekelesi osszefoglalo (2026-08-22-i kampany)

**Tenyleges kampanyablak:** 2026-08-22T13:48:33.811050+00:00 -- 2026-08-22T16:47:28.943719+00:00 (~178.9 perc, tervezett: 240 perc)

> A tenyleges kampanyidotartam a benign_generator.py meta-naploja alapjan ~179 perc, nem a tervezett 240 -- lasd Ch.6 'Modszertani eltmresek'. Forensics: journalctl session-31 lezarasa 16:47:28-kor, human-initiated SIGTERM, nem OOM/crash.

## Technikankenti konfuzios matrix es F1

| Technika | N | TP | FN | Recall | Recall 95% CI | Precision (finomitott/nyers) | F1 |
|---|---|---|---|---|---|---|---|
| T0836 | 17 | 17 | 0 | 1.00 | (1.0, 1.0) | 1.0 | 1.0 |
| T0816 | 23 | 20 | 3 | 0.87 | (1.0, 1.0) (csak A.4) | 1.0 | 0.9302325581395349 |
| T0888 | 20 | 0 | 20 | 0.00 | (0.0, 0.0) | N/A (nincs szabaly) | N/A |
| T0846 | 3 | 0 | 3 | 0.00 | N/A (N=3<10) | N/A (nincs szabaly) | N/A |
| T0843 | 3 | 0 | 3 | 0.00 | N/A (N=3<10) | N/A (nincs szabaly) | N/A |

> **T0846/T0888 ID-csere (2026-08-25, 2.4/0.1 tetel):** a fenti ket sor technika-ID-je korabban forditva allt a hivatalos MITRE-definiciohoz kepest -- javitva, lasd `metrics.json` `id_correction_note` mezoi. Csak a cimke valtozott, a mert ertekek (N, TP, FN) nem.

> **Megjegyzes a degeneralt (0 szelessegu) CI-kre:** T0836 es T0816/A.4 minden resample-elt epizodon 100%-os recallt ad, mert a valodi minta maga is 100%-os (17/17, ill. 20/20) -- a percentilis bootstrap ilyenkor sose mintavetelez FN-t, tehat az intervallum matematikailag korrekt modon nulla szelessegu. Ez a percentilis bootstrap ismert korlatja tokeletes pontbecsles + kis N eseten, NEM szoftverhiba -- a 6. fejezetben explicit jelolendo.

## Osszesitett mutatok

- **Makro-recall (pontbecsles, mind az 5 technikaval, a vakfoltokat is bele­ertve):** 0.374
- **Makro-recall 95% CI (MAS mennyiseg -- lasd lent):** (0.6231884057971014, 0.6231884057971014)

> **KRITIKUS, a Milestone5-Terv.md E) szakasza altal explicit eloirt labjegyzet:** a fenti ket szam **nem ugyanarra a mennyisegre** vonatkozik. A pontbecsles (0.374) mind az ot technikat tartalmazza, a garantalt vakfoltokkal egyutt (T0846, T0843, es T0816 A.5-resze -- mindegyik 0 recall-lal, szandekosan lehuzva az atlagot, RQ3-demonstraciokent). A CI-sav ezzel szemben KIZAROLAG a harom, teljes statisztikai kezelesu technikara (T0836, T0888, T0816-A.4-resz) szamolt, retegzett makro-recall bizonytalansagat fejezi ki -- a vakfoltok (N=3, CI-kuszob alatt) nincsenek benne a resampling-ben. A ket szamot EGYMAS MELLETT, DE KULON ertelmezve kell kozolni a dolgozatban.

- **Makro-F1** (technikankent, csak aktiv-szabalyu technikak -- T0836 vegso/finomitott, T0816): 0.965 [javitva 2026-08-25, korabban tevesen 0.846 -- lasd metrics.json macro_f1 megjegyzese]
- **Mikro-F1** (finomitott szabalyvariansal, MINDEN technika FN-je bennevan, a szabaly-nelkuliek 0 TP/0 FP mellett is): 0.718 (TP=37, FP=0, FN=29)

## Kepletek (attekinthetoseg, 6. fejezethez)

```
Recall_tech      = TP_tech / (TP_tech + FN_tech)                  [epizod-szintu]
Precision_tech   = TP_tech / (TP_tech + FP_tech)                  [FP: teljes kampanyablak
                                                                   minus epizod-ablakok]
F1_tech          = 2 * Precision_tech * Recall_tech / (Precision_tech + Recall_tech)
Makro-Recall     = mean(Recall_tech for tech in {T0836,T0846,T0816,T0888,T0843})
Makro-F1         = mean(F1_tech for tech in {T0836,T0816})  [csak aktiv szabaly, T0836 = vegso/finomitott]
Mikro-F1         = 2*TP_pooled*... / (pooled TP+FP+FN, technikahatarok nelkul)
Bootstrap CI     = percentilis, B=10000, seed=42; retegzett a makro-recall-hoz,
                   blokk (5 perces bin) a FP/precision/F1-hez
```