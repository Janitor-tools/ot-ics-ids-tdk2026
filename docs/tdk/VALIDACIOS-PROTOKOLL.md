# Validációs protokoll (prereg-v1, 2026-10-31)

- A protokollt a mérés előtt rögzítjük; a git-tag `prereg-v1`.
- A döntések indoklása: `docs/tdk/DONTESEK.md` (D0–D13).
- Hivatkozás: fájl:sor vagy FORRAS-ID (`docs/tdk/forras-leltar.md`).
- A korábbi NYITOTT pontok (NYK-1–10) 2026-10-31-én lezárva (`DONTESEK.md`, lista a fájl végén); a protokoll ezeket a döntéseket tartalmazza.

## 1. Cél

- **Megfigyelhetőség vs. detektálhatóság:**
  - megfigyelhető, ha a procedúráról rekord keletkezik;
  - detektált, ha riasztás is keletkezik.
  - A kettőt külön mérjük (D0).
- **Állított vs. mért képesség:**
  - az állított képesség az elvárt detektálás az ATT&CK for ICS v20.0 szerint (`results/m3g/attack_ics_v20_detection_map.csv`; D1, D13);
  - a mért képesség a kampányokban kapott evidencia (D0, D5).
- **LÁTTA-definíció (D0):**
  - LÁTTA = az epizód ablakában létezik a procedúrát azonosító rekord (ES-ben; a C1-ben a Sensor nyers naplóiban is) vagy riasztás;
  - NEM LÁTTA = nincs ilyen;
  - másodlagos, ordinális tengely: None < Telemetry < General < Tactic < Technique (#103); LÁTTA ⇔ ≥ Telemetry.

## 2. Rögzített környezet

- Állapotfelmérés: `results/lab-health-2026-10-29.txt`.
- Hash-baseline: `results/lab-baseline-2026-10-29.sha256`.
- Verziók (`results/lab-health-2026-10-29.txt`; `docs/tdk/forras-horgonyok.md`:8–13):
  - Zeek 8.0.9, Suricata 8.0.6;
  - Elasticsearch / Kibana 8.19.19, Wazuh 4.14.7;
  - icsnpp-modbus v2.0.0 (`16428919`), icsnpp-s7comm `a2f93024` (E-17);
  - OpenPLC_v3 `b5d41356`;
  - python-snap7 3.1.2, pymodbus 3.14.0.
- ATT&CK for ICS v20.0 (#73, attack-stix-data `c2494b29`). A 97/42-es osztályozás v19.2 (#74), delta: `results/m3g/attack_ics_structure.txt`:781–793 (D1).
- Az eltérésnaplóban rögzített állapotok:
  - E-06: az automatikus frissítés tiltva;
  - E-07: kernel 5.15.0-190;
  - E-09: a SIEM a belső időreferencia;
  - E-17: az icsnpp-s7comm rögzített hash-sel.
- A kampányokhoz használt szkriptek commit-hash-ét és sha256-ját kampányonként a manifest rögzíti (D6).

## 3. Szcenáriótábla

Forrás-IP:
- .50 = 192.168.1.50, támadói identitás, nem allowlistelt (`scripts/attack_runner.py`:85);
- .51 = 192.168.1.51, allowlistelt (`scripts/benign_generator.py`:44).

Cél minden szcenárióban: PLC, 192.168.1.100 (`scripts/attack_runner.py`:86).

A „várt evidencia” azt mondja meg, hol keletkezhet a procedúrát azonosító rekord. Nem előrejelzés, kivéve az A.5-öt (D2).

### 3.1 V1 (D3): K = 3, seed 1/2/3

| Szcenárió | Technika (v20) | Eszköz | Forrás-IP | N / kampány | Várt evidencia |
|---|---|---|---|---|---|
| A.1 | T0836 Modify Parameter | pymodbus: FC03, majd FC06 (`scripts/attack_runner.py`:206–218) | .50 | 20 | ES: `zeek.icsnpp_modbus` / `modbus_detailed` (#78) |
| A.2 | T0888 Remote System Information Discovery | pymodbus: FC03, FC01, FC02, FC04 (`scripts/attack_runner.py`:221–238) | .50 | 20 | ES: `zeek.icsnpp_modbus` |
| A.3 | T0846.001 Port Scan | TCP `connect_ex`, 192.168.1.1–254, 502/102 (`scripts/attack_runner.py`:241–255) | .50 | 3 | C1: `conn.log` (Sensor nyers, D5b); C1: SID 2009286 (#51) |
| A.4 | T0816 Device Restart/Shutdown | python-snap7 `plc_stop()` (`scripts/attack_runner.py`:325–339) + hatásigazolás (D2) | .50 | 20 | ES: `zeek.icsnpp_s7comm` „PLC Stop” (#82) |
| A.5 | T0816 (másodlagos: T1694 Insecure Credentials) | HTTP `/login`, majd `/stop_plc` (#90:601–668) + hatásigazolás (D2) | .50 | 3 | C1: `http.log` (Sensor nyers, D5b). Előrejelzés: a SIEM-ben nem látszik (D2) |
| A.6 | T0843 Program Download | python-snap7 `download()` (`scripts/attack_runner.py`:342–353) | .50 | 3 | ES: `zeek.icsnpp_s7comm` Download-funkciók (#82); C1: `s7comm_upload_download` (#80) |

### 3.2 V2 (D4): N = 20 szcenáriónként

| Szcenárió | Technika (v20) | Eszköz | Forrás-IP | N | Várt evidencia |
|---|---|---|---|---|---|
| V2.1 | T0836 Modify Parameter (kompromittált mérnöki állomás) | pymodbus FC03 + FC06 | .51 | 20 | ES: `zeek.icsnpp_modbus` / `modbus_detailed` |
| V2.2 | T0893 Data from Local System | python-snap7 `db_read(1002, 0, 2)`, %MW0 (#91:762–766, #93) | .50 | 20 | ES: `zeek.icsnpp_s7comm` „Read Variable” (#82; cím nélkül: #80:112–138) |
| V2.3 | T0821 Modify Controller Tasking | python-snap7 `db_write(1002, 0, …)`, írt érték 4242 (#91:762–766, #93) | .50 | 20 | ES: `zeek.icsnpp_s7comm` „Write Variable” (#82; cím nélkül: #80:112–138) |
| V2.4 | T0836 – kitérés: FC16 FC06 helyett | pymodbus FC03 + FC16 (#79) | .50 | 20 | ES: `zeek.icsnpp_modbus` / `modbus_detailed` |
| V2.5 | T0836 – kitérés: 15 s a FC03 és az írás között (> 10 s `maxspan`) | pymodbus FC03 + FC06 (#87) | .50 | 20 | ES: `zeek.icsnpp_modbus` / `modbus_detailed` |

Epizódközi szünet a V2-ben: 30 ± 10 s, a seed alapján determinisztikusan (mint az A.1-ben; `scripts/attack_runner.py` `_jitter_pause`). A V2.5 belső 15 s-os várakozása a FC03 és az írás között ezen felül van.

## 4. Végrehajtás

1. **Seed:** a V1 kampányai 1, 2, 3. Az `attack_runner.py` jelenleg nem állít seedet (`docs/tdk/2026-11-atirasi-terv.md`:43). A seedet a szkript a mérés előtt kapja meg, és a manifest rögzíti.
2. **Kezdőállapot (D9):** a regiszter 1009-re állítása a .51-ről, a mérési ablakon kívül. Az időpontot a manifest rögzíti, az ablak kizárt (5.5).
3. **Hatásigazolás (D2), az A.4-nél és az A.5-nél, kétágú jel (prereg-v1.1, kalibrálva — E-24):**
   - mérőcsatorna: a 102-es TCP-porton figyelő folyamat (`ss -tlnp`) a PLC menedzsment-IP-jén (192.168.56.20) SSH-n (E-23); annak `/proc/<pid>/stat` `utime+stime` (#111) és szálanként `/proc/<pid>/task/*/stat` — nyers diagnosztika;
   - ablak: 20 s (konfigurálható, `OT_EFFECT_WINDOW_S`);
   - **1. ág (`listener_gone`):** ha a stop előtt figyel folyamat a 102-n (pid0), és a stop után (2 s várakozás, majd 3 ellenőrzés 2 s-onként) a 102-n **nincs** figyelő → `executed_effect`;
   - **2. ág (`scan_stopped` / `scan_running`):** ha a stop után van figyelő, a figyelő folyamat tick-deltája az utána-ablakban (20 s): ≤ 2 tick → `executed_effect` (`scan_stopped`); > 2 tick → `executed_no_effect` (`scan_running`). T = 2 = floor((R_min=5 + S_max=0)/2) — **[SAJÁT MÉRNÖKI DÖNTÉS]**, az A.4 füstteszt validálja; ha az élő-de-leállított delta > 2, prereg-v1.2;
   - **3. ág:** ha a stop előtt nincs figyelő, vagy a mérés hibázik → `executed_no_measurement`;
   - a `get_cpu_state()` nem használható (E-22). A rekordmező: `effect_branch`.
4. **Pozitív kontroll (D2), a füstteszt elfogadási feltétele (kalibrált — E-24):**
   - futó állapotban van 102-figyelő és a 20 s-os delta ≥ 5 tick (kalibrált R_min; a kalibrációban 5–8);
   - a mgmt-stop után nincs 102-figyelő (a runtime-folyamat kilép, `listener_gone`).
   - Ha ez nem teljesül (pl. az élő-de-leállított delta > 2, vagy a folyamat a stop után is figyel), a jel a kampány előtt prereg-v1.2-ben módosul, eltérésnapló-tétellel. Addig a kampány nem indul.
5. **Epizódstátuszok (D2):**
   - `executed_effect`: leállás igazolva (`listener_gone` vagy `scan_stopped`);
   - `executed_no_effect`: a parancs kiment, a scan tovább fut (`scan_running`);
   - `executed_no_measurement`: a before- vagy az after-mérés nem sikerült (a nyers adattal);
   - `error`, valamint az A.6-nál `blocked` (`scripts/attack_runner.py`:342–353).
   - Mindegyiket kiértékeljük, de külön jelentjük.
6. **Visszaállítás (D2):** `/start_plc` a menedzsmenthálózaton (új pid igazolja). A `get_cpu_state()` nem használható (E-22).
7. **Adatgyűjtés (D6):** kampányonként a következők készülnek:
   - pcap (Sensor);
   - `eve.json`-szelet;
   - capture_loss (#76);
   - manifest: fájlonként sha256, szkript-commit, seed, a kezdőállapot és a kizárt ablakok időpontjai.
   - A nyers adat megváltoztathatatlan; javítás csak külön leképezési fájlban lehet (E-05).

## 5. Kiértékelés

### 5.1 Konfigurációk (D5, D5b)

- **C0** = telepített állapot:
  - ES (a négy icsnpp-adatfolyam: `results/lab-health-2026-10-29.txt`:703–707);
  - Suricata offline replay a pcap-on, a telepített szabályokkal (#84).
- **C1** = C0, és ezen felül:
  - utólagos EQL/DSL-szabályok (#87);
  - a SID 2009286 aktiválva (#51);
  - a Sensor nyers naplói: `conn.log`, `http.log`, `s7comm_read_szl`, `s7comm_upload_download` (#80).
- Élő Kibana-szabály nincs (E-16).

### 5.2 Besorolási szabályok (D0, D13): a szabálykód ezt valósítja meg

**Epizódablak:** [`start_ts` − 1 s, `end_ts` + 5 s], az A.3-nál is. Az óraeltérés-tűrés ±1 s (chrony, E-09), az ablak ezt már tartalmazza. A szabályokat a szabálykód előre rögzítve, determinisztikusan alkalmazza; emberi felülbírálás nincs.

**B1 – Kapcsolódás.** Egy rekord vagy riasztás akkor tartozik egy epizódhoz, ha:
- a időbélyege az epizódablakba esik, ÉS
- a forrás-IP-je az epizód forrás-IP-je, ÉS
- a cél-IP-je az epizód célja.
- Az A.3-nál a cél bármely 192.168.1.0/24-es cím lehet.
- **[SAJÁT MÉRNÖKI DÖNTÉS]**

**B2 – A procedúrát azonosító rekord (Telemetry).** A kapcsolódó rekordok közül a szcenárióhoz tartozó predikátumnak megfelelő:

| Szcenárió | Predikátum |
|---|---|
| A.1, V2.1, V2.5 | `modbus` rekord, `func` = WRITE_SINGLE_REGISTER, `pdu_type` = REQ |
| V2.4 | `modbus` rekord, `func` = WRITE_MULTIPLE_REGISTERS, `pdu_type` = REQ |
| A.2 | `modbus` rekord, `pdu_type` = REQ, `func` ∈ {READ_HOLDING_REGISTERS, READ_COILS, READ_DISCRETE_INPUTS, READ_INPUT_REGISTERS} |
| A.3 | `conn.log` rekord a 502-es vagy a 102-es célportra (csak a C1-ben) |
| A.4 | `s7comm` rekord, `function_name` = „PLC Stop” (#82) |
| A.5 | `http.log` rekord, `uri` = `/stop_plc` (csak a C1-ben; mező: `HTTP::Info` → `uri`, #112) |
| A.6 | `s7comm` rekord, Download-funkció (0x1a–0x1c, #82), vagy `s7comm_upload_download` rekord (csak a C1-ben) |
| V2.2 | `s7comm` rekord, `function_name` = „Read Variable” (#82) |
| V2.3 | `s7comm` rekord, `function_name` = „Write Variable” (#82) |

- A mezőnevek az ES-ben `icsnpp.modbus.*` / `icsnpp.s7comm.*` alakúak (`scripts/evaluate_campaign.py`:107–113, :367).
- A Modbus-funkciónevek: #79:230–246.
- **[SAJÁT MÉRNÖKI DÖNTÉS]** (D0 operacionalizálás).

**B3 – Riasztás szintje.** Riasztás a kapcsolódó Suricata-alert (`eve.json`, `event_type` = alert), illetve a C1-ben az EQL/DSL-szabály találata. A szintet a szabály neve, üzenete és metaadata dönti el:
- **Technique:** ATT&CK-technika-ID-t vagy -nevet tartalmaz;
- **Tactic:** csak taktika-ID-t vagy -nevet tartalmaz;
- **General:** egyiket sem tartalmazza.
- **[SAJÁT MÉRNÖKI DÖNTÉS]**

**B4 – Epizódkategória.** Az alábbi sorrendben az első teljesülő:
1. Not Applicable: a szcenárióhoz tervezetten nincs szenzor. A V1/V2 minden szcenáriója hálózati, ezért ez itt nem fordul elő.
2. Technique: a legmagasabb szintű kapcsolódó riasztás Technique szintű (B3).
3. Tactic: a legmagasabb szintű kapcsolódó riasztás Tactic szintű.
4. General: a legmagasabb szintű kapcsolódó riasztás General szintű.
5. Telemetry: van B2-rekord, riasztás nincs.
6. None: egyéb esetben.

**B5 – LÁTTA.** LÁTTA ⇔ a B4 kategóriája ≥ Telemetry.

**B6 – Modifier (#103).**
- A C1-eredmény „Configuration Change–Detection Logic” jelölést kap, ha a LÁTTA csak az utólagos szabályokon múlik.
- „Configuration Change–Data Sources” jelölést kap, ha a LÁTTA csak a Sensor nyers naplóin múlik.

### 5.3 Külső jelző (D13)

- Technikánként bináris összevetés:
  - nálunk: van-e LÁTTA epizód;
  - MITRE v20 (#73): van-e a technikához olyan analitika, amelynek log source-neve `NSM:`, `netflow:` vagy `otids:` előtagú.
- Mérőszám: súlyozatlan Cohen-kappa (#97).
- Nálunk = LÁTTA a C1-ben. Technikahalmaz: a V1 + V2 egyedi v20-as technikái. Az előtag-illesztés kis- és nagybetű-érzéketlen.
- Csak jelzőként közöljük.

### 5.4 FP (D8) és statisztika (D11)

- **FP (E-28 szerint):** a SID 2250008 (#86) azon találatainak száma a benign forgalmon (forrás: .51), amelyek egyetlen epizódablakba [`start_ts` − 1 s, `end_ts` + 5 s] és egyetlen visszaállítási/init-ablakba (D9 init, D2 restore, `.51` reset) sem esnek; kampányonként. A V1-ben nincs külön 60 perces benign-only elő/utó blokk (időkorlát), ezért a **nevező** az epizódokon (és a visszaállítási/init-ablakokon) kívüli benign-idő, valamint az ez alatt kiment benign kérések száma. **[SAJÁT MÉRNÖKI DÖNTÉS]**
- **Statisztika:**
  - a LÁTTA-arány k / n, az `error` státuszú epizódok nélkül;
  - posterior: Beta(k + 1/2, n − k + 1/2) (Jeffreys, elsődleges);
  - érzékenység: Beta(k + 1, n − k + 1);
  - közlés: posterior medián + 95%-os egyenlő farkú intervallum (2,5% és 97,5% kvantilis).
  - Aggregálás: elsődleges a szcenárió × konfiguráció, a K = 3 kampányt összevonva; másodlagos kampányonként, a kampányok közötti szórás jelzésére.
  - Az `executed_effect` és az `executed_no_effect` külön sor.

### 5.5 Kizárások (D12)

- Kizárjuk az `error` státuszú epizódokat; a számukat szcenárióként közöljük.
- Kizárt ablakok (UTC):

| Ablak | Mettől | Meddig | Forrás |
|---|---|---|---|
| lab_up | 2026-10-29T13:06:16Z | 2026-10-29T13:06:17Z | `results/lab-up-20261029T130616Z.log`:1, :62 |
| deploy-red-team | 2026-10-29T13:06:33Z | 2026-10-29T13:06:43Z | `results/deploy-red-team-20261029T130633Z.log`:1, :10; `results/deploy-red-team-20261029T130638Z.log`:1, :6 |
| lab_up | 2026-10-29T13:21:53Z | 2026-10-29T13:22:28Z | `results/lab-up-20261029T132153Z.log`:1, :40 |
| lab_up | 2026-10-29T13:23:27Z | 2026-10-29T13:23:59Z | `results/lab-up-20261029T132327Z.log`:1, :46 |
| M2c füstteszt | 2026-10-29T13:38:58.406050Z | 2026-10-29T13:40:15.225466Z | `results/lab-health-2026-10-29.txt`:53, :1032 |
| hatásjel-kalibráció (E-24) | 2026-10-31T09:13:55.924242Z | 2026-10-31T09:16:10.087040Z | `results/m4b/effect_calibration_20261031T091355Z.jsonl` |

- A jövőbeli lab_up-, füstteszt- és init-ablakokat (D9) kampányonként a manifest rögzíti (4.7). Ezek ugyanígy kizártak.

## 6. Eltéréskezelés

- Minden eltérés a tervtől a `docs/tdk/ELTERESNAPLO.md`-be kerül, ID-vel, dátummal és bizonyítékkal.
- Protokollmódosítás csak új taggel lehetséges (`prereg-v1.1`, …), a módosítás okával együtt.
- A hatásigazolási küszöb módosítása (4.4) is protokollmódosításnak számít (prereg-v1.1).

## 7. Ismert korlátok

- Egyetlen emberi értékelő helyett szabálykód sorol be. A szabálykód hibája szisztematikus; ezt a külső jelző (D13) csak jelzi.
- Szoftveres PLC (OpenPLC); valódi S7-en a viselkedés eltérhet (D2, D8).
- Filebeat-hatókör: az ES-ben csak a négy icsnpp-adatfolyam van. A `conn.log`, a `http.log` és a többi s7comm-napló csak a C1-ben, a Sensor nyers naplóiból jön (D5b).
- A statisztikai források (#95, #96, #97) csak metaadatból ismertek (D11, D13).
