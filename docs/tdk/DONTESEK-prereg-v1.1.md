# Döntési rekordok – validációs kampányok (M3b, 2026-10-31)

- A döntések a `docs/tdk/VALIDACIOS-PROTOKOLL.md` (prereg-v1) alapjai.
- Hivatkozás: fájl:sor vagy FORRAS-ID (`docs/tdk/forras-leltar.md`; a helyi fájl és sora a `docs/tdk/forras-horgonyok.md`-ben).
- R1, R2 = az Informatics'26 bírálói (`docs/tdk/related-works/informatics-2026/biralat.md`:8, :11).
- **[SAJÁT MÉRNÖKI DÖNTÉS]** jelöli azt a részt, amelyet nem elsődleges forrás ír elő.
- **NYITOTT (NYK-n)** jelölte azt a pontot, amelynél a hivatkozás nem igazolta az állítást, vagy egy paraméter nem volt rögzítve. Mind a tíz pont LEZÁRVA 2026-10-31 (lista a fájl végén).

---

## D0 – Mi számít „látta”-nak

- **Kérdés:** Mikor mondjuk, hogy a megfigyelő stack „látta” egy támadási epizódot, és milyen erős a bizonyíték?
- **Alternatívák:** (a) csak riasztás számít; (b) bináris: rekord vagy riasztás; (c) ordinális skála; (d) saját, ad hoc kategóriák.
- **Kritériumok:** Különválassza a megfigyelhetőséget a detektálhatóságtól; legyen külső, publikált definíciója; gépileg, determinisztikusan eldönthető legyen.
- **Döntés:**
  - ELSŐDLEGES METRIKA (bináris):
    - LÁTTA = van evidencia: az epizód ablakában létezik a procedúrát azonosító rekord (ES-ben; a C1-ben a Sensor nyers naplóiban is) vagy riasztás.
    - NEM LÁTTA = nincs ilyen.
  - MÁSODLAGOS METRIKA (ordinális, a bizonyíték erőssége): a MITRE ATT&CK Evaluations ICS (TRITON) kategóriái a #103 (Wayback 2021-07-29) rögzített szövege szerint: None < Telemetry < General < Tactic < Technique. LÁTTA ⇔ ≥ Telemetry.
  - A Not Applicable külön kategória: tervezetten nincs szenzor (pl. host-oldali technikák). A #103 szerint a hiányzó szenzort előre kell rögzíteni.
  - Modifierek (#103):
    - Configuration Change–Detection Logic = C1 (D5);
    - Configuration Change–Data Sources = a Sensor nyers naplóinak bevonása (D5b).
  - Magyarázó tengely: L1–L4 (`docs/tdk/related-works/informatics-2026/informatics_2026_paper.txt`:181–192):
    - L1: egyetlen protokollüzenet megnevezi a műveletet;
    - L2: csak eseménysorozatból következtethető ki;
    - L3: csak kiegészítő kontextussal azonosítható;
    - L4: csak gyanúként vagy a forgalom hiányaként jelezhető.
  - **[SAJÁT MÉRNÖKI DÖNTÉS]** Az operacionalizálás:
    - Telemetry = a procedúrát azonosító rekord;
    - Technique = a technikát nevesítő riasztás;
    - a kategóriák sorrendje ordinális skálaként. A #103 a kategóriákat ebben a sorrendben közli, de rangsort nem mond ki.
  - A szabályok pontos szövege: protokoll 5.2.
- **Saját bizonyíték:**
  - `results/m3g/evals_ics_detection_categories.txt` (szó szerinti kivonat: kategóriák :7–70, modifierek :72–116);
  - `results/m3g/evals_ics_detcat_drift.txt`: a két további 2021-es snapshot szövege azonos.
  - Az élő oldal eltér: öt kategóriacím, Technique és Modifier nincs (#70 headless; `results/m3g/evals_ics_detection_categories.txt`:118–132).
- **Elsődleges forrás:**
  - #103 (wayback-…-20210729150312.txt: kategóriák :67–118, modifierek :119–159, bevezető :42–66);
  - L1–L4: Informatics-cikk (lásd fent).
- **Kezelt bírálói kifogás:**
  - R1: kategória-összemosás („The categories conflate a lack of observability with a lack of the context necessary for identification”, `biralat.md`:8). A LÁTTA (van-e evidencia) és az L-szint (milyen kontextus kell az azonosításhoz) két külön tengely.
  - R2: nem itt; LEZÁRVA 2026-10-31 (NYK-4): az R2 csak a D1-nél szerepel.
- **Epizódablak:** LEZÁRVA 2026-10-31 (NYK-5):
  - [`start_ts` − 1 s, `end_ts` + 5 s], az A.3-nál is;
  - az óraeltérés-tűrés ±1 s (chrony, E-09), az ablak ezt már tartalmazza.
  - **[SAJÁT MÉRNÖKI DÖNTÉS]**
- **Kockázat:**
  - A 2021-es TRITON-definíciók gyártói termékekre készültek, nem nyílt forrású stackre.
  - Az élő oldal 2026-ban csonka (#70).
  - Az ordinális sorrend saját értelmezés.
- **Státusz:** ELFOGADVA 2026-10-31 (Szabados J.)

## D1 – ATT&CK-verzió

- **Kérdés:** Melyik ATT&CK for ICS kiadásra hivatkozunk a kampánytechnikáknál és az elvárt detektálásnál, és mi lesz a v19.2-es 97/42-es osztályozással?
- **Alternatívák:** (a) minden v19.2-n marad; (b) minden v20.0-ra kerül; (c) a kampány és az elvárt detektálás v20.0-n, az osztályozás v19.2-n, delta-táblával.
- **Kritériumok:** A mérés idején aktuális kiadás; a beadott absztrakt számainak (97/42) visszakövethetősége; rögzített, letöltött STIX-forrás.
- **Döntés:** (c).
  - ATT&CK for ICS v20.0 (#73, attack-stix-data commit `c2494b29`) a kampánytechnikákhoz és az elvárt detektálás referenciájához (`results/m3g/attack_ics_v20_detection_map.csv`).
  - A 97/42-es osztályozás v19.2-n marad (#74), delta-táblával (`results/m3g/attack_ics_structure.txt`:781–793; #72:106: v20 = 12 taktika, 78 technika, 26 al-technika).
  - T0855 → T1692.001 (`results/m3g/attack_ics_structure.txt`:325–326: „revoked-by -> T1692.001”).
  - A.3 = T0846.001 Port Scan (`results/m3g/attack_ics_v20_detection_map.csv`:38).
  - A T0816/T0868 pár törölve (E-22; `docs/tdk/ELTERESNAPLO.md`:30).
  - A 97 soros tábla függelékbe kerül.
- **Saját bizonyíték:** `results/m3g/attack_ics_structure.txt`, `attack_ics_v19_2_detection_map.csv`, `attack_ics_v20_detection_map.csv`.
- **Elsődleges forrás:** #72, #73, #74.
- **Kezelt bírálói kifogás:**
  - R1: a 97 technika teljes besorolási táblája nem volt közölve (`biralat.md`:8);
  - R2: nincs definíció mind a 97 technikára (`biralat.md`:11).
- **Kockázat:** Két kiadás párhuzamos használata; ezt a delta-tábla és a függelék kezeli.
- **Státusz:** ELFOGADVA 2026-10-31 (Szabados J.)

## D2 – A PLC-leállítás valódi végrehajtása és igazolása

- **Kérdés:** Hogyan hajtjuk végre és igazoljuk a T0816 (leállítás) hatását, ha a `get_cpu_state()` nem mér (E-22), és az augusztusi A.5 nem állított le semmit?
- **Alternatívák:** (a) a leállítás elhagyása; (b) parancs kiküldése hatásigazolás nélkül; (c) valódi leállítás független hatásigazolással.
- **Kritériumok:** A ground truth legyen igazolt; a mérés ne a támadó eszköz önbevallására épüljön; a visszaállítás ne szennyezze a mért forgalmat.
- **Indoklás (fenyegetés-bizonyíték):** LEZÁRVA 2026-10-31 (NYK-1).
  - A #6 szerint a fenyegető szereplők AI-generált szkriptjeinek céljai: „initial access, credential access, denial of service, and other objectives” (PDF 2. o. 40–41. sor és 3. o. 5. sor).
  - A lehetséges hatások között szerepel a leállási idő („downtime”) és a vészleállító rendszerek manipulálása (PDF 4. o. 14–28. sor, „Potential operational impacts”).
  - A sorszámok a `pdftotext -layout` oldalankénti kimenetére vonatkoznak.
  - A T0816 ennek a vezérlőn megvalósuló hálózati formája; ezért a leállítást ténylegesen végre kell hajtani és igazolni.
  - Megjegyzés: a #6 ezeket lehetséges hatásként írja le; a megfigyelt tevékenységet felderítésnek és előkészítésnek értékeli (PDF 4. o. 5–12. sor).
- **Döntés:** (c).
  - **A.5:**
    - lépések: `/login` (gyári hitelesítés, E-18), majd `/stop_plc` az OT-Neten (#90:601–640, :642–668);
    - címke: T0816, másodlagos T1694 (Insecure Credentials; #6, 3. o.: „insecure credentials … [T1694]”; név: `results/m3g/attack_ics_v20_detection_map.csv`:92).
  - Az augusztusi A.5 érvénytelen, kizárva: csak `GET /` volt, leállító hívás nem (`scripts/attack_runner.py`:364–367).
  - **A.4:** S7 `plc_stop()`, változatlan vektor (`scripts/attack_runner.py`:325–339).
  - **Hatásigazolás** mindkét vektorra, csak a `/proc` és a 102-figyelő mérésével. LEZÁRVA 2026-10-31, kalibrálva prereg-v1.1-ben (NYK-2, NYK-3; E-24).
    - Mérőcsatorna (NYK-2): a PLC menedzsment-IP-jén (192.168.56.20) SSH-n (E-23); a 102-es TCP-porton figyelő folyamat (`ss -tlnp`), annak `/proc/<pid>/stat` `utime` (14) + `stime` (15) mezője clock tickben (#111), valamint szálanként `/proc/<pid>/task/*/stat` (nyers diagnosztika).
    - **Kalibráció (E-24, `results/m4b/effect_calibration_20261031T091355Z.jsonl`):** a mgmt `/stop_plc` hatására az OpenPLC-runtime folyamata **kilép** (mind a 6 leállított ablak: `listener=false`, `total_delta=null`, `current_listener_pid=null`); futó állapotban az összesített delta 5–8 tick / 20 s (R_min=5). A tiszta, kategorikus jel így a **102-figyelő jelenléte**, nem a tick-delta.
    - **Kétágú `effect_status` szabály (DÖNTÉS: Szabados J., 2026-10-31):**
      1. ha a stop **előtt** figyel folyamat a 102-n (pid0), és a stop **után** (2 s várakozás, majd 3 ellenőrzés 2 s-onként) a 102-n **nincs** figyelő → `executed_effect`, ág `listener_gone`;
      2. ha a stop után **van** figyelő: a figyelő folyamat tick-deltája az utána-ablakban (20 s). ≤ 2 tick → `executed_effect`, ág `scan_stopped`; > 2 tick → `executed_no_effect`, ág `scan_running`. A T = 2 = floor((R_min=5 + feltételezett S_max=0)/2). **[SAJÁT MÉRNÖKI DÖNTÉS]** Ezt az ágat az A.4 füstteszt validálja; ha az élő-de-leállított delta > 2, prereg-v1.2 + eltérésnapló;
      3. ha a stop előtt nincs figyelő, vagy a mérés hibázik → `executed_no_measurement` (nyers adattal).
    - A tick-adat (összesített és szálankénti) minden ágban nyers diagnosztikaként a rekordban marad (mező: `effect_branch`).
    - A `get_cpu_state()` nem használható (E-22; #108:1363–1375: az `extract_cpu_state()` konstanst ad vissza).
  - **Epizódstátusz:** `executed_effect` (leállás igazolva) / `executed_no_effect` (a parancs kiment, leállás nincs) / `executed_no_measurement`. Mindegyiket detektálásra mérjük, de külön jelentjük.
  - **Visszaállítás:** `/start_plc` (#90:642–668) a menedzsmenthálózaton (a kalibráció után új pid igazolja: 3301 → 6470).
  - **Elfogadási feltétel a füsttesztben:** futó állapotban van 102-figyelő és delta ≥ 5 tick / 20 s (kalibrált R_min); a mgmt-stop után nincs 102-figyelő (`listener_gone`). Különben prereg-v1.2.
  - **Előre jelzett eredmény:** az A.5 HTTP-forgalma a Sensoron látszik, a SIEM-ben nem. Az ES-ben csak a négy icsnpp-adatfolyam van: modbus, modbus_detailed, s7comm, cotp (`results/lab-health-2026-10-29.txt`:703–707).
- **Saját bizonyíték:**
  - E-22 (`results/m3g/get_cpu_state_audit.txt`, `results/m3g/k3_zeek_records.txt`);
  - az augusztusi A.4-rekordokban a `cpu_state_after` = `S7CpuStatusRun` (`data/campaign_2026-08-22/attack_log.original.jsonl`:1).
- **Elsődleges forrás:** #6 (indoklás és T1694-címke), #90 (OpenPLC webserver), #108 (python-snap7), #111 (proc_pid_stat(5)).
- **Kezelt bírálói kifogás:** R2: „It also lacks the impact analysis and verification” (`biralat.md`:11). LEZÁRVA 2026-10-31 (NYK-9).
- **Kockázat:**
  - A CPU-idő delta közvetett jel; a szoftveres PLC viselkedése eltérhet a valódi S7-étől.
  - Az A.5 N = 3 kicsi.
  - A `/stop_plc` a `stop_runtime()`-ot hívja (#90:657–666). Hogy a folyamat ezután is fut-e (vagyis mérhető-e az utána-delta), az OpenPLC helyben mentett forrásából nem látszik; ezt a füstteszt mutatja meg.
- **Státusz:** ELFOGADVA 2026-10-31 (Szabados J.)

## D3 – V1: replikáció

- **Kérdés:** Hány független kampány fusson, és milyen szerkezettel?
- **Alternatívák:** (a) egy kampány; (b) K = 3 az augusztusi szerkezettel; (c) K > 3.
- **Kritériumok:** R1 szerint egyetlen rövid kampány nem elég (`biralat.md`:8); a kampány kb. 179 perc; a határidő 2026-11-10.
- **Döntés:**
  - K = 3 replikáció az augusztusi szerkezettel.
  - N: A1 20, A2 20, A3 3, A4 20, A5 3, A6 3 (`scripts/attack_runner.py`:100).
  - Seed 1/2/3: az `attack_runner.py`-ban jelenleg nincs seed (`docs/tdk/2026-11-atirasi-terv.md`:43).
  - Kezdőállapot a D9 szerint.
  - Az A.3 hossza dokumentált eltérés: tervezett ~20 s (`chapters/Milestone5-Terv.md`:169), mért 114,6 / 115,5 / 116,2 s (`data/campaign_2026-08-22/attack_log.original.jsonl`:9, :47, :63).
- **Saját bizonyíték:** az augusztusi nyers adat (lásd fent).
- **Elsődleges forrás:** – (tervezési döntés).
- **Kezelt bírálói kifogás:** R1: „single short campaign” (`biralat.md`:8).
- **Kockázat:** A K = 3 kicsi a kampányok közötti szórás becsléséhez.
- **Státusz:** ELFOGADVA 2026-10-31 (Szabados J.)

## D4 – V2: kitérési és kiegészítő szcenáriók

- **Kérdés:** Milyen szcenáriók tesztelik a finomított szabály határait és az advisory TTP-it?
- **Alternatívák:** (a) nincs V2; (b) a konzulensi kitérési lista teljes egészében; (c) szűkített V2.
- **Kritériumok:** R1 kifogása (kompromittált mérnöki állomás); az advisory TTP-i (#6); megvalósíthatóság a laborban.
- **Döntés:** (c), N = 20 szcenáriónként:
  - a .51-ről (allowlistelt forrás: `scripts/benign_generator.py`:44) T0836 írás (kompromittált mérnöki állomás);
  - S7 DB1002 olvasás és írás (T0893 / T0821):
    - #6, 3. o.: „read/write operations on data blocks … [T0893, T0821]”;
    - #91:762–766: %MW → DB1002; #91:1165–1240: a DB1002 elfogadott terület;
  - kitérések: FC16 FC06 helyett (#79); időzítés > 10 s a `maxspan` ellen (#87; `scripts/evaluate_campaign.py`:107).
  - LEZÁRVA 2026-10-31 (NYK-6):
    - A V2.2–V2.5 forrás-IP-je .50 (támadó). Indok: a kitérés a finomított T0836-szabály logikáját teszteli; a .51 már az allowlist miatt kiesik, az a V2.1 tárgya.
    - DB1002: start = 0, size = 2 (%MW0; #91:762–766).
    - A V2.3 írt értéke 4242: eltér a D9-es 1009-től, így egyértelműen azonosítható.
    - V2.5: az FC03 és az írás között 15 s.
- **Saját bizonyíték:** a finomított T0836 a .51-et kizárja (`scripts/evaluate_campaign.py`:329–347).
- **Elsődleges forrás:** #6, #79, #87, #91.
- **Kezelt bírálói kifogás:** R1: „does not confirm effectiveness against a compromised engineering workstation” (`biralat.md`:8).
- **Kockázat:**
  - Az `s7comm.log` a DB-számot és a címet nem naplózza (#80:112–138), tehát az olvasás/írás csak funkcióként látszik.
- **Státusz:** ELFOGADVA 2026-10-31 (Szabados J.)

## D5 – Kiértékelési konfigurációk (C0/C1)

- **Kérdés:** Mivel mérünk: a telepített állapottal vagy utólag írt szabályokkal is?
- **Alternatívák:** (a) csak C0; (b) csak C1; (c) C0 és C1 párosítva ugyanazon az adaton; (d) élő Kibana-szabályok.
- **Kritériumok:** A telepített képesség és a hozzáadott képesség szétválasztása; reprodukálhatóság; az E-16 (Kibana Detection Engine nem működik).
- **Döntés:** (c).
  - C0 = telepített állapot: ES, valamint Suricata offline replay a telepített szabályokkal (#84: `-r`).
  - C1 = utólagos szabályok: EQL/DSL (#87), és a SID 2009286 aktiválva (#51; a telepített állapotban kommentelt).
  - Élő Kibana-szabály nincs (E-16; #89:34–51 előfeltételei hiányoznak).
- **Saját bizonyíték:** E-16 (`docs/tdk/ELTERESNAPLO.md`:24).
- **Elsődleges forrás:** #51, #84, #87, #89.
- **Kezelt bírálói kifogás:** –
- **Kockázat:** Az offline replay és az élő capture eltérhet. Ezt kampányonként a capture_loss (D6) ellenőrzi.
- **Státusz:** ELFOGADVA 2026-10-31 (Szabados J.)

## D5b – Adatforrás-bővítés csak a C1-ben

- **Kérdés:** Bővítjük-e élőben a Filebeat által szállított naplókat?
- **Alternatívák:** (a) a Filebeat bővítése élőben; (b) a Filebeat változatlan, a nyers naplók utólag.
- **Kritériumok:** A telepített állapot (C0) ne változzon; a Data Sources modifier (D0) külön jelölhető legyen.
- **Döntés:** (b). A Filebeat élőben nem változik. A C1-ben a Sensor nyers naplóiból kerül be:
  - `s7comm_read_szl` és `s7comm_upload_download` (#80:16–23, :140–146, :166–177);
  - `http.log` és `conn.log`.
- **Saját bizonyíték:** az ES-ben csak a négy icsnpp-adatfolyam van (`results/lab-health-2026-10-29.txt`:703–707).
- **Elsődleges forrás:** #80.
- **Kezelt bírálói kifogás:** –
- **Kockázat:** A C1-eredmény nem a telepített SIEM képessége; ezt a modifier jelöli.
- **Státusz:** ELFOGADVA 2026-10-31 (Szabados J.)

## D6 – Adatgyűjtés kampányonként

- **Döntés:** Kampányonként a következők készülnek:
  - pcap;
  - `eve.json`-szelet;
  - capture_loss (#76);
  - manifest (sha256).
- **Kritériumok:** A C0/C1 offline újrafuttathatósága; a veszteség kontrollja (E-07).
- **Elsődleges forrás:** #76 (a capture_loss gap-alapú becslés).
- **Kezelt bírálói kifogás:** –
- **Kockázat:** A capture_loss csak a TCP-gap-ekből becsül (#76).
- **Státusz:** ELFOGADVA 2026-10-31 (Szabados J.)

## D7 – event.ingested

- **Döntés:** Nincs `event.ingested` pipeline-módosítás. **[SAJÁT MÉRNÖKI DÖNTÉS]**
- **Kritériumok:** A telepített állapot változatlansága (C0).
- **Elsődleges forrás:** –
- **Kockázat:** Az ingest-késleltetés nem mérhető közvetlenül.
- **Státusz:** ELFOGADVA 2026-10-31 (Szabados J.)

## D8 – SID 2250008 mint FP-metrika

- **Döntés:** A SID 2250008 (E-19, #86) FP-metrikája: a benign forgalmon kapott találatok száma.
- **Saját bizonyíték:** E-19: 2026-08-20-án 45, 2026-08-22-én 2883 azonos alert (`docs/tdk/ELTERESNAPLO.md`:27).
- **Elsődleges forrás:** #86 (a szabály: `app-layer-event:modbus.value_mismatch`, `flow:to_client`).
- **Kezelt bírálói kifogás:** –
- **Kockázat:** A decoder-esemény az OpenPLC válaszára tüzel; valódi PLC-n más lehet.
- **Státusz:** ELFOGADVA 2026-10-31 (Szabados J.)

## D9 – Kezdőállapot

- **Döntés:** Minden kampány előtt a regiszter kezdőértéke 1009, a .51-ről írva, a mérési ablakon kívül (E-20).
- **Saját bizonyíték:**
  - E-20 (`docs/tdk/ELTERESNAPLO.md`:28): a regiszter nem perzisztens, most 0;
  - `scripts/attack_runner.py`:91: `BASELINE_VALUE = 1009`.
- **Elsődleges forrás:** –
- **Kockázat:** Az írás maga Modbus-forgalom. Ezért az ablakon kívül történik, és a D12 szerint kizárjuk.
- **Státusz:** ELFOGADVA 2026-10-31 (Szabados J.)

## D10 – CIC Modbus 2023

- **Döntés:** KIMARAD (döntés: Szabados J., 2026-10-31); továbbfejlesztési irány.
- **Kritériumok:** Határidő; a konzulensi javaslat is csak megvalósíthatósági vizsgálat után venné fel (`docs/tdk/2026-11-atirasi-terv.md`:53).
- **Elsődleges forrás:** – (a forrásleltárban nincs tétel).
- **Státusz:** ELFOGADVA 2026-10-31 (Szabados J.)

## D11 – Statisztika

- **Kérdés:** Hogyan közöljük a LÁTTA-arány bizonytalanságát kis N mellett?
- **Alternatívák:** (a) bootstrap (a korábbi [1,000; 1,000]); (b) Clopper–Pearson; (c) Beta-Binomiális posterior.
- **Döntés:** (c).
  - Elsődleges prior: Jeffreys, Beta(1/2, 1/2); érzékenység: Beta(1, 1).
  - Közlés: posterior medián + 95%-os egyenlő farkú intervallum.
  - **[SAJÁT MÉRNÖKI DÖNTÉS]** hivatkozással: #95 (Brown–Cai–DasGupta 2001) és #96 (Clopper–Pearson 1934). Mindkettő csak metaadatból (`docs/tdk/forras-leltar.md` „átnézve”: IGEN – csak metaadat).
  - Az aggregálási szint, LEZÁRVA 2026-10-31 (NYK-7):
    - elsődleges: szcenárió × konfiguráció, a K = 3 kampányt összevonva;
    - másodlagos: kampányonként, a kampányok közötti szórás jelzésére.
- **Kezelt bírálói kifogás:**
  - R1: a [1.000, 1.000] intervallum „fails to reflect the uncertainty” (`biralat.md`:8);
  - lásd még `docs/tdk/2026-11-atirasi-terv.md`:38.
- **Kockázat:** A statisztikai források teljes szövege nincs meg.
- **Státusz:** ELFOGADVA 2026-10-31 (Szabados J.)

## D12 – Kizárások

- **Döntés:**
  - Kizárjuk az `error` státuszú epizódokat.
  - Kizárjuk a lab_up-, a füstteszt- és az init-ablakokat (D9). A lista a protokoll 5.5 pontjában van.
- **Saját bizonyíték:**
  - augusztus: A1 17 executed, 3 error (`data/campaign_2026-08-22/attack_log.original.jsonl`);
  - füstteszt-ablak: `results/lab-health-2026-10-29.txt`:53, :1032.
- **Kezelt bírálói kifogás:** –
- **Kockázat:** A kizárt epizódok aránya torzíthat; ezért külön közöljük.
- **Státusz:** ELFOGADVA 2026-10-31 (Szabados J.)

## D13 – A besorolás végrehajtója és a külső jelző

- **Kérdés:** Ki vagy mi sorolja be az epizódokat, és van-e független viszonyítási pont?
- **Alternatívák:** (a) egy emberi értékelő; (b) két emberi értékelő + kappa; (c) előre rögzített szabálykód + külső jelző.
- **Kritériumok:** Reprodukálhatóság; az egyetlen szakértő problémája; erőforrás (második értékelő nincs).
- **Döntés:** (c).
  - A besorolást előre rögzített, determinisztikus szabálykód végzi, nem ember (protokoll 5.2).
  - Külső jelző technikánként: bináris összevetés.
    - Egyik oldal: van-e nálunk hálózati evidencia.
    - Másik oldal: vár-e a MITRE v20 `NSM:` / `netflow:` / `otids:` analitikát. Ezek a log source-nevek a v20 STIX-ben (#73) előfordulnak; példák: `results/m3g/attack_ics_structure.txt`:617, :630, :643.
  - Mérőszám: súlyozatlan Cohen-kappa (#97, csak metaadat).
  - LEZÁRVA 2026-10-31 (NYK-8):
    - „nálunk hálózati evidencia” = LÁTTA a C1-ben;
    - technikahalmaz: a V1 + V2 egyedi v20-as technikái;
    - az előtag-illesztés kis- és nagybetű-érzéketlen.
  - A pontos szabály: protokoll 5.3.
- **Elsődleges forrás:** #73, #97.
- **Kezelt bírálói kifogás:** LEZÁRVA 2026-10-31 (NYK-9):
  - R1: „The mapping was performed by a single expert” (`biralat.md`:8);
  - R2: „Mapping was set by the expert, however, no critical discussion is present” (`biralat.md`:11).
- **Kockázat:** A két oldal eltérő konstrukció (mért evidencia vs. elvárt analitika), ezért a kappa csak jelző.
- **Státusz:** ELFOGADVA 2026-10-31 (Szabados J.)

---

## NYITOTT KÉRDÉSEK (2026-10-31) – mind LEZÁRVA

- **NYK-1 (D2):** A #6 nem tartalmazta az eredetileg megfogalmazott állítást, hogy a valós hatás a leállítás.
  - LEZÁRVA 2026-10-31: az indoklás a #6 céljaira (DoS) és lehetséges hatásaira („downtime”, a vészleállító rendszerek manipulálása) épül, oldal- és sorhivatkozással (D2).
- **NYK-2 (D2):** Nem volt elsődleges forrás a `/proc/<pid>/stat` `utime`/`stime` mezőire.
  - LEZÁRVA 2026-10-31: #111 (proc_pid_stat(5), `man7-proc_pid_stat.5.txt`:134–152).
- **NYK-3 (D2):** Nem volt rögzítve a hatásigazolás ablaka, küszöbe, a pid és a webes státusz.
  - LEZÁRVA 2026-10-31, kalibrálva prereg-v1.1 (E-24):
    - mérőcsatorna: a 102-figyelő folyamat (`ss -tlnp`) és `/proc/<pid>/stat` a PLC mgmt-IP-jén SSH-n (E-23);
    - a kalibráció szerint a mgmt-stop a runtime-folyamatot megszünteti → a tick-delta nem válik szét, a jel a **102-figyelő jelenléte**;
    - kétágú szabály: `listener_gone` (stop után nincs figyelő) → `executed_effect`; ha van figyelő: utána-ablak (20 s) tick-deltája ≤ 2 → `executed_effect` (`scan_stopped`), > 2 → `executed_no_effect`; nincs before-figyelő/hiba → `executed_no_measurement`. Lásd D2.
- **NYK-4 (D0):** Az R2 (`biralat.md`:11) a technikadefiníciókra vonatkozik.
  - LEZÁRVA 2026-10-31: az R2 csak a D1-nél szerepel.
- **NYK-5 (D0):** Nem volt rögzítve az epizódablak.
  - LEZÁRVA 2026-10-31: [`start_ts` − 1 s, `end_ts` + 5 s], az A.3-nál is; az óraeltérés-tűrés ±1 s (chrony, E-09) benne van.
- **NYK-6 (D4):** Nem volt rögzítve a V2 forrás-IP-je, a DB-cím, az érték és a késleltetés.
  - LEZÁRVA 2026-10-31:
    - a V2.2–V2.5 forrás-IP-je .50;
    - DB1002, start = 0, size = 2 (%MW0);
    - a V2.3 írt értéke 4242;
    - V2.5: 15 s.
- **NYK-7 (D11):** Nem volt rögzítve az aggregálási szint.
  - LEZÁRVA 2026-10-31: elsődleges: K = 3 összevonva, szcenárió × konfiguráció; másodlagos: kampányonként.
- **NYK-8 (D13):** Nem volt rögzítve a konfiguráció, a technikahalmaz és a betűkezelés.
  - LEZÁRVA 2026-10-31:
    - LÁTTA a C1-ben;
    - a V1 + V2 egyedi v20-as technikái;
    - az előtag-illesztés kis- és nagybetű-érzéketlen.
- **NYK-9 (D2, D13):** Kezelt bírálói kifogások.
  - LEZÁRVA 2026-10-31:
    - D2: R2 „lacks the impact analysis and verification”;
    - D13: R1 „single expert” és R2 „Mapping was set by the expert…” (`biralat.md`:8, :11).
- **NYK-10 (protokoll 5.2, A.5):** Nem volt helyi forrás a `http.log` URI-mezőjének nevére.
  - LEZÁRVA 2026-10-31: #112, `HTTP::Info` → `uri` („URI used in the request.”, `zeek-8.0.9-http-main.zeek.txt`:3283, :3329–3335).
