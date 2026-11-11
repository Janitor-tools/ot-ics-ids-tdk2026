#!/usr/bin/env python3
"""
benign_generator.py -- Milestone 5/6 hattérzaj-generátor.

Fut a Red-Team-VM-en, a masodlagos, allowlistelt '.51' ("engineering
station") IP-cimrol -- lasd Milestone5-Terv.md D2/D.2 szakasz.

ONALLO OS-FOLYAMAT, nem resze az attack_runner.py-nak. A ket script
kozott nincs megosztott allapot, nincs IPC -- lasd a terv "Architektura-
dontes" indoklasat (GIL / blokkolo socket-fuggetlenseg).

Harom fuggetlen szal, a D.2 tablazat szerinti kadenciaval:
  1. poll_loop        -- 5 mp-enkent read_holding_registers (csak olvasas,
                          soha nem tuzeli a read->write EQL-szabalyt)
  2. idempotent_loop   -- 10 percenkent read -> write UGYANAZZAL az ertekkel
                          (az "ertek tenylegesen valtozott" felteteltjol el)
  3. setpoint_loop      -- 60 percenkent read -> write ELTERO ertekkel
                          (az allowlist-feltetelt teszi mérhetove)

Minden ciklus egy JSONL sort ir a benign_log.jsonl-be -- ez NEM epizod-
szintu ground truth (a kiertekeles a "nem esik tamadasi ablakba" negativ
felteteellel azonositja a benign esemenyeket), csak diagnosztikai naplo.
"""

from __future__ import annotations

import json
import logging
import random
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from pymodbus.client import ModbusTcpClient

# --------------------------------------------------------------------------
# KONFIGURACIO -- Milestone5-Terv.md D2 / D.2 szakasz szerint befagyasztva
# --------------------------------------------------------------------------

SOURCE_IP = "192.168.1.51"          # allowlistelt "engineering station" alias
TARGET_IP = "192.168.1.100"
TARGET_PORT = 502
DEVICE_ID = 1
REGISTER_ADDRESS = 0                # ugyanaz a regiszter, mint az A.1 epizodoknal
BASELINE_VALUE = 1009

POLL_INTERVAL_S = 5
IDEMPOTENT_INTERVAL_S = 10 * 60
SETPOINT_INTERVAL_S = 60 * 60

# a valodi ertekmodositas kis, biztonsagos tartomanyban mozog a baseline korul
SETPOINT_DELTA_RANGE = (1, 5)

LOG_PATH = Path("benign_log.jsonl")
CONNECT_TIMEOUT_S = 3

_stop_event = threading.Event()
_log_lock = threading.Lock()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_log(record: dict) -> None:
    """Egyetlen kozos JSONL fajl, lock-kal vedve a harom szal kozott."""
    with _log_lock:
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def make_client() -> ModbusTcpClient:
    """Minden hivas sajat, rovid eletu kapcsolatot nyit -- nincs megosztott
    kliens-objektum a harom szal kozott (elkeruli a socket-allapot
    interferenciat)."""
    return ModbusTcpClient(
        TARGET_IP,
        port=TARGET_PORT,
        source_address=(SOURCE_IP, 0),   # PoC-ban igazolt: pymodbus 3.14+ tamogatja
        timeout=CONNECT_TIMEOUT_S,
    )


# --------------------------------------------------------------------------
# A harom benign ciklus
# --------------------------------------------------------------------------

def poll_loop() -> None:
    """Tipikus HMI/SCADA poll -- soha nem ir, csak olvas."""
    while not _stop_event.wait(POLL_INTERVAL_S):
        ts = utc_now_iso()
        client = make_client()
        try:
            if not client.connect():
                append_log({"ts": ts, "cycle": "poll", "status": "connect_failed"})
                continue
            rr = client.read_holding_registers(
                address=REGISTER_ADDRESS, count=1, device_id=DEVICE_ID
            )
            append_log({
                "ts": ts,
                "cycle": "poll",
                "status": "error" if rr.isError() else "ok",
                "value": None if rr.isError() else rr.registers[0],
            })
        except Exception as exc:  # a benign generator nem allhat meg egy hibas ciklus miatt
            logging.exception("poll_loop hiba")
            append_log({"ts": ts, "cycle": "poll", "status": "exception", "detail": str(exc)})
        finally:
            client.close()


def idempotent_loop() -> None:
    """D.2: read -> write UGYANAZZAL az ertekkel -- a naiv szabalyt tuzeli,
    a finomitottat (ertek-valtozas feltetel) nem."""
    while not _stop_event.wait(IDEMPOTENT_INTERVAL_S):
        ts = utc_now_iso()
        client = make_client()
        try:
            if not client.connect():
                append_log({"ts": ts, "cycle": "idempotent", "status": "connect_failed"})
                continue
            rr = client.read_holding_registers(
                address=REGISTER_ADDRESS, count=1, device_id=DEVICE_ID
            )
            if rr.isError():
                append_log({"ts": ts, "cycle": "idempotent", "status": "read_error"})
                continue
            current_value = rr.registers[0]
            wr = client.write_register(
                address=REGISTER_ADDRESS, value=current_value, device_id=DEVICE_ID
            )
            append_log({
                "ts": ts,
                "cycle": "idempotent",
                "status": "error" if wr.isError() else "ok",
                "value_before": current_value,
                "value_after": current_value,  # szandekosan valtozatlan
            })
        except Exception as exc:
            logging.exception("idempotent_loop hiba")
            append_log({"ts": ts, "cycle": "idempotent", "status": "exception", "detail": str(exc)})
        finally:
            client.close()


def setpoint_loop() -> None:
    """D.2: read -> write ELTERO ertekkel -- a naiv szabalyt tuzeli, a
    finomitottat is (mert valoban valtozik az ertek), de az allowlist-
    feltetel elnyomja, mert a forras a '.51'."""
    while not _stop_event.wait(SETPOINT_INTERVAL_S):
        ts = utc_now_iso()
        client = make_client()
        try:
            if not client.connect():
                append_log({"ts": ts, "cycle": "setpoint", "status": "connect_failed"})
                continue
            rr = client.read_holding_registers(
                address=REGISTER_ADDRESS, count=1, device_id=DEVICE_ID
            )
            if rr.isError():
                append_log({"ts": ts, "cycle": "setpoint", "status": "read_error"})
                continue
            current_value = rr.registers[0]
            delta = random.choice([1, -1]) * random.randint(*SETPOINT_DELTA_RANGE)
            new_value = current_value + delta
            wr = client.write_register(
                address=REGISTER_ADDRESS, value=new_value, device_id=DEVICE_ID
            )
            append_log({
                "ts": ts,
                "cycle": "setpoint",
                "status": "error" if wr.isError() else "ok",
                "value_before": current_value,
                "value_after": new_value,
            })
        except Exception as exc:
            logging.exception("setpoint_loop hiba")
            append_log({"ts": ts, "cycle": "setpoint", "status": "exception", "detail": str(exc)})
        finally:
            client.close()


# --------------------------------------------------------------------------
# Eloallitas / leallitas
# --------------------------------------------------------------------------

def _handle_signal(signum, _frame) -> None:
    logging.info("Leallitasi jel (%s) fogadva, szalak leallitasa...", signum)
    _stop_event.set()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    append_log({
        "ts": utc_now_iso(),
        "cycle": "meta",
        "status": "generator_started",
        "source_ip": SOURCE_IP,
        "target": f"{TARGET_IP}:{TARGET_PORT}",
    })

    threads = [
        threading.Thread(target=poll_loop, name="poll", daemon=True),
        threading.Thread(target=idempotent_loop, name="idempotent", daemon=True),
        threading.Thread(target=setpoint_loop, name="setpoint", daemon=True),
    ]
    for t in threads:
        t.start()

    logging.info(
        "benign_generator elindult (.51-rol), poll=%ss idempotent=%ss setpoint=%ss. "
        "Leallitas: Ctrl+C.",
        POLL_INTERVAL_S, IDEMPOTENT_INTERVAL_S, SETPOINT_INTERVAL_S,
    )

    # a fo szal a stop_event-re var -- a harom worker szal daemon, de a
    # graceful leallitashoz (utolso naplosor) megvarjuk a join-t
    _stop_event.wait()
    for t in threads:
        t.join(timeout=5)

    append_log({"ts": utc_now_iso(), "cycle": "meta", "status": "generator_stopped"})
    logging.info("benign_generator leallt.")


if __name__ == "__main__":
    main()
