#!/usr/bin/env python3
"""tests/test_evaluate_v.py -- evaluate_v.py egysegtesztek (prereg-v1.1).

Lefedi: minden B2-predikatum (+/-), B1 ablakhatarok, kizarasok (error/ABORTED/
kizart ablak), Jeffreys Beta-kvantilis ismert ertekre (k=20,n=20), Cohen-kappa
ismert peldara, es a stdlib betaincinv == scipy (ha van) egyezes.
Futtatas:  python3 -m unittest tests/test_evaluate_v.py  (vagy pytest)
"""
import datetime as dt
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import evaluate_v as ev  # noqa: E402

UTC = dt.timezone.utc


def mk_episode(scenario="A1", src=ev.ATTACKER_IP, target=ev.TARGET_IP,
               start="2026-11-01T12:00:00+00:00", end="2026-11-01T12:00:10+00:00",
               status="executed", effect_status=None, technique="T0836"):
    eid = {"A1": "A1_T0836_001", "A2": "A2_T0888_001", "A3": "A3_T0846.001_001",
           "A4": "A4_T0816_001", "A5": "A5_T0816_001", "A6": "A6_T0843_001",
           "V2.1": "V21_T0836_001", "V2.2": "V22_T0893_001", "V2.3": "V23_T0821_001",
           "V2.4": "V24_T0836_001", "V2.5": "V25_T0836_001"}[scenario]
    rec = {"episode_id": eid, "mitre_technique_id": technique, "status": status,
           "start_ts": start, "end_ts": end, "source_ip": src, "target": target,
           "parameters": {"effect_status": effect_status} if effect_status else {}}
    return ev.Episode(rec, "campaign_test")


class TestB2Predicates(unittest.TestCase):
    """Minden B2-predikatum: egy pozitiv es egy negativ eset (protokoll 5.2)."""

    def test_a1_v21_v25_write_single(self):
        pos = {"kind": "modbus", "func": "WRITE_SINGLE_REGISTER", "pdu_type": "REQ"}
        neg = {"kind": "modbus", "func": "READ_HOLDING_REGISTERS", "pdu_type": "REQ"}
        neg2 = {"kind": "modbus", "func": "WRITE_SINGLE_REGISTER", "pdu_type": "RESP"}
        for s in ("A1", "V2.1", "V2.5"):
            self.assertTrue(ev.B2_PREDICATES[s](pos), s)
            self.assertFalse(ev.B2_PREDICATES[s](neg), s)
            self.assertFalse(ev.B2_PREDICATES[s](neg2), s)

    def test_v24_write_multiple(self):
        pos = {"kind": "modbus", "func": "WRITE_MULTIPLE_REGISTERS", "pdu_type": "REQ"}
        neg = {"kind": "modbus", "func": "WRITE_SINGLE_REGISTER", "pdu_type": "REQ"}
        self.assertTrue(ev.B2_PREDICATES["V2.4"](pos))
        self.assertFalse(ev.B2_PREDICATES["V2.4"](neg))

    def test_a2_reads(self):
        for f in ev.READ_FUNCS:
            self.assertTrue(ev.B2_PREDICATES["A2"]({"kind": "modbus", "func": f, "pdu_type": "REQ"}), f)
        self.assertFalse(ev.B2_PREDICATES["A2"]({"kind": "modbus", "func": "WRITE_SINGLE_REGISTER", "pdu_type": "REQ"}))
        self.assertFalse(ev.B2_PREDICATES["A2"]({"kind": "modbus", "func": "READ_COILS", "pdu_type": "RESP"}))

    def test_a3_conn_ports(self):
        self.assertTrue(ev.B2_PREDICATES["A3"]({"kind": "conn", "dest_port": 502}))
        self.assertTrue(ev.B2_PREDICATES["A3"]({"kind": "conn", "dest_port": 102}))
        self.assertFalse(ev.B2_PREDICATES["A3"]({"kind": "conn", "dest_port": 80}))
        self.assertFalse(ev.B2_PREDICATES["A3"]({"kind": "modbus", "dest_port": 502}))

    def test_a4_plc_stop(self):
        self.assertTrue(ev.B2_PREDICATES["A4"]({"kind": "s7comm", "function_name": "PLC Stop"}))
        self.assertFalse(ev.B2_PREDICATES["A4"]({"kind": "s7comm", "function_name": "Read Variable"}))

    def test_a5_http_stop(self):
        self.assertTrue(ev.B2_PREDICATES["A5"]({"kind": "http", "uri": "/stop_plc"}))
        self.assertFalse(ev.B2_PREDICATES["A5"]({"kind": "http", "uri": "/login"}))

    def test_a6_download_or_s7ud(self):
        for fc in (0x1a, 0x1b, 0x1c):
            self.assertTrue(ev.B2_PREDICATES["A6"]({"kind": "s7comm", "func_code": fc}), hex(fc))
        self.assertTrue(ev.B2_PREDICATES["A6"]({"kind": "s7ud"}))
        self.assertFalse(ev.B2_PREDICATES["A6"]({"kind": "s7comm", "func_code": 0x04}))

    def test_v22_read_variable(self):
        self.assertTrue(ev.B2_PREDICATES["V2.2"]({"kind": "s7comm", "function_name": "Read Variable"}))
        self.assertFalse(ev.B2_PREDICATES["V2.2"]({"kind": "s7comm", "function_name": "Write Variable"}))

    def test_v23_write_variable(self):
        self.assertTrue(ev.B2_PREDICATES["V2.3"]({"kind": "s7comm", "function_name": "Write Variable"}))
        self.assertFalse(ev.B2_PREDICATES["V2.3"]({"kind": "s7comm", "function_name": "Read Variable"}))


class TestB1Window(unittest.TestCase):
    """B1: ablakhatarok ([start-1s, end+5s]), forras/cel, A.3 /24."""

    def setUp(self):
        self.ep = mk_episode("A1")  # [11:59:59, 12:00:15]

    def test_boundaries_inclusive(self):
        lo, hi = self.ep.window()
        self.assertEqual(lo, ev.parse_ts("2026-11-01T11:59:59+00:00"))
        self.assertEqual(hi, ev.parse_ts("2026-11-01T12:00:15+00:00"))
        self.assertTrue(self.ep.b1_connect(ev.ATTACKER_IP, ev.TARGET_IP, lo))         # also hataron bent
        self.assertTrue(self.ep.b1_connect(ev.ATTACKER_IP, ev.TARGET_IP, hi))         # felso hataron bent
        self.assertFalse(self.ep.b1_connect(ev.ATTACKER_IP, ev.TARGET_IP,
                                            lo - dt.timedelta(microseconds=1)))
        self.assertFalse(self.ep.b1_connect(ev.ATTACKER_IP, ev.TARGET_IP,
                                            hi + dt.timedelta(microseconds=1)))

    def test_wrong_src_or_dest(self):
        mid = ev.parse_ts("2026-11-01T12:00:05+00:00")
        self.assertFalse(self.ep.b1_connect(ev.BENIGN_IP, ev.TARGET_IP, mid))         # rossz forras
        self.assertFalse(self.ep.b1_connect(ev.ATTACKER_IP, "192.168.1.200", mid))    # rossz cel

    def test_a5_url_target_ip_extraction(self):
        # Az A.5 target-je teljes URL ('http://192.168.1.100:8080'); a B1-hez az
        # IPv4-et kell kinyerni, kulonben a dest_ip==target sosem illeszkedik.
        ep5 = ev.Episode({"episode_id": "A5_T0816_001", "mitre_technique_id": "T0816",
                          "status": "executed_effect", "start_ts": "2026-11-01T12:00:00+00:00",
                          "end_ts": "2026-11-01T12:00:10+00:00", "source_ip": ev.ATTACKER_IP,
                          "target": "http://192.168.1.100:8080",
                          "parameters": {"effect_status": "executed_effect"}}, "c")
        self.assertEqual(ep5.target, "192.168.1.100")
        mid = ev.parse_ts("2026-11-01T12:00:05+00:00")
        self.assertTrue(ep5.b1_connect(ev.ATTACKER_IP, "192.168.1.100", mid))

    def test_as_int_hex_and_decimal(self):
        self.assertEqual(ev._as_int("0x1a"), 0x1a)
        self.assertEqual(ev._as_int(26), 26)
        self.assertIsNone(ev._as_int(None))
        self.assertIsNone(ev._as_int("PLC Stop"))

    def test_a3_subnet_target(self):
        ep3 = mk_episode("A3", technique="T0846.001")
        mid = ev.parse_ts("2026-11-01T12:00:05+00:00")
        self.assertTrue(ep3.b1_connect(ev.ATTACKER_IP, "192.168.1.7", mid))           # /24 barmelyik
        self.assertTrue(ep3.b1_connect(ev.ATTACKER_IP, "192.168.1.254", mid))
        self.assertFalse(ep3.b1_connect(ev.ATTACKER_IP, "192.168.2.7", mid))          # mas halo


class TestExclusions(unittest.TestCase):
    """5.5/D12: error-status es ABORTED kizaras; kizart ablak maszkol FP-t."""

    def test_error_status_episode_flagged(self):
        ep = mk_episode("A1", status="error")
        self.assertEqual(ep.status, "error")   # az aggregate() status != 'error' szuri

    def test_fp_masking_and_denominator(self):
        ep = mk_episode("A1")  # [11:59:59, 12:00:15]
        lo, hi = ep.window()
        inside = lo + dt.timedelta(seconds=3)
        outside = hi + dt.timedelta(seconds=60)
        # FP alert: ketto a benign (.51) sessionon, egy bent (maszkolt), egy kint (FP)
        alerts = [
            {"ts": inside, "src_ip": ev.TARGET_IP, "dest_ip": ev.BENIGN_IP, "dest_port": 1, "sid": ev.FP_SID, "signature": "x", "category": ""},
            {"ts": outside, "src_ip": ev.TARGET_IP, "dest_ip": ev.BENIGN_IP, "dest_port": 1, "sid": ev.FP_SID, "signature": "x", "category": ""},
            {"ts": outside, "src_ip": ev.ATTACKER_IP, "dest_ip": ev.BENIGN_IP, "dest_port": 1, "sid": ev.FP_SID, "signature": "x", "category": ""},  # .50 -> nem benign-FP
        ]
        benign_reqs = [inside, outside, outside + dt.timedelta(seconds=1)]
        bstart = ev.parse_ts("2026-11-01T11:59:00+00:00")
        bstop = ev.parse_ts("2026-11-01T12:05:00+00:00")
        fp = ev.compute_fp(alerts, [ep], [], benign_reqs, bstart, bstop)
        self.assertEqual(fp["fp_count"], 1)                      # csak a kint-benign-.51
        self.assertEqual(fp["denominator_benign_requests"], 2)  # az inside maszkolva
        # benign-ido: 360 s total minusz az epizod-ablak (16 s) atfedese
        self.assertAlmostEqual(fp["denominator_benign_time_s"], 360.0 - 16.0, places=3)

    def test_aborted_manifest(self):
        self.assertEqual(str("ABORTED").upper(), "ABORTED")  # load_campaign ezt nezi


class TestBetaQuantiles(unittest.TestCase):
    """D11: Jeffreys Beta(k+1/2,n-k+1/2) ismert ertek (k=20,n=20) + stdlib==scipy."""

    def test_known_k20_n20(self):
        s = ev.beta_summary(20, 20, True)  # Beta(20.5, 0.5)
        self.assertAlmostEqual(s["mean"], 20.5 / 21.0, places=10)
        self.assertAlmostEqual(s["median"], 0.988831, places=5)
        self.assertAlmostEqual(s["ci_lo"], 0.883361, places=5)
        self.assertAlmostEqual(s["ci_hi"], 0.999976, places=5)

    def test_uniform_prior_k0_n0_none(self):
        s = ev.beta_summary(0, 0, True)
        self.assertIsNone(s["median"])

    def test_stdlib_matches_backend(self):
        for (k, n) in [(20, 20), (0, 20), (10, 20), (3, 3), (1, 7)]:
            a, b = k + 0.5, n - k + 0.5
            for p in (0.025, 0.5, 0.975):
                self.assertAlmostEqual(ev._betaincinv_stdlib(a, b, p),
                                       ev.beta_ppf(a, b, p), places=5,
                                       msg=f"k={k} n={n} p={p}")

    def test_betainc_identity_and_symmetry(self):
        for x in (0.1, 0.37, 0.5, 0.9):
            self.assertAlmostEqual(ev.betainc(1, 1, x), x, places=9)   # I_x(1,1)=x
        self.assertAlmostEqual(ev.beta_ppf(0.5, 0.5, 0.5), 0.5, places=9)  # szimmetria


class TestCohenKappa(unittest.TestCase):
    """5.3: sulyozatlan Cohen-kappa ismert 2x2 peldara (po=0.7, pe=0.5 -> 0.4)."""

    def test_known_example(self):
        a = [1] * 20 + [1] * 5 + [0] * 10 + [0] * 15
        b = [1] * 20 + [0] * 5 + [1] * 10 + [0] * 15
        self.assertAlmostEqual(ev.cohen_kappa(a, b), 0.4, places=9)

    def test_perfect_and_empty(self):
        self.assertEqual(ev.cohen_kappa([1, 0, 1], [1, 0, 1]), 1.0)
        self.assertIsNone(ev.cohen_kappa([], []))


class TestKappaEdge(unittest.TestCase):
    """E-39/1: a Cohen-kappa hatareset (p_e=1 -> null) + degeneracio-jelzes."""

    def test_pe_one_both_constant_null(self):
        # mindket jelolo konstans (minden technikara IGEN) -> p_e=1 -> null
        d = ev.cohen_kappa_detail([1, 1, 1], [1, 1, 1])
        self.assertIsNone(d["kappa"])
        self.assertAlmostEqual(d["p_observed"], 1.0, places=9)
        self.assertAlmostEqual(d["p_expected"], 1.0, places=9)
        self.assertIn("nem definialt", d["kappa_note"])
        self.assertIsNone(ev.cohen_kappa([1, 1, 1], [1, 1, 1]))

    def test_one_rater_constant_pe_lt1_zero_with_note(self):
        # V1-eset: MITRE csupa IGEN (konstans), nalunk 4/5 -> p_o=0.8, p_e=0.8, kappa=0
        ours = [1, 1, 0, 1, 1]
        mitre = [1, 1, 1, 1, 1]
        d = ev.cohen_kappa_detail(ours, mitre)
        self.assertAlmostEqual(d["p_observed"], 0.8, places=9)
        self.assertAlmostEqual(d["p_expected"], 0.8, places=9)
        self.assertAlmostEqual(d["kappa"], 0.0, places=9)
        self.assertIn("degeneralt", d["kappa_note"])

    def test_normal_case_unchanged(self):
        a = [1] * 20 + [1] * 5 + [0] * 10 + [0] * 15
        b = [1] * 20 + [0] * 5 + [1] * 10 + [0] * 15
        d = ev.cohen_kappa_detail(a, b)
        self.assertAlmostEqual(d["kappa"], 0.4, places=9)
        self.assertIsNone(d["kappa_note"])


class TestC0Source(unittest.TestCase):
    """#84: --c0-source replay a replay_c0/eve.json-bol olvassa a C0 alerteket."""

    @staticmethod
    def _alert(sid):
        return ('{"event_type":"alert","timestamp":"2026-11-01T12:00:00.000000+0000",'
                '"src_ip":"192.168.1.100","dest_ip":"192.168.1.51","dest_port":502,'
                f'"alert":{{"signature_id":{sid},"signature":"X","category":"Y"}}}}')

    def test_replay_source_reads_replay_dir(self):
        import tempfile
        from pathlib import Path as _P
        with tempfile.TemporaryDirectory() as td:
            d = _P(td)
            (d / "eve_slice.json").write_text(self._alert(2250008) + "\n", encoding="utf-8")
            (d / "replay_c0").mkdir()
            (d / "replay_c0" / "eve.json").write_text(
                self._alert(2250008) + "\n" + self._alert(2250008) + "\n", encoding="utf-8")
            live = ev.load_suricata_alerts(d, "live")
            rep = ev.load_suricata_alerts(d, "replay")
            self.assertEqual(len(live), 1)
            self.assertEqual(len(rep), 2)
            self.assertTrue(all(a["source"] == "suricata" for a in rep))

    def test_replay_missing_dir_empty(self):
        import tempfile
        from pathlib import Path as _P
        with tempfile.TemporaryDirectory() as td:
            d = _P(td)
            (d / "eve_slice.json").write_text(self._alert(2250008) + "\n", encoding="utf-8")
            self.assertEqual(ev.load_suricata_alerts(d, "replay"), [])


class TestE39Sensitivity(unittest.TestCase):
    """E-39: a --sensitivity-exclude hatasa a technika x config LÁTTA k/n-re."""

    @staticmethod
    def _row(cid, eid, tech, cfg, seen):
        return {"campaign_id": cid, "episode_id": eid, "technique": tech,
                "config": cfg, "seen": seen, "category": "Telemetry", "scenario": "V2.1"}

    def test_exclusion_changes_kn(self):
        cls = [self._row("c", "e1", "T0836", "C1", True),
               self._row("c", "e2", "T0836", "C1", True),
               self._row("c", "e3", "T0836", "C1", True),
               self._row("c", "bad", "T0836", "C1", False)]
        res = ev.e39_analysis(cls, {("c", "bad")})
        row = next(r for r in res["by_technique_config"] if r["config"] == "C1")
        self.assertEqual((row["main"]["k"], row["main"]["n"]), (3, 4))
        self.assertEqual((row["sensitivity"]["k"], row["sensitivity"]["n"]), (3, 3))
        self.assertTrue(row["changed"])
        self.assertEqual(res["excluded"], ["c:bad"])
        self.assertEqual(res["excluded_count"], 1)

    def test_exclusion_noop_when_id_absent(self):
        cls = [self._row("c", "e1", "T0836", "C1", True),
               self._row("c", "e2", "T0836", "C1", False)]
        res = ev.e39_analysis(cls, {("c", "nincs_ilyen")})
        row = next(r for r in res["by_technique_config"] if r["config"] == "C1")
        self.assertEqual((row["main"]["k"], row["main"]["n"]),
                         (row["sensitivity"]["k"], row["sensitivity"]["n"]))
        self.assertFalse(row["changed"])

    def test_exclusion_scoped_by_campaign(self):
        # ugyanaz az episode_id ket kampanyban: csak a megadott kampanybol zar ki
        cls = [self._row("c1", "e_dup", "T0836", "C1", False),
               self._row("c2", "e_dup", "T0836", "C1", True)]
        res = ev.e39_analysis(cls, {("c1", "e_dup")})
        row = next(r for r in res["by_technique_config"] if r["config"] == "C1")
        self.assertEqual((row["main"]["k"], row["main"]["n"]), (1, 2))
        self.assertEqual((row["sensitivity"]["k"], row["sensitivity"]["n"]), (1, 1))


if __name__ == "__main__":
    unittest.main(verbosity=2)
