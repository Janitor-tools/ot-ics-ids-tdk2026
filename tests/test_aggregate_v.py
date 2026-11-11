#!/usr/bin/env python3
"""tests/test_aggregate_v.py -- aggregate_v.py egysegtesztek (prereg-v1.1, E-28).

Szintetikus eredmeny_*.json-okkal (az evaluate_v.py kimeneti semaja), ideiglenes
fajlokba irva. Lefedi:
  - 1 es 3 kampany osszevonasa (epizod-pool: k=sum, n=sum; prereg 5.4);
  - a (a) kampanyonkenti + (d) C1 technika-pool egyezese a forrassal (4. pont);
  - degeneralt Cohen-kappa (konstans MITRE-oldal -> kappa=0 + nyers arany);
  - eltero epizodszam es error-os epizod kezelese (az error mar a forrasban kizart:
    n_known nem tartalmazza; a NA sem szamit a k/n-be);
  - V1/V2 szetvalasztas (a T0836 nem vonodik ossze a ket varians kozott).
Futtatas:  python3 -m unittest tests.test_aggregate_v
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import evaluate_v as ev   # noqa: E402
import aggregate_v as ag  # noqa: E402


# ------------------------------------------------------------------ builder
def mk_result(campaign_id, scen_cfg_kn, mitre_map, out_dir):
    """Szintetikus eredmeny_*.json egy kampanyra, a valodi semaval.

    scen_cfg_kn: {(scenario, config): (k, n, na)}  -- mar error-kizart k/n.
    mitre_map:   {technique: bool}                 -- a D13 MITRE-oldala.
    A posteriort, a tech_seen_c1-et es az external_signal-t a valodi fuggvenyekkel
    szamolja, hogy a forras es az aggregate konzisztens legyen (4. pont).
    """
    secondary = []
    c1_tech = {}  # technique -> [true, known] (C1)
    for (scn, cfg), (k, n, na) in sorted(scen_cfg_kn.items()):
        pj = ev.beta_summary(k, n, True)
        pu = ev.beta_summary(k, n, False)
        secondary.append({
            "n_rows": n + na, "n_known": n, "k_seen": k, "n_na": na,
            "category_dist": {"Telemetry": k} if k else {},
            "posterior_jeffreys": pj, "posterior_uniform": pu,
            "campaign_id": campaign_id, "scenario": scn, "config": cfg,
        })
        if cfg == "C1":
            t = ag.technique_of(scn)
            acc = c1_tech.setdefault(t, [0, 0])
            acc[0] += k
            acc[1] += n
    tech_seen_c1 = {t: {"true": v[0], "known": v[1]} for t, v in c1_tech.items()}

    # external_signal: technikankent ours = (C1 true>0); kappa a forras oldalan is
    ours_bits, theirs_bits, rows = [], [], []
    for t in sorted(set(tech_seen_c1) | set(mitre_map)):
        d = tech_seen_c1.get(t, {"true": 0, "known": 0})
        ours = (d["true"] > 0) if d["known"] > 0 else None
        mt = mitre_map.get(t)
        rows.append({"technique": t, "ours_c1_seen": ours, "mitre_network_analytic": mt})
        if ours is None or mt is None:
            continue
        ours_bits.append(1 if ours else 0)
        theirs_bits.append(1 if mt else 0)
    ext = {"rows": rows, "n_paired": len(ours_bits),
           "cohen_kappa_unweighted": ev.cohen_kappa(ours_bits, theirs_bits) if ours_bits else None}

    fp_per_campaign = {campaign_id: {
        "fp_count": 100, "sid": ev.FP_SID, "denominator_benign_requests": 200,
        "denominator_benign_time_s": 3600.0, "fp_per_request": 0.5, "fp_per_hour": 100.0,
    }}

    doc = {"meta": {"prereg": "v1.1", "campaigns": [campaign_id]},
           "aggregate": {"secondary": secondary, "fp_per_campaign": fp_per_campaign,
                         "external_signal": ext, "tech_seen_c1": tech_seen_c1}}
    p = Path(out_dir) / f"eredmenyek_{campaign_id}.json"
    p.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
    return p


# V1 "teljes" szcenario-konfig kn egy kampanyra (a .md peldahoz hasonlo aranyokkal)
def v1_campaign_kn(k_a4c0=20):
    return {
        ("A1", "C0"): (20, 20, 0), ("A1", "C1"): (20, 20, 0),
        ("A2", "C0"): (20, 20, 0), ("A2", "C1"): (20, 20, 0),
        ("A3", "C0"): (0, 3, 0),   ("A3", "C1"): (3, 3, 0),     # A3 C0 raw/C1 -> C0 nincs
        ("A4", "C0"): (k_a4c0, 20, 0), ("A4", "C1"): (20, 20, 0),
        ("A5", "C0"): (0, 3, 0),   ("A5", "C1"): (3, 3, 0),     # A5 C0 None; C1 http
        ("A6", "C0"): (0, 3, 0),   ("A6", "C1"): (0, 3, 0),
    }


V1_MITRE_ALL_TRUE = {"T0836": True, "T0888": True, "T0846.001": True,
                     "T0816": True, "T0843": True}


class TestSingleCampaign(unittest.TestCase):
    """1 kampany: per-campaign == forras; T0816 = A4 u A5 pool; minden egyezes PASS."""

    def test_single_equivalence_and_t0816_pool(self):
        with tempfile.TemporaryDirectory() as td:
            p = mk_result("campaign_X_V1_s1", v1_campaign_kn(), V1_MITRE_ALL_TRUE, td)
            data = ag.load_results([p])
            result = ag.build_result(data)
            per_camp = result["per_campaign"]
            ext = result["external_signal"]

            # T0816 (A4 u A5) pool: C1 = 23/23, C0 = 20/23
            pooled = {(r["technique"], r["config"]): r
                      for r in result["pooled_by_technique"]["V1"]}
            self.assertEqual((pooled[("T0816", "C1")]["k_seen"],
                              pooled[("T0816", "C1")]["n_known"]), (23, 23))
            self.assertEqual((pooled[("T0816", "C0")]["k_seen"],
                              pooled[("T0816", "C0")]["n_known"]), (20, 23))
            self.assertEqual(sorted(pooled[("T0816", "C1")]["scenarios"]), ["A4", "A5"])
            # a pool-posterior == ev.beta_summary(k, n) (prereg modszer)
            exp = ev.beta_summary(20, 23, True)
            self.assertAlmostEqual(pooled[("T0816", "C0")]["posterior_jeffreys"]["median"],
                                   exp["median"], places=12)

            # 4. pont: minden egyezes PASS
            lines = ag.verify_equivalence(data, per_camp, ext)
            self.assertIn("==> OSSZESEN: PASS", lines[-1], msg="\n".join(lines))

    def test_t0816_k_campaigns_is_one(self):
        with tempfile.TemporaryDirectory() as td:
            p = mk_result("campaign_X_V1_s1", v1_campaign_kn(), V1_MITRE_ALL_TRUE, td)
            data = ag.load_results([p])
            result = ag.build_result(data)
            pooled = {(r["technique"], r["config"]): r
                      for r in result["pooled_by_technique"]["V1"]}
            self.assertEqual(pooled[("T0836", "C0")]["k_campaigns"], 1)


class TestThreeCampaigns(unittest.TestCase):
    """3 kampany, eltero epizodszam: pool k = sum, n = sum; posterior = beta(sum)."""

    def test_pool_sums_and_posterior(self):
        with tempfile.TemporaryDirectory() as td:
            # eltero A4 C0 LÁTTA kampanyonkent (20, 18, 19) + eltero A1 n (error kizart)
            c1 = mk_result("campaign_A_V1_s1", v1_campaign_kn(k_a4c0=20), V1_MITRE_ALL_TRUE, td)
            kn2 = v1_campaign_kn(k_a4c0=18)
            kn2[("A1", "C0")] = (18, 18, 2)   # 2 error-os epizod mar kizarva (n=18), 2 NA->na
            kn2[("A1", "C1")] = (18, 18, 2)
            c2 = mk_result("campaign_B_V1_s2", kn2, V1_MITRE_ALL_TRUE, td)
            c3 = mk_result("campaign_C_V1_s3", v1_campaign_kn(k_a4c0=19), V1_MITRE_ALL_TRUE, td)
            data = ag.load_results([c1, c2, c3])
            result = ag.build_result(data)
            pooled = {(r["technique"], r["config"]): r
                      for r in result["pooled_by_technique"]["V1"]}

            # T0836 = A1: C0 k = 20+18+19? (nem: A1 C0 LÁTTA = 20,18,20) -- ellenorizzuk n-t
            # A1 n_known: 20 + 18 + 20 = 58 (a 2 error a 2. kampanyban kizarva)
            self.assertEqual(pooled[("T0836", "C0")]["n_known"], 20 + 18 + 20)
            # T0816 = A4 u A5: C0 k = (20+0)+(18+0)+(19+0) = 57 ; n = (20+3)*3 = 69
            self.assertEqual(pooled[("T0816", "C0")]["k_seen"], 20 + 18 + 19)
            self.assertEqual(pooled[("T0816", "C0")]["n_known"], 69)
            self.assertEqual(pooled[("T0816", "C0")]["k_campaigns"], 3)
            exp = ev.beta_summary(57, 69, True)
            self.assertAlmostEqual(pooled[("T0816", "C0")]["posterior_jeffreys"]["median"],
                                   exp["median"], places=12)

    def test_fp_pooled_sums(self):
        with tempfile.TemporaryDirectory() as td:
            ps = [mk_result(f"campaign_{i}_V1_s{i}", v1_campaign_kn(), V1_MITRE_ALL_TRUE, td)
                  for i in (1, 2, 3)]
            data = ag.load_results(ps)
            result = ag.build_result(data)
            fp = result["fp_pooled"]["V1"]
            self.assertEqual(fp["fp_count"], 300)                  # 3 x 100
            self.assertEqual(fp["denominator_benign_requests"], 600)
            self.assertAlmostEqual(fp["denominator_benign_time_s"], 10800.0)
            self.assertAlmostEqual(fp["fp_per_request"], 300 / 600)
            self.assertAlmostEqual(fp["fp_per_hour"], 300 / (10800 / 3600))


class TestDegenerateKappa(unittest.TestCase):
    """D13 (5.3): konstans MITRE-oldal (csupa IGEN) -> kappa=0 + nyers arany + ok."""

    def test_all_mitre_true_kappa_zero(self):
        with tempfile.TemporaryDirectory() as td:
            p = mk_result("campaign_X_V1_s1", v1_campaign_kn(), V1_MITRE_ALL_TRUE, td)
            data = ag.load_results([p])
            ext = ag.build_result(data)["external_signal"]
            self.assertEqual(ext["cohen_kappa_unweighted"], 0.0)
            # ours: T0843 NEM, a tobbi LÁTTA -> 4/5 egyezes
            self.assertEqual(ext["raw_agreement_frac"], "4/5")
            self.assertAlmostEqual(ext["raw_agreement"], 0.8)
            self.assertIsNotNone(ext["degeneracy_reason"])
            self.assertIn("MITRE", ext["degeneracy_reason"])

    def test_non_degenerate_kappa(self):
        with tempfile.TemporaryDirectory() as td:
            # T0843 MITRE=NEM is -> van variancia mindket oldalon; tokeletes egyezes
            mitre = dict(V1_MITRE_ALL_TRUE, **{"T0843": False})
            p = mk_result("campaign_X_V1_s1", v1_campaign_kn(), mitre, td)
            data = ag.load_results([p])
            ext = ag.build_result(data)["external_signal"]
            # ours: T0843 NEM, tobbi LÁTTA; mitre: T0843 NEM, tobbi IGEN -> tokeletes
            self.assertEqual(ext["cohen_kappa_unweighted"], 1.0)
            self.assertEqual(ext["raw_agreement_frac"], "5/5")


class TestErrorAndNA(unittest.TestCase):
    """Error-os epizod (mar a forrasban kizart, n_known nem tartalmazza) + NA kezelese."""

    def test_na_not_counted_in_kn(self):
        with tempfile.TemporaryDirectory() as td:
            kn = v1_campaign_kn()
            kn[("A2", "C0")] = (15, 15, 5)   # 5 NA (nincs begyujtve) -> n_known=15 marad
            p = mk_result("campaign_X_V1_s1", kn, V1_MITRE_ALL_TRUE, td)
            data = ag.load_results([p])
            pooled = {(r["technique"], r["config"]): r
                      for r in ag.build_result(data)["pooled_by_technique"]["V1"]}
            self.assertEqual(pooled[("T0888", "C0")]["n_known"], 15)
            self.assertEqual(pooled[("T0888", "C0")]["n_na"], 5)

    def test_error_excluded_upstream_reduces_n(self):
        with tempfile.TemporaryDirectory() as td:
            kn = v1_campaign_kn()
            kn[("A1", "C0")] = (17, 17, 0)   # 3 error kizarva upstream -> n=17
            kn[("A1", "C1")] = (17, 17, 0)
            p = mk_result("campaign_X_V1_s1", kn, V1_MITRE_ALL_TRUE, td)
            data = ag.load_results([p])
            pooled = {(r["technique"], r["config"]): r
                      for r in ag.build_result(data)["pooled_by_technique"]["V1"]}
            self.assertEqual(pooled[("T0836", "C0")]["n_known"], 17)


class TestVariantSeparation(unittest.TestCase):
    """A V2 kampany nem vonodik ossze a V1-gyel (T0836 mindketton szerepel)."""

    def test_v1_v2_kept_separate(self):
        with tempfile.TemporaryDirectory() as td:
            v1 = mk_result("campaign_A_V1_s1", v1_campaign_kn(), V1_MITRE_ALL_TRUE, td)
            v2kn = {("V2.1", "C0"): (20, 20, 0), ("V2.1", "C1"): (20, 20, 0),
                    ("V2.4", "C0"): (10, 20, 0), ("V2.4", "C1"): (20, 20, 0),
                    ("V2.2", "C0"): (20, 20, 0), ("V2.2", "C1"): (20, 20, 0),
                    ("V2.3", "C0"): (20, 20, 0), ("V2.3", "C1"): (20, 20, 0),
                    ("V2.5", "C0"): (20, 20, 0), ("V2.5", "C1"): (20, 20, 0)}
            v2mitre = {"T0836": True, "T0893": True, "T0821": False}
            v2 = mk_result("campaign_B_V2_s1", v2kn, v2mitre, td)
            data = ag.load_results([v1, v2])
            result = ag.build_result(data)

            self.assertEqual(set(result["pooled_by_technique"].keys()), {"V1", "V2"})
            v1p = {(r["technique"], r["config"]): r for r in result["pooled_by_technique"]["V1"]}
            v2p = {(r["technique"], r["config"]): r for r in result["pooled_by_technique"]["V2"]}
            # T0836 V1 = A1 (20/20); T0836 V2 = V2.1+V2.4+V2.5 (60/60 C1) -- KULON
            self.assertEqual(v1p[("T0836", "C0")]["n_known"], 20)
            self.assertEqual(v2p[("T0836", "C1")]["n_known"], 60)
            self.assertEqual(sorted(v2p[("T0836", "C1")]["scenarios"]), ["V2.1", "V2.4", "V2.5"])
            # FP variansonkent kulon
            self.assertIn("V1", result["fp_pooled"])
            self.assertIn("V2", result["fp_pooled"])

    def test_d13_combines_variants(self):
        """A D13 (d) a V1+V2 egyedi technikait EGYUTT ertelmezi (prereg 5.3/NYK-8)."""
        with tempfile.TemporaryDirectory() as td:
            v1 = mk_result("campaign_A_V1_s1", v1_campaign_kn(), V1_MITRE_ALL_TRUE, td)
            v2kn = {("V2.2", "C0"): (20, 20, 0), ("V2.2", "C1"): (20, 20, 0),
                    ("V2.3", "C0"): (0, 20, 0), ("V2.3", "C1"): (0, 20, 0)}
            v2 = mk_result("campaign_B_V2_s1", v2kn, {"T0893": True, "T0821": True}, td)
            data = ag.load_results([v1, v2])
            ext = ag.build_result(data)["external_signal"]
            techs = {r["technique"] for r in ext["rows"]}
            # V1 (5) + V2 egyedi (T0893, T0821) = 7 technika
            self.assertEqual(techs, {"T0836", "T0888", "T0846.001", "T0816", "T0843",
                                     "T0893", "T0821"})


class TestKappaNullAndE39(unittest.TestCase):
    """1): p_e=1 -> null kappa; 2): E-39 pool_e39 osszegzes variansonkent."""

    def test_pool_external_null_when_both_constant(self):
        with tempfile.TemporaryDirectory() as td:
            # minden technika LÁTTA (k=n) es minden MITRE IGEN -> p_e=1 -> kappa null
            scen = {("V2.2", "C0"): (20, 20, 0), ("V2.2", "C1"): (20, 20, 0),
                    ("V2.3", "C0"): (20, 20, 0), ("V2.3", "C1"): (20, 20, 0)}
            p = mk_result("campaign_X_V2_s1", scen, {"T0893": True, "T0821": True}, td)
            ext = ag.build_result(ag.load_results([p]))["external_signal"]
            self.assertIsNone(ext["cohen_kappa_unweighted"])
            self.assertIn("nem definialt", ext["kappa_note"])
            self.assertAlmostEqual(ext["p_expected"], 1.0)
            self.assertAlmostEqual(ext["p_observed"], 1.0)

    def test_pool_e39_sums_across_campaigns(self):
        src = [
            {"variant": "V1", "technique": "T0836", "config": "C1",
             "main_k": 20, "main_n": 20, "sens_k": 19, "sens_n": 19},
            {"variant": "V1", "technique": "T0836", "config": "C1",
             "main_k": 19, "main_n": 19, "sens_k": 18, "sens_n": 18},
            {"variant": "V1", "technique": "T0888", "config": "C1",
             "main_k": 20, "main_n": 20, "sens_k": 20, "sens_n": 20},
            {"variant": "V2", "technique": "T0836", "config": "C1",
             "main_k": 51, "main_n": 51, "sens_k": 48, "sens_n": 48},
        ]
        rows = ag.pool_e39(src, "V1")
        t = next(r for r in rows if r["technique"] == "T0836")
        self.assertEqual((t["main"]["k"], t["main"]["n"]), (39, 39))
        self.assertEqual((t["sensitivity"]["k"], t["sensitivity"]["n"]), (37, 37))
        self.assertTrue(t["changed"])
        t2 = next(r for r in rows if r["technique"] == "T0888")
        self.assertFalse(t2["changed"])
        # a V2 sor NEM keveredik a V1-be
        self.assertTrue(all(r["main"]["n"] <= 39 for r in rows))


if __name__ == "__main__":
    unittest.main(verbosity=2)
