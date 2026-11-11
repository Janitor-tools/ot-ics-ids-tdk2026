#!/usr/bin/env python3
"""TDK-2026 "A) gyorsjavitasok" -- egzakt intervallumok a 2026-08-22-i kampanyra.

Kizarolag a results/campaign_2026-08-22_metrics.json szamlaloibol szamol:
  - ketoldalu 95% Clopper-Pearson intervallum (Recall, Precision),
  - Poisson felso korlat 0 megfigyelt FP-re (egy- es ketoldalu 95%), riasztas/ora,
  - makro-recall pontbecsles.
Futtatas: python scripts/tdk2026_ci_fix.py > results/tdk2026_ci_fix.txt
"""
import json
from datetime import datetime
from pathlib import Path

import scipy
from scipy.stats import beta, chi2

ALPHA = 0.05
METRICS = Path(__file__).resolve().parent.parent / "results" / "campaign_2026-08-22_metrics.json"


def clopper_pearson(k: int, n: int, alpha: float = ALPHA) -> tuple[float, float]:
    lo = 0.0 if k == 0 else beta.ppf(alpha / 2, k, n - k + 1)
    hi = 1.0 if k == n else beta.ppf(1 - alpha / 2, k + 1, n - k)
    return float(lo), float(hi)


def poisson_upper_zero(conf_tail: float) -> float:
    """Egzakt Poisson felso korlat 0 esemenyre: chi2(conf_tail; 2) / 2."""
    return float(chi2.ppf(conf_tail, 2) / 2)


def main() -> None:
    m = json.loads(METRICS.read_text(encoding="utf-8"))
    t = m["techniques"]
    print(f"scipy {scipy.__version__}; forras: {METRICS.name}")

    t_start = datetime.fromisoformat(m["campaign"]["start"])
    t_end = datetime.fromisoformat(m["campaign"]["end"])
    hours_json = (t_end - t_start).total_seconds() / 3600
    hours = 2.982
    print(f"Kampanyhossz a JSON start/end alapjan: {hours_json:.4f} h; a szamitasban hasznalt T = {hours} h")

    print("\na) Ketoldalu 95% Clopper-Pearson intervallum")
    t0836_tp, t0836_n = t["T0836"]["tp"], t["T0836"]["n_effective"]
    t0816_tp, t0816_n = t["T0816"]["tp"], t["T0816"]["n_effective"]
    t0816_a4 = 20  # A.4 epizodok szama (n_effective 23 = A.4 20 + A.5 3)
    cases = [
        ("Recall T0836 (A.1)", t0836_tp, t0836_n),
        ("Recall T0816 csak A.4", t0816_a4, t0816_a4),
        ("Recall T0816 pooled A.4+A.5", t0816_tp, t0816_n),
        ("Precision T0836 finomitott", t0836_tp, t0836_tp + t["T0836"]["refined"]["fp_count"]),
    ]
    for label, k, n in cases:
        lo, hi = clopper_pearson(k, n)
        print(f"  {label:32s} {k}/{n} = {k / n:.3f}  CI95 = [{lo:.3f}; {hi:.3f}]")

    print("\nb) Naiv T0836 Precision, ketoldalu 95% Clopper-Pearson")
    fp_naive = t["T0836"]["naive"]["fp_count"]
    k, n = t0836_tp, t0836_tp + fp_naive
    lo, hi = clopper_pearson(k, n)
    print(f"  Precision T0836 naiv             {k}/{n} = {k / n:.3f}  CI95 = [{lo:.3f}; {hi:.3f}]")

    print("\nc) Poisson felso korlat 0 FP-re")
    for label, tail in [("egyoldalu 95%", 0.95), ("ketoldalu 95% (97,5% felso farok)", 0.975)]:
        mu = poisson_upper_zero(tail)
        print(f"  {label:34s} mu_felso = {mu:.4f} esemeny -> {mu / hours:.3f} riasztas/ora (T = {hours} h)")

    print("\nd) Makro-recall (5 tesztelt technika)")
    recalls_rounded = [1.000, 0.0, 0.870, 0.0, 0.0]
    print(f"  (1,000 + 0 + 0,870 + 0 + 0) / 5 = {sum(recalls_rounded) / 5:.3f}")
    recalls_exact = [t[x]["recall"] for x in ("T0836", "T0888", "T0816", "T0846", "T0843")]
    print(f"  pontos recall-ertekekkel a JSON-bol: {sum(recalls_exact) / 5:.3f} (JSON macro_recall.value = {m['macro_recall']['value']:.3f})")


if __name__ == "__main__":
    main()
