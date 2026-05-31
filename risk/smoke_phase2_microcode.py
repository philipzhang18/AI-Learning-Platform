"""
Phase 2 验收 + Phase 1 回归 + 微码原型 smoke test
独立可执行，避免污染 test_version_prediction.py
"""
from __future__ import annotations

import sys
import time
import os

# 强制 UTF-8 输出（Windows 控制台默认 GBK 会乱码）
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, "e:/AI/Claude/CVE")
os.chdir("e:/AI/Claude/CVE")

DB = "cve_data/cve_database.db"


def section(title: str) -> None:
    print()
    print("=" * 70)
    print(title)
    print("=" * 70)


def test_phase1_regression() -> None:
    section("R1-R4: Phase 1 产品线级回归")
    from risk.dsa_prediction import DSAProductLinePredictor, DSAProductLineForecast

    predictor = DSAProductLinePredictor(DB)

    # R1: 产品线数 + 性能（预热后计时，避开冷启动 SQLite + JSON 解析开销）
    predictor.forecast_all(forecast_days=30)  # warmup
    t0 = time.time()
    results = predictor.forecast_all(forecast_days=30)
    elapsed = time.time() - t0
    assert len(results) == 29, f"FAIL R1: 期望 29 条，实际 {len(results)}"
    assert all(isinstance(r, DSAProductLineForecast) for r in results)
    assert elapsed < 6.0, f"FAIL R1: 预热后耗时 {elapsed:.2f}s 超过 6s 基线"
    print(f"[PASS R1] 29 条产品线，预热后耗时 {elapsed:.2f}s")

    # R2: 概率范围
    for r in results:
        assert 0 <= r.probability <= 1, f"FAIL R2: {r.product_line} prob={r.probability}"
    print("[PASS R2] 概率均在 [0,1]")

    # R3: 多周期单调
    r30 = {r.product_line: r.probability for r in results}
    r90 = {r.product_line: r.probability for r in predictor.forecast_all(forecast_days=90)}
    bad = [pl for pl in r30 if r90[pl] + 1e-6 < r30[pl]]
    assert not bad, f"FAIL R3: {bad}"
    print("[PASS R3] 概率随窗口单调")


def test_phase2_acceptance() -> None:
    section("Phase 2 验收：VMR / Bayesian / Bootstrap")
    from risk.dsa_prediction_version import DSAVersionPredictor

    predictor = DSAVersionPredictor(DB)

    t0 = time.time()
    versions = predictor.forecast_all_versions(forecast_days=90, min_confidence=0.0)
    elapsed = time.time() - t0
    print(f"[INFO] 全量版本预测：{len(versions)} 条，耗时 {elapsed:.1f}s")
    assert len(versions) > 0, "FAIL: 没有任何版本预测结果"

    # 字段存在性
    sample = versions[0]
    for f in ("vmr_value", "is_poisson_valid", "ci_method", "prior_method"):
        assert hasattr(sample, f), f"FAIL: 缺字段 {f}"
    print("[PASS] Phase 2 新字段存在")

    # ci_method 分布
    ci_dist = {}
    prior_dist = {}
    for v in versions:
        ci_dist[v.ci_method] = ci_dist.get(v.ci_method, 0) + 1
        prior_dist[v.prior_method] = prior_dist.get(v.prior_method, 0) + 1
    print(f"[INFO] ci_method 分布: {ci_dist}")
    print(f"[INFO] prior_method 分布: {prior_dist}")

    # VMR 失败应触发 fallback + low confidence
    vmr_fails = [v for v in versions if v.vmr_value is not None and not v.is_poisson_valid]
    print(f"[INFO] VMR 过度离散版本: {len(vmr_fails)}")
    for v in vmr_fails[:3]:
        assert v.is_fallback or v.confidence <= 0.5, \
            f"FAIL: {v.version_display} VMR={v.vmr_value} 但未回退"
    if vmr_fails:
        print(f"[PASS] VMR 失败版本均已 fallback / 低置信度（抽样 3 条）")

    # Bayesian 先验：零历史版本应有 prior_method == bayesian_age_adjusted
    zero_hist = [v for v in versions if v.historical_dsa_total == 0]
    print(f"[INFO] 零历史版本: {len(zero_hist)}（极少见，因为 index 由历史 DSA 构建）")

    # CI 合法性
    for v in versions:
        p_low, p_high = v.probability_ci
        assert 0 <= p_low <= 1 and 0 <= p_high <= 1, f"FAIL: CI 越界 {v.probability_ci}"
        assert p_low <= v.probability <= p_high + 1e-9, \
            f"FAIL: prob={v.probability} 不在 CI [{p_low}, {p_high}] 内 ({v.version_display})"
    print("[PASS] 所有 CI 合法且包含 probability")

    # 性能上限
    assert elapsed < 60.0, f"FAIL: 全量预测 {elapsed:.1f}s 超过 60s"
    print(f"[PASS] 性能：{elapsed:.1f}s < 60s")

    # Top 5 展示
    print("\n[INFO] Top 5 版本（含 Phase 2 标注）")
    for v in versions[:5]:
        print(f"  {v.version_display}")
        print(f"    prob={v.probability:.1%} CI={v.probability_ci} "
              f"vmr={v.vmr_value} ci_method={v.ci_method} prior={v.prior_method}")


def test_microcode_smoke() -> None:
    section("微码原型 smoke test")
    from risk.dsa_prediction_microcode import MicrocodeRiskAssessor

    assessor = MicrocodeRiskAssessor(DB)

    t0 = time.time()
    cov = assessor.coverage_summary()
    print(f"[INFO] 覆盖率统计 (耗时 {time.time()-t0:.1f}s):")
    print(f"  total DSA: {cov['total_dsa']}")
    print(f"  microcode keys: {cov['total_microcode_keys']}")
    print(f"  含机型 keys: {cov['keys_with_model']} ({cov['keys_with_model_pct']}%)")
    print(f"  按 firmware_type 分布:")
    for k, n in sorted(cov['keys_per_firmware_type'].items(), key=lambda x: -x[1]):
        print(f"    {k}: {n}")

    assert cov["total_microcode_keys"] > 0, "FAIL: 没有提取出任何微码 key"
    print("[PASS] 至少提取出 1 个微码 key")

    # 排名 Top 10（PowerEdge BIOS）
    t0 = time.time()
    pe_bios = assessor.assess_all(
        product_line_filter="PowerEdge (服务器)",
        firmware_type_filter="BIOS",
        top=10,
    )
    print(f"\n[INFO] PowerEdge BIOS Top 10（耗时 {time.time()-t0:.1f}s）:")
    if pe_bios:
        for s in pe_bios:
            print(f"  {s.exposure_score:>5.1f} {s.risk_band:<8} "
                  f"{s.key.model:<10} {s.key.version:<10} "
                  f"qual={s.qualifier!r:<5} dsa={s.expanded_dsa_count:<3} "
                  f"cvss={s.severity_avg_cvss}")
    else:
        print("  （PowerEdge BIOS 维度无可用 key — 数据中机型识别可能为空）")

    # 任意一个 key 的解释
    all_scores = assessor.assess_all(top=1)
    if all_scores:
        print(f"\n[INFO] Top 1 详细解释:")
        for line in all_scores[0].explanation:
            print(f"  {line}")


if __name__ == "__main__":
    print("DSA 预测系统：Phase 2 + 微码原型综合测试")
    try:
        test_phase1_regression()
        test_phase2_acceptance()
        test_microcode_smoke()
        section("[SUCCESS] 全部测试通过")
    except AssertionError as e:
        print(f"\n[ASSERT FAIL] {e}")
        sys.exit(1)
    except Exception as e:
        import traceback
        print(f"\n[ERROR] {e}")
        print(traceback.format_exc())
        sys.exit(1)
