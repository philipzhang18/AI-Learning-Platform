"""
智能预测可行性验证（feasibility report）

目标：在修好双源 CVSS 后，用真实数据跑出
1. CVSS 命中率（双源覆盖了多少 DSA）
2. 微码级原型 Top N 排序（PowerEdge BIOS / iDRAC / OneFS / All）
3. 与产品线级、版本级预测的对照
4. 给出"方法是否值得做下去"的判断

直接执行：
    PYTHONIOENCODING=utf-8 python risk/feasibility_report.py
"""
from __future__ import annotations

import os
import sys
import time
from collections import Counter

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, "e:/AI/Claude/CVE")
os.chdir("e:/AI/Claude/CVE")

DB = "cve_data/cve_database.db"


def section(title: str) -> None:
    print()
    print("━" * 70)
    print(f"  {title}")
    print("━" * 70)


def report_cvss_coverage() -> None:
    section("1. 双源 CVSS 命中率")
    from risk.dsa_prediction_microcode import MicrocodeRiskAssessor
    ass = MicrocodeRiskAssessor(DB)
    t0 = time.time()
    records = ass._load_dsa_records()
    elapsed = time.time() - t0
    sources = Counter(r["cvss_source"] for r in records)
    n = len(records)
    print(f"DSA 记录: {n}（加载 {elapsed:.1f}s）")
    for src, c in sources.most_common():
        print(f"  cvss_source = {src:<20} {c:>5}  ({100*c/n:.1f}%)")
    avg = sum(r["avg_cvss"] for r in records if r["avg_cvss"] > 0) / max(
        1, sum(1 for r in records if r["avg_cvss"] > 0)
    )
    print(f"非零 CVSS 平均分: {avg:.2f}")
    nonzero_pct = 100 * sum(1 for r in records if r["avg_cvss"] > 0) / n
    print(f"非零 CVSS 覆盖率: {nonzero_pct:.1f}%")
    if nonzero_pct >= 95:
        print("[结论] CVSS 数据可用，severity_factor 有判别力 ✅")
    else:
        print("[结论] CVSS 仍有缺口，部分 DSA severity 未填充")


def report_microcode_top(product_line: str, firmware_type: str | None, top: int) -> None:
    title = f"{product_line}"
    if firmware_type:
        title += f" / {firmware_type}"
    section(f"微码级 Top {top}：{title}")
    from risk.dsa_prediction_microcode import MicrocodeRiskAssessor
    ass = MicrocodeRiskAssessor(DB)
    t0 = time.time()
    scores = ass.assess_all(
        product_line_filter=product_line,
        firmware_type_filter=firmware_type,
        top=top,
    )
    elapsed = time.time() - t0
    if not scores:
        print(f"（无数据；耗时 {elapsed:.1f}s）")
        return
    print(f"耗时 {elapsed:.1f}s，Top {len(scores)} 条：\n")
    print(f"  {'分':>5} {'等级':<8} {'机型':<10} {'版本':<14} "
          f"{'qual':<5} {'命中':<5} {'CVSS':<5} 最近")
    for s in scores:
        print(f"  {s.exposure_score:>5.1f} {s.risk_band:<8} "
              f"{s.key.model or '-':<10} {s.key.version:<14} "
              f"{s.qualifier or '':<5} {s.expanded_dsa_count:<5} "
              f"{s.severity_avg_cvss:<5} {s.months_since_last}月前")


def report_global_top(top: int) -> None:
    section(f"全量微码级 Top {top}（跨产品线）")
    from risk.dsa_prediction_microcode import MicrocodeRiskAssessor
    ass = MicrocodeRiskAssessor(DB)
    t0 = time.time()
    scores = ass.assess_all(top=top)
    elapsed = time.time() - t0
    print(f"耗时 {elapsed:.1f}s\n")
    band_count = Counter(s.risk_band for s in scores)
    print(f"风险带分布: {dict(band_count)}")
    print()
    print(f"  {'分':>5} {'等级':<8} {'产品线':<28} {'机型':<8} "
          f"{'类型':<10} {'版本':<12} {'CVSS':<5}")
    for s in scores:
        pl = s.key.product_line[:26]
        print(f"  {s.exposure_score:>5.1f} {s.risk_band:<8} {pl:<28} "
              f"{s.key.model or '-':<8} {s.key.firmware_type:<10} "
              f"{s.key.version:<12} {s.severity_avg_cvss}")


def report_layer_comparison() -> None:
    section("3 层对照：产品线 vs 版本 vs 微码（仅 PowerEdge）")
    from risk.dsa_prediction import DSAProductLinePredictor
    from risk.dsa_prediction_version import DSAVersionPredictor
    from risk.dsa_prediction_microcode import MicrocodeRiskAssessor

    pl_predictor = DSAProductLinePredictor(DB)
    pl_predictor.forecast_all(forecast_days=30)  # 预热
    pl_results = pl_predictor.forecast_all(forecast_days=90)
    pe_pl = next((r for r in pl_results if r.product_line == "PowerEdge (服务器)"), None)
    if pe_pl:
        print(f"[产品线级] PowerEdge")
        print(f"  P(≥1 DSA in 90d) = {pe_pl.probability:.1%}  ({pe_pl.risk_level})")
        print(f"  λ_base = {pe_pl.base_rate_per_month:.2f}/月，"
              f"trend = {pe_pl.trend_multiplier}，severity = {pe_pl.severity_factor}")
        print(f"  open_cve_pressure = {pe_pl.open_cve_pressure}")

    print()
    v_predictor = DSAVersionPredictor(DB)
    v_results = v_predictor.forecast_all_versions(forecast_days=90, min_confidence=0.0)
    pe_v = [v for v in v_results if v.product_line == "PowerEdge (服务器)"]
    print(f"[版本级] PowerEdge 共 {len(pe_v)} 个版本（按概率降序）")
    for v in pe_v[:5]:
        print(f"  {v.probability:.1%} {v.risk_level:<8} {v.version_display:<35} "
              f"hist={v.historical_dsa_total} ci_method={v.ci_method}")

    print()
    ass = MicrocodeRiskAssessor(DB)
    micro = ass.assess_all(product_line_filter="PowerEdge (服务器)", top=10)
    print(f"[微码级] PowerEdge Top 10（exposure_score 0~100）")
    for s in micro:
        print(f"  {s.exposure_score:>5.1f} {s.risk_band:<8} "
              f"{s.key.model:<8} {s.key.firmware_type:<10} {s.key.version:<12} "
              f"hit={s.expanded_dsa_count} cvss={s.severity_avg_cvss}")

    print()
    print("[判断]")
    if pe_pl and len(pe_v) >= 1 and len(micro) >= 5:
        print("  ✅ 三层均能产出结果，可形成 GUI 联动：")
        print("     产品线级给整体风险 → 版本级给重点版本 → 微码级给具体 BIOS/Firmware")
    else:
        print("  ⚠️ 某层数据不足，需补充版本提取规则或机型识别")


if __name__ == "__main__":
    print("智能预测可行性验证报告")
    print(f"数据库: {DB}")
    try:
        report_cvss_coverage()
        report_microcode_top("PowerEdge (服务器)", "BIOS", top=10)
        report_microcode_top("PowerEdge (服务器)", "iDRAC", top=10)
        report_microcode_top("PowerScale / Isilon (NAS)", "OS", top=10)
        report_microcode_top("OpenManage / iDRAC (管理)", "iDRAC", top=10)
        report_global_top(top=15)
        report_layer_comparison()
        print()
        print("=" * 70)
        print("[完成] 可行性验证")
        print("=" * 70)
    except Exception as e:
        import traceback
        print(f"\n[ERROR] {e}")
        print(traceback.format_exc())
        sys.exit(1)
