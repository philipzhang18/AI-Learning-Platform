"""
DSA 预测权重自动校准 (risk/weight_calibration.py)

回测结果显示，当前 predictor 的复杂启发式（severity_factor / open_cve_pressure / trend）
在所有指标上**都不如朴素的"看历史频率"baseline**。

但这不一定意味着启发式没用——**也可能是权重设错了**。
本模块用 grid search 在历史数据上找最优权重。

------------------------------------------------------------
搜索的权重
------------------------------------------------------------
1. severity_alpha    在 `severity_factor = 1.0 + α × (cvss/10)` 中
   原值 0.5 → 搜索 [0.0, 0.3, 0.5, 0.8, 1.0, 1.5]

2. pressure_beta     在 `+ β × open_cve_pressure` 中
   原值 0.04 → 搜索 [0.0, 0.02, 0.04, 0.08, 0.12]

3. trend_clip        在 `clip(ratio, low, high)` 中
   原值 (0.5, 3.0) → 搜索 [(1.0, 1.0)固定/no-trend, (0.7, 2.0), (0.5, 3.0), (0.3, 5.0)]

------------------------------------------------------------
评估
------------------------------------------------------------
对每组权重，跑 N 个时间点的回测，目标函数：
- 默认 = 平均 Brier score（越小越好）；可切换为 -avg_AUC

------------------------------------------------------------
输出
------------------------------------------------------------
  best_weights / best_metric / 与原始权重的差距 / 与 naive baseline 的差距
"""
from __future__ import annotations

import math
import json
import itertools
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from risk._dsa_base import parse_date
from risk.backtest import (
    PredictionBacktester,
    naive_frequency_baseline,
    compute_brier,
    compute_auc_roc,
    compute_precision_at_k,
    compute_hit_rate_at_threshold,
    load_actual_dsas_in_window,
)
from risk.dsa_prediction import (
    DSAProductLinePredictor,
    DELL_PRODUCT_LINES,
)


@dataclass
class WeightConfig:
    severity_alpha: float       # severity_factor = 1 + α * (cvss/10)
    pressure_beta: float        # + β * open_cve_pressure
    trend_low: float            # clip(ratio, low, high)
    trend_high: float

    def to_dict(self) -> Dict[str, float]:
        return asdict(self)


# ────────────────────────────────────────────────────────────────────────────
# Predictor with overridable weights
# ────────────────────────────────────────────────────────────────────────────

class TunableDSAPredictor(DSAProductLinePredictor):
    """覆盖关键权重的 DSAProductLinePredictor 子类，用于 grid search"""

    def __init__(
        self,
        db_path: str,
        config: WeightConfig,
        now: Optional[datetime] = None,
    ) -> None:
        super().__init__(db_path, now=now)
        self.config = config

    def forecast_line(self, product_line: str, forecast_days: int = 30):
        """重新实现核心计算（与父类一致，但用 self.config 的权重）"""
        from risk.dsa_prediction import DSAProductLineForecast

        if product_line not in DELL_PRODUCT_LINES:
            raise ValueError(f"未知产品线: {product_line}")

        records = self._load_dsa_records()
        line_records = [r for r in records if product_line in r["product_lines"]]

        cutoff_12m = self.now - timedelta(days=365)
        cutoff_3m = self.now - timedelta(days=90)
        dsa_12m = [r for r in line_records if r["published"] >= cutoff_12m]
        dsa_3m = [r for r in line_records if r["published"] >= cutoff_3m]

        base_rate = len(dsa_12m) / 12.0
        recent_rate = len(dsa_3m) / 3.0

        if base_rate < 0.05:
            trend_multiplier = 1.0
        else:
            raw_ratio = recent_rate / base_rate
            trend_multiplier = max(self.config.trend_low,
                                   min(self.config.trend_high, raw_ratio))

        line_cve_index = self._build_line_cve_index()
        line_cve_records = line_cve_index.get(product_line, [])
        if line_cve_records:
            avg_cvss = sum(c["cvss"] for c in line_cve_records) / len(line_cve_records)
            severity_factor = 1.0 + self.config.severity_alpha * (avg_cvss / 10.0)
            # 同步原裁剪上限（α=0.5 时上限 1.5；按比例放大）
            severity_factor = max(1.0, min(1.0 + self.config.severity_alpha, severity_factor))
        else:
            avg_cvss = 0.0
            severity_factor = 1.0

        dsa_cve_set = self._load_dsa_cve_set()
        open_cves = [c for c in line_cve_records if c["cve_id"] not in dsa_cve_set]
        open_cve_pressure = len(open_cves)

        lambda_effective = (
            base_rate * trend_multiplier * severity_factor
            + self.config.pressure_beta * open_cve_pressure
        )

        expected = lambda_effective * (forecast_days / 30.0)
        probability = 1.0 - math.exp(-expected) if expected > 0 else 0.0
        sigma2 = expected
        ci_low = max(0.0, 1 - math.exp(-(expected - 1.28 * math.sqrt(sigma2))))
        ci_high = min(1.0, 1 - math.exp(-(expected + 1.28 * math.sqrt(sigma2))))

        return DSAProductLineForecast(
            product_line=product_line,
            forecast_days=forecast_days,
            historical_dsa_total=len(line_records),
            historical_dsa_12m=len(dsa_12m),
            historical_dsa_3m=len(dsa_3m),
            base_rate_per_month=round(base_rate, 3),
            recent_rate_per_month=round(recent_rate, 3),
            trend_multiplier=round(trend_multiplier, 3),
            severity_factor=round(severity_factor, 3),
            open_cve_pressure=open_cve_pressure,
            expected_dsa_count=round(expected, 3),
            probability=round(probability, 4),
            probability_ci=(round(ci_low, 4), round(ci_high, 4)),
            risk_level=self._level_from_probability(probability),
            explanation=[],
            forecast_date=self.now,
        )


# ────────────────────────────────────────────────────────────────────────────
# 评估单一权重组合
# ────────────────────────────────────────────────────────────────────────────

def evaluate_config(
    db_path: str,
    config: WeightConfig,
    cutoffs: List[datetime],
    forecast_days: int = 90,
    _predictor_cache: Optional[Dict[str, Any]] = None,
) -> Dict[str, float]:
    """对一组 cutoff 跑回测，返回平均指标。

    _predictor_cache: {cutoff_iso: predictor} 缓存，避免重复加载数据。
    """
    briers, aucs, p10s, hits = [], [], [], []
    for cutoff in cutoffs:
        key = cutoff.isoformat()
        if _predictor_cache is not None and key in _predictor_cache:
            predictor = _predictor_cache[key]
            # 复用缓存的 predictor 但换权重
            predictor.config = config
            # 清 _line_cve_index 因它不依赖权重但 forecast_line 会复用
        else:
            predictor = TunableDSAPredictor(db_path, config, now=cutoff)
            # 预热数据
            predictor._load_dsa_records()
            predictor._load_recent_cves()
            predictor._build_line_cve_index()
            predictor._load_dsa_cve_set()
            if _predictor_cache is not None:
                _predictor_cache[key] = predictor

        # 换权重后跑
        predictor.config = config
        forecasts = predictor.forecast_all(forecast_days=forecast_days)
        actuals = load_actual_dsas_in_window(
            db_path, cutoff, cutoff + timedelta(days=forecast_days)
        )
        preds: List[Tuple[float, int]] = []
        for f in forecasts:
            label = 1 if actuals.get(f.product_line, 0) > 0 else 0
            preds.append((f.probability, label))
        briers.append(compute_brier(preds))
        aucs.append(compute_auc_roc(preds))
        p10s.append(compute_precision_at_k(preds, 10))
        hits.append(compute_hit_rate_at_threshold(preds, 0.7))
    return {
        "avg_brier": round(sum(briers) / len(briers), 4),
        "avg_auc": round(sum(aucs) / len(aucs), 4),
        "avg_precision_at_10": round(sum(p10s) / len(p10s), 4),
        "avg_hit_rate_high": round(sum(hits) / len(hits), 4),
    }


# ────────────────────────────────────────────────────────────────────────────
# Grid search
# ────────────────────────────────────────────────────────────────────────────

def grid_search(
    db_path: str,
    cutoffs: List[datetime],
    forecast_days: int = 90,
    objective: str = "brier",  # "brier" | "auc"
    severity_alphas: Optional[List[float]] = None,
    pressure_betas: Optional[List[float]] = None,
    trend_clips: Optional[List[Tuple[float, float]]] = None,
    verbose: bool = True,
) -> Dict[str, Any]:
    """
    grid search 找最佳权重组合。

    objective="brier" → 最小化 avg_brier
    objective="auc"   → 最大化 avg_auc
    """
    severity_alphas = severity_alphas or [0.0, 0.3, 0.5, 0.8, 1.0, 1.5]
    pressure_betas = pressure_betas or [0.0, 0.02, 0.04, 0.08, 0.12]
    trend_clips = trend_clips or [(1.0, 1.0), (0.7, 2.0), (0.5, 3.0), (0.3, 5.0)]

    combos = list(itertools.product(severity_alphas, pressure_betas, trend_clips))
    if verbose:
        print(f"  Grid: {len(severity_alphas)} a x {len(pressure_betas)} b x "
              f"{len(trend_clips)} trend = {len(combos)} combos x {len(cutoffs)} cutoffs")

    # 共享 predictor 缓存——数据只加载 len(cutoffs) 次
    predictor_cache: Dict[str, Any] = {}

    results: List[Dict[str, Any]] = []
    for i, (alpha, beta, (low, high)) in enumerate(combos, 1):
        cfg = WeightConfig(severity_alpha=alpha, pressure_beta=beta,
                           trend_low=low, trend_high=high)
        m = evaluate_config(db_path, cfg, cutoffs, forecast_days,
                            _predictor_cache=predictor_cache)
        m["config"] = cfg.to_dict()
        results.append(m)
        if verbose and i % 10 == 0:
            print(f"    [{i}/{len(combos)}] a={alpha} b={beta} clip=({low},{high}) "
                  f"-> brier={m['avg_brier']:.4f} auc={m['avg_auc']:.4f}")

    # 排序
    if objective == "brier":
        results.sort(key=lambda r: r["avg_brier"])
    elif objective == "auc":
        results.sort(key=lambda r: -r["avg_auc"])
    else:
        raise ValueError(f"objective 必须是 'brier' 或 'auc'，收到: {objective}")

    # 与原始权重 (α=0.5, β=0.04, trend=(0.5,3.0)) 对比
    original_cfg = WeightConfig(severity_alpha=0.5, pressure_beta=0.04,
                                trend_low=0.5, trend_high=3.0)
    original_metrics = evaluate_config(db_path, original_cfg, cutoffs, forecast_days)

    # 与 naive baseline 对比（用同样 cutoffs）
    n_briers, n_aucs, n_p10s, n_hits = [], [], [], []
    for cutoff in cutoffs:
        naive = naive_frequency_baseline(db_path, cutoff, forecast_days)
        preds = [(p, y) for p, y, _ in naive]
        n_briers.append(compute_brier(preds))
        n_aucs.append(compute_auc_roc(preds))
        n_p10s.append(compute_precision_at_k(preds, 10))
        n_hits.append(compute_hit_rate_at_threshold(preds, 0.7))
    naive_metrics = {
        "avg_brier": round(sum(n_briers) / len(n_briers), 4),
        "avg_auc": round(sum(n_aucs) / len(n_aucs), 4),
        "avg_precision_at_10": round(sum(n_p10s) / len(n_p10s), 4),
        "avg_hit_rate_high": round(sum(n_hits) / len(n_hits), 4),
    }

    return {
        "objective": objective,
        "n_combos": len(combos),
        "n_cutoffs": len(cutoffs),
        "forecast_days": forecast_days,
        "best": results[0],
        "top5": results[:5],
        "original": {"config": original_cfg.to_dict(), "metrics": original_metrics},
        "naive_baseline": naive_metrics,
        "all_results": results,  # 用于后续分析
    }


# ────────────────────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────────────────────

def _format_summary(result: Dict[str, Any]) -> str:
    out = []
    out.append("=" * 78)
    out.append("DSA 预测权重 Grid Search 结果")
    out.append("=" * 78)
    out.append(f"  目标: {result['objective']}  (回测 cutoffs: {result['n_cutoffs']}, "
               f"forecast: {result['forecast_days']}d, 组合数: {result['n_combos']})")
    out.append("")
    out.append("  方案对比 (越小 brier 越好, 越大 auc/p10/hit 越好):")
    out.append(f"  {'方案':28s} {'brier':>8s} {'auc':>7s} {'P@10':>6s} {'hit>=.7':>9s}")
    out.append("  " + "-" * 70)
    bm = result["best"]
    om = result["original"]["metrics"]
    nm = result["naive_baseline"]
    out.append(f"  {'best (校准后)':28s} {bm['avg_brier']:>8.4f} {bm['avg_auc']:>7.4f} "
               f"{bm['avg_precision_at_10']:>6.3f} {bm['avg_hit_rate_high']:>9.3f}")
    out.append(f"  {'original (拍脑袋权重)':28s} {om['avg_brier']:>8.4f} {om['avg_auc']:>7.4f} "
               f"{om['avg_precision_at_10']:>6.3f} {om['avg_hit_rate_high']:>9.3f}")
    out.append(f"  {'naive freq baseline':28s} {nm['avg_brier']:>8.4f} {nm['avg_auc']:>7.4f} "
               f"{nm['avg_precision_at_10']:>6.3f} {nm['avg_hit_rate_high']:>9.3f}")
    out.append("")
    out.append("  最佳权重组合:")
    cfg = bm["config"]
    out.append(f"    severity_alpha = {cfg['severity_alpha']}")
    out.append(f"    pressure_beta  = {cfg['pressure_beta']}")
    out.append(f"    trend_clip     = ({cfg['trend_low']}, {cfg['trend_high']})")
    out.append("")
    out.append("  Top-5 候选:")
    out.append(f"  {'#':>3s} {'α':>6s} {'β':>6s} {'trend':>14s} {'brier':>8s} {'auc':>7s} {'P@10':>6s}")
    for i, r in enumerate(result["top5"], 1):
        c = r["config"]
        trend = f"({c['trend_low']},{c['trend_high']})"
        out.append(f"  {i:>3d} {c['severity_alpha']:>6.2f} {c['pressure_beta']:>6.3f} "
                   f"{trend:>14s} {r['avg_brier']:>8.4f} {r['avg_auc']:>7.4f} "
                   f"{r['avg_precision_at_10']:>6.3f}")
    out.append("")
    return "\n".join(out)


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="DSA 预测权重 grid search 校准")
    parser.add_argument("--db", default="cve_data/cve_database.db")
    parser.add_argument("--cutoffs", default="2024-01-01,2024-06-01,2024-12-01,2025-06-01,2025-12-01",
                        help="逗号分隔的 cutoff 日期")
    parser.add_argument("--forecast-days", type=int, default=90)
    parser.add_argument("--objective", default="brier", choices=["brier", "auc"])
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    cutoffs = [parse_date(s.strip()) for s in args.cutoffs.split(",")]
    cutoffs = [c for c in cutoffs if c is not None]

    result = grid_search(
        args.db,
        cutoffs=cutoffs,
        forecast_days=args.forecast_days,
        objective=args.objective,
    )
    print()
    print(_format_summary(result))
    if args.out:
        # all_results 太大，保存简化版
        save = {k: v for k, v in result.items() if k != "all_results"}
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(save, f, ensure_ascii=False, indent=2)
        print(f"  结果已保存: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
