"""
DSA 产品线 ML Baseline (risk/ml_baseline.py)

回测显示：启发式 predictor 即使权重最优也仅比 naive 好 6%（Brier 0.068 vs 0.072）。
本模块用 sklearn 训练一个真正"从数据学权重"的分类器，看看能否拉开差距。

------------------------------------------------------------
特征设计（每个样本 = 一条产品线在某个 cutoff 时的状态）
------------------------------------------------------------
- dsa_count_12m:        过去 12 个月该产品线 DSA 数
- dsa_count_3m:         过去 3 个月该产品线 DSA 数
- dsa_count_1m:         过去 1 个月该产品线 DSA 数
- months_since_last:    距上次 DSA 的月数（冷启动=12.0）
- avg_cvss_recent:      近 90 天匹配该产品线 CVE 的平均 CVSS
- open_cve_count:       近 90 天未被 DSA 覆盖的 CVE 数
- max_cvss_recent:      近 90 天最高 CVSS
- trend_ratio:          dsa_count_3m/3 / max(dsa_count_12m/12, 0.1)

Label: 未来 forecast_days 天内该产品线是否出现 DSA（0/1）

------------------------------------------------------------
训练策略
------------------------------------------------------------
- 滑动窗口生成样本：每 60 天取一次 cutoff（2021-01 ~ 最新可用）
- TimeSeriesSplit 或 留出末尾 20% 做 test
- 模型：LogisticRegression (baseline) + GradientBoosting (进阶)
- 与启发式 predictor / naive baseline 在相同 cutoff 集上对比
"""
from __future__ import annotations

import math
import sqlite3
import warnings
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from risk._dsa_base import (
    parse_date,
    parse_advisory_data,
    affected_text_of,
    fetch_advisory_rows,
    load_recent_cves_base,
)
from risk.dsa_prediction import (
    DSAProductLinePredictor,
    DELL_PRODUCT_LINES,
    classify_dsa,
    classify_cve_text,
)
from risk.backtest import (
    PredictionBacktester,
    naive_frequency_baseline,
    compute_brier,
    compute_auc_roc,
    compute_precision_at_k,
    compute_hit_rate_at_threshold,
    load_actual_dsas_in_window,
)


# ────────────────────────────────────────────────────────────────────────────
# 特征提取
# ────────────────────────────────────────────────────────────────────────────

def extract_features_for_cutoff(
    db_path: str,
    cutoff: datetime,
    forecast_days: int = 90,
) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """
    对某个 cutoff 提取所有产品线的特征和标签。

    返回 (X: shape [n_lines, n_features], y: shape [n_lines], line_names)
    """
    lines = list(DELL_PRODUCT_LINES.keys())
    end_dt = cutoff + timedelta(days=forecast_days)

    # 加载 cutoff 之前的 DSA（带产品线分类）
    predictor = DSAProductLinePredictor(db_path, now=cutoff)
    dsa_records = predictor._load_dsa_records()
    recent_cves = predictor._load_recent_cves(days=90)
    dsa_cve_set = predictor._load_dsa_cve_set()
    line_cve_index = predictor._build_line_cve_index()

    # 真值
    actuals = load_actual_dsas_in_window(db_path, cutoff, end_dt)

    cutoff_12m = cutoff - timedelta(days=365)
    cutoff_3m = cutoff - timedelta(days=90)
    cutoff_1m = cutoff - timedelta(days=30)

    X_rows = []
    y_rows = []
    for line in lines:
        line_dsas = [r for r in dsa_records if line in r["product_lines"]]
        dsa_12m = [r for r in line_dsas if r["published"] >= cutoff_12m]
        dsa_3m = [r for r in line_dsas if r["published"] >= cutoff_3m]
        dsa_1m = [r for r in line_dsas if r["published"] >= cutoff_1m]

        # months since last DSA
        if line_dsas:
            last_pub = max(r["published"] for r in line_dsas)
            months_since = (cutoff - last_pub).days / 30.0
        else:
            months_since = 12.0  # 冷启动兜底

        # CVE 特征
        line_cves = line_cve_index.get(line, [])
        open_cves = [c for c in line_cves if c["cve_id"] not in dsa_cve_set]
        if line_cves:
            avg_cvss = sum(c["cvss"] for c in line_cves) / len(line_cves)
            max_cvss = max(c["cvss"] for c in line_cves)
        else:
            avg_cvss = 0.0
            max_cvss = 0.0

        # trend ratio
        base_monthly = len(dsa_12m) / 12.0
        recent_monthly = len(dsa_3m) / 3.0
        trend_ratio = recent_monthly / max(base_monthly, 0.1)

        features = [
            len(dsa_12m),           # dsa_count_12m
            len(dsa_3m),            # dsa_count_3m
            len(dsa_1m),            # dsa_count_1m
            months_since,           # months_since_last
            avg_cvss,               # avg_cvss_recent
            len(open_cves),         # open_cve_count
            max_cvss,               # max_cvss_recent
            trend_ratio,            # trend_ratio
        ]
        X_rows.append(features)

        label = 1 if actuals.get(line, 0) > 0 else 0
        y_rows.append(label)

    return np.array(X_rows), np.array(y_rows), lines


FEATURE_NAMES = [
    "dsa_count_12m", "dsa_count_3m", "dsa_count_1m",
    "months_since_last", "avg_cvss_recent", "open_cve_count",
    "max_cvss_recent", "trend_ratio",
]


# ────────────────────────────────────────────────────────────────────────────
# 训练数据生成（滑动窗口）
# ────────────────────────────────────────────────────────────────────────────

def generate_training_data(
    db_path: str,
    start: str = "2022-01-01",
    end: str = "2025-12-01",
    step_days: int = 60,
    forecast_days: int = 90,
    verbose: bool = True,
) -> Tuple[np.ndarray, np.ndarray, List[datetime]]:
    """
    滑动窗口生成训练数据。

    每个 cutoff 产生 29 个样本（每条产品线一个），滑动窗口步长 step_days。
    返回 (X: [n_samples, 8], y: [n_samples], cutoff_per_sample)
    """
    start_dt = parse_date(start) or datetime(2022, 1, 1)
    end_dt = parse_date(end) or datetime(2025, 12, 1)

    # 确保 end + forecast_days <= 今天
    latest_safe = datetime.now() - timedelta(days=forecast_days)
    if end_dt > latest_safe:
        end_dt = latest_safe

    all_X, all_y, all_cutoffs = [], [], []
    cur = start_dt
    while cur <= end_dt:
        if verbose:
            print(f"  generating cutoff={cur.date()} ...", end=" ", flush=True)
        X, y, _ = extract_features_for_cutoff(db_path, cur, forecast_days)
        all_X.append(X)
        all_y.append(y)
        all_cutoffs.extend([cur] * len(y))
        if verbose:
            print(f"pos={y.sum()}/{len(y)}")
        cur += timedelta(days=step_days)

    return np.vstack(all_X), np.concatenate(all_y), all_cutoffs


# ────────────────────────────────────────────────────────────────────────────
# 模型训练与评估
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class MLComparisonResult:
    """ML 与启发式/naive 的对比结果"""
    n_train: int
    n_test: int
    test_cutoffs: List[str]

    # 各方案在 test 集上的指标
    ml_logistic: Dict[str, float]
    ml_gbc: Dict[str, float]
    heuristic: Dict[str, float]
    naive: Dict[str, float]

    # Logistic 系数可解释性
    logistic_coefs: Dict[str, float]

    def to_dict(self):
        d = asdict(self)
        return d


def train_and_compare(
    db_path: str,
    train_start: str = "2022-01-01",
    train_end: str = "2025-06-01",
    test_cutoffs_str: str = "2025-06-01,2025-08-01,2025-10-01,2025-12-01",
    step_days: int = 60,
    forecast_days: int = 90,
    verbose: bool = True,
) -> MLComparisonResult:
    """
    端到端：生成训练集 → 训练 → 在 test_cutoffs 上对比 ML / 启发式 / naive。
    """
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.preprocessing import StandardScaler

    # 1. 训练数据
    if verbose:
        print("=" * 60)
        print("Step 1: 生成训练数据")
        print("=" * 60)
    X_train, y_train, _ = generate_training_data(
        db_path, start=train_start, end=train_end,
        step_days=step_days, forecast_days=forecast_days, verbose=verbose,
    )
    if verbose:
        print(f"  训练集: {X_train.shape[0]} 样本, pos_rate={y_train.mean():.3f}")

    # 2. 训练
    if verbose:
        print("\nStep 2: 训练模型")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_train)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        lr = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42)
        lr.fit(X_scaled, y_train)

        gbc = GradientBoostingClassifier(
            n_estimators=100, max_depth=3, learning_rate=0.1,
            random_state=42, subsample=0.8,
        )
        gbc.fit(X_train, y_train)  # GBC 不需要标准化

    if verbose:
        print("  LogisticRegression + GradientBoosting 训练完成")
        print("  LR coefs:", {n: round(c, 3) for n, c in zip(FEATURE_NAMES, lr.coef_[0])})
        print("  GBC importances:", {n: round(c, 3) for n, c in
              zip(FEATURE_NAMES, gbc.feature_importances_)})

    # 3. Test 评估
    if verbose:
        print(f"\nStep 3: Test 评估")
    test_cutoffs = [parse_date(s.strip()) for s in test_cutoffs_str.split(",")]
    test_cutoffs = [c for c in test_cutoffs if c is not None]

    ml_lr_preds: List[Tuple[float, int]] = []
    ml_gbc_preds: List[Tuple[float, int]] = []
    heuristic_preds: List[Tuple[float, int]] = []
    naive_preds: List[Tuple[float, int]] = []

    for cutoff in test_cutoffs:
        if verbose:
            print(f"  evaluating cutoff={cutoff.date()} ...")

        # ML 特征
        X_test, y_test, _ = extract_features_for_cutoff(db_path, cutoff, forecast_days)
        X_test_scaled = scaler.transform(X_test)

        # ML 概率
        lr_probs = lr.predict_proba(X_test_scaled)[:, 1]
        gbc_probs = gbc.predict_proba(X_test)[:, 1]
        for i in range(len(y_test)):
            ml_lr_preds.append((lr_probs[i], int(y_test[i])))
            ml_gbc_preds.append((gbc_probs[i], int(y_test[i])))

        # 启发式
        bt = PredictionBacktester(db_path)
        point = bt.run(cutoff, forecast_days=forecast_days)
        actuals = load_actual_dsas_in_window(
            db_path, cutoff, cutoff + timedelta(days=forecast_days)
        )
        for f in point.top_predictions:
            pass  # 已经在 bt.run 中计算
        # 重新获取（以完整概率列表）
        predictor = DSAProductLinePredictor(db_path, now=cutoff)
        forecasts = predictor.forecast_all(forecast_days=forecast_days)
        for f in forecasts:
            label = 1 if actuals.get(f.product_line, 0) > 0 else 0
            heuristic_preds.append((f.probability, label))

        # Naive
        naive = naive_frequency_baseline(db_path, cutoff, forecast_days)
        for p, y, _ in naive:
            naive_preds.append((p, y))

    def _metrics(preds):
        return {
            "brier": round(compute_brier(preds), 4),
            "auc": round(compute_auc_roc(preds), 4),
            "precision_at_10": round(compute_precision_at_k(preds, 10), 4),
            "hit_rate_high": round(compute_hit_rate_at_threshold(preds, 0.7), 4),
        }

    result = MLComparisonResult(
        n_train=len(y_train),
        n_test=len(ml_lr_preds),
        test_cutoffs=[c.date().isoformat() for c in test_cutoffs],
        ml_logistic=_metrics(ml_lr_preds),
        ml_gbc=_metrics(ml_gbc_preds),
        heuristic=_metrics(heuristic_preds),
        naive=_metrics(naive_preds),
        logistic_coefs={n: round(c, 4) for n, c in zip(FEATURE_NAMES, lr.coef_[0])},
    )

    if verbose:
        print("\n" + "=" * 60)
        print("结果对比 (test set)")
        print("=" * 60)
        print(f"  {'方案':25s} {'brier':>8s} {'auc':>7s} {'P@10':>6s} {'hit>=.7':>9s}")
        print("  " + "-" * 60)
        for name, m in [("ML GradientBoosting", result.ml_gbc),
                        ("ML LogisticRegression", result.ml_logistic),
                        ("Heuristic predictor", result.heuristic),
                        ("Naive freq baseline", result.naive)]:
            print(f"  {name:25s} {m['brier']:>8.4f} {m['auc']:>7.4f} "
                  f"{m['precision_at_10']:>6.3f} {m['hit_rate_high']:>9.3f}")
        print()
        print("  LR 特征重要性 (系数绝对值排序):")
        sorted_coefs = sorted(result.logistic_coefs.items(), key=lambda x: -abs(x[1]))
        for name, coef in sorted_coefs:
            bar = "+" * int(min(abs(coef) * 5, 30))
            print(f"    {name:20s} {coef:>7.3f} {bar}")

    return result


# ────────────────────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────────────────────

def main() -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(description="DSA ML Baseline 训练与对比")
    parser.add_argument("--db", default="cve_data/cve_database.db")
    parser.add_argument("--train-start", default="2022-01-01")
    parser.add_argument("--train-end", default="2025-06-01")
    parser.add_argument("--test-cutoffs", default="2025-06-01,2025-08-01,2025-10-01,2025-12-01")
    parser.add_argument("--step-days", type=int, default=60)
    parser.add_argument("--forecast-days", type=int, default=90)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    result = train_and_compare(
        db_path=args.db,
        train_start=args.train_start,
        train_end=args.train_end,
        test_cutoffs_str=args.test_cutoffs,
        step_days=args.step_days,
        forecast_days=args.forecast_days,
    )

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, ensure_ascii=False, indent=2)
        print(f"  结果已保存: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
