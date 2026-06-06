"""
DSA 预测回测框架 (risk/backtest.py)

回答一个核心问题：**当前的 DSA 概率预测器，准不准？**

------------------------------------------------------------
工作原理（防数据泄漏）
------------------------------------------------------------
回测 = 模拟"在过去某个时间点，predictor 能预测到什么"

1. 选定一个 cutoff_date（如 2024-06-01）
2. 构造 predictor 时传入 now=cutoff_date
   - [risk/_dsa_base.py](risk/_dsa_base.py) load_recent_cves_base 已按 now 截断 CVE
   - [risk/dsa_prediction.py](risk/dsa_prediction.py) _load_dsa_records 已按 now 截断 DSA
3. 跑 forecast_all(forecast_days=N) 生成"预测"——这是 predictor 凭 cutoff 之前的数据做出的判断
4. 查 cutoff ~ cutoff+N 之间**真实出现**的 DSA → 这是"答案"
5. 比较两者，计算 precision / recall / hit-rate

------------------------------------------------------------
评估指标
------------------------------------------------------------
**产品线粒度**：每条产品线一次预测概率，问题是"未来 N 天该产品线是否出现 DSA"

- **Brier Score**: ⟨(p − y)²⟩，越小越好；y∈{0,1} 表示真实是否出现 DSA
- **AUC-ROC**: 排序质量；0.5=瞎猜，1.0=完美
- **Precision@K**: 取 top-K 高概率预测，其中真实命中比例
- **Hit Rate@threshold**: p≥threshold 的预测中真实命中比例
- **Calibration**: 预测概率 0.7 的产品线，实际命中率应当接近 70%

------------------------------------------------------------
为什么这套指标重要
------------------------------------------------------------
单纯 accuracy 在 DSA 这种"低基率事件"下会骗人——
若某产品线 90 天内出 DSA 概率只有 20%，全猜 0 也能 80% accuracy。
所以必须用 Brier / AUC / Precision@K，三者从不同角度刻画"排序+概率校准"。
"""
from __future__ import annotations

import json
import math
import sqlite3
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from risk._dsa_base import (
    parse_date,
    parse_cve_ids,
    parse_advisory_data,
    affected_text_of,
    fetch_advisory_rows,
)
from risk.dsa_prediction import DSAProductLinePredictor, classify_dsa, DELL_PRODUCT_LINES


# ────────────────────────────────────────────────────────────────────────────
# 数据结构
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class BacktestPoint:
    """单次时间点回测结果"""
    cutoff_date: datetime
    forecast_days: int
    n_lines: int                    # 总产品线数
    n_positive: int                 # 真实出现 DSA 的产品线数
    base_rate: float                # n_positive / n_lines（瞎猜的 baseline）
    brier_score: float              # 越小越好
    auc_roc: float                  # 越大越好
    precision_at_5: float
    precision_at_10: float
    hit_rate_high: float            # p≥0.7 的预测命中率
    hit_rate_critical: float        # p≥0.9 的预测命中率
    calibration: List[Tuple[float, float, int]]  # [(predicted_bin, observed_rate, n)]
    # 详细预测对照（仅 top-K 节省存储）
    top_predictions: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["cutoff_date"] = self.cutoff_date.isoformat()
        return d


@dataclass
class RollingBacktestResult:
    """滚动回测聚合结果"""
    points: List[BacktestPoint]
    avg_brier: float
    avg_auc: float
    avg_precision_at_5: float
    avg_precision_at_10: float
    avg_hit_rate_high: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "n_points": len(self.points),
            "avg_brier": self.avg_brier,
            "avg_auc": self.avg_auc,
            "avg_precision_at_5": self.avg_precision_at_5,
            "avg_precision_at_10": self.avg_precision_at_10,
            "avg_hit_rate_high": self.avg_hit_rate_high,
            "points": [p.to_dict() for p in self.points],
        }


# ────────────────────────────────────────────────────────────────────────────
# 真值加载
# ────────────────────────────────────────────────────────────────────────────

def load_actual_dsas_in_window(
    db_path: str, start: datetime, end: datetime
) -> Dict[str, int]:
    """
    查询 [start, end] 区间内每条产品线的真实 DSA 数量。

    返回 {产品线: dsa_count}，用于和预测概率比对。
    """
    counts: Dict[str, int] = {line: 0 for line in DELL_PRODUCT_LINES.keys()}
    for title, cve_ids_str, pub, data_str in fetch_advisory_rows(db_path):
        if not pub:
            continue
        pub_dt = parse_date(pub)
        if pub_dt is None or pub_dt < start or pub_dt > end:
            continue
        d = parse_advisory_data(data_str)
        affected_text = affected_text_of(d, include_version_range=False)
        for line in classify_dsa(title or "", affected_text):
            counts[line] = counts.get(line, 0) + 1
    return counts


# ────────────────────────────────────────────────────────────────────────────
# 评估指标
# ────────────────────────────────────────────────────────────────────────────

def compute_brier(predictions: List[Tuple[float, int]]) -> float:
    """Brier score = ⟨(p − y)²⟩"""
    if not predictions:
        return 0.0
    return sum((p - y) ** 2 for p, y in predictions) / len(predictions)


def compute_auc_roc(predictions: List[Tuple[float, int]]) -> float:
    """
    AUC-ROC：等价于"在所有正负样本对里，正样本预测分高于负样本的比例"。

    返回 0.5（瞎猜）~ 1.0（完美），样本不足返回 0.5。
    """
    pos = [p for p, y in predictions if y == 1]
    neg = [p for p, y in predictions if y == 0]
    if not pos or not neg:
        return 0.5
    # Mann-Whitney U 等价计算
    n_correct = 0
    n_total = 0
    for pp in pos:
        for pn in neg:
            n_total += 1
            if pp > pn:
                n_correct += 1
            elif pp == pn:
                n_correct += 0.5
    return n_correct / n_total if n_total > 0 else 0.5


def compute_precision_at_k(predictions: List[Tuple[float, int]], k: int) -> float:
    """取概率最高的 k 个，命中比例"""
    if not predictions:
        return 0.0
    sorted_preds = sorted(predictions, key=lambda x: -x[0])
    top = sorted_preds[:k]
    return sum(y for _, y in top) / len(top) if top else 0.0


def compute_hit_rate_at_threshold(
    predictions: List[Tuple[float, int]], threshold: float
) -> float:
    """概率 ≥ threshold 的预测中，真实命中比例（无符合返回 0.0）"""
    selected = [(p, y) for p, y in predictions if p >= threshold]
    if not selected:
        return 0.0
    return sum(y for _, y in selected) / len(selected)


def compute_calibration(
    predictions: List[Tuple[float, int]], n_bins: int = 5
) -> List[Tuple[float, float, int]]:
    """
    校准曲线：把预测分按等宽区间分桶，每个桶 (avg_predicted, observed_rate, n)。

    完美校准时：avg_predicted ≈ observed_rate。
    """
    if not predictions:
        return []
    bins: List[List[Tuple[float, int]]] = [[] for _ in range(n_bins)]
    for p, y in predictions:
        idx = min(int(p * n_bins), n_bins - 1)
        bins[idx].append((p, y))
    out: List[Tuple[float, float, int]] = []
    for b in bins:
        if not b:
            continue
        avg_p = sum(p for p, _ in b) / len(b)
        obs = sum(y for _, y in b) / len(b)
        out.append((round(avg_p, 3), round(obs, 3), len(b)))
    return out


# ────────────────────────────────────────────────────────────────────────────
# 回测主体
# ────────────────────────────────────────────────────────────────────────────

class PredictionBacktester:
    """
    DSA 产品线预测回测器。

    用法：
        bt = PredictionBacktester("cve_data/cve_database.db")
        # 单点回测
        point = bt.run(cutoff="2024-06-01", forecast_days=90)
        print(point.brier_score, point.auc_roc, point.precision_at_10)

        # 滚动回测
        result = bt.run_rolling(start="2024-01-01", end="2025-06-01",
                                step_days=60, forecast_days=90)
        print(result.avg_brier, result.avg_auc)
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path

    # ── 单点回测 ────────────────────────────────────────────────────────

    def run(
        self,
        cutoff: str | datetime,
        forecast_days: int = 90,
        top_k_to_save: int = 10,
    ) -> BacktestPoint:
        """
        在 cutoff 时间点做一次回测。

        步骤
        1. 用 cutoff 之前的数据训练 predictor（now=cutoff）
        2. forecast_all(forecast_days) 生成每条产品线的概率
        3. 查 cutoff ~ cutoff+forecast_days 实际 DSA
        4. 计算各项指标
        """
        cutoff_dt = cutoff if isinstance(cutoff, datetime) else parse_date(cutoff)
        if cutoff_dt is None:
            raise ValueError(f"无法解析 cutoff: {cutoff}")
        end_dt = cutoff_dt + timedelta(days=forecast_days)

        # 1. 训练（即创建 predictor，传 now=cutoff_dt）
        predictor = DSAProductLinePredictor(self.db_path, now=cutoff_dt)
        forecasts = predictor.forecast_all(forecast_days=forecast_days)

        # 2. 查真值
        actuals = load_actual_dsas_in_window(self.db_path, cutoff_dt, end_dt)

        # 3. 拼成 (predicted_prob, actual_label) 对
        predictions: List[Tuple[float, int]] = []
        detailed: List[Dict[str, Any]] = []
        for f in forecasts:
            actual_count = actuals.get(f.product_line, 0)
            label = 1 if actual_count > 0 else 0
            predictions.append((f.probability, label))
            detailed.append({
                "product_line": f.product_line,
                "predicted_prob": round(f.probability, 4),
                "predicted_level": f.risk_level,
                "actual_dsa_count": actual_count,
                "label": label,
            })
        detailed.sort(key=lambda x: -x["predicted_prob"])

        # 4. 指标
        n_pos = sum(y for _, y in predictions)
        return BacktestPoint(
            cutoff_date=cutoff_dt,
            forecast_days=forecast_days,
            n_lines=len(predictions),
            n_positive=n_pos,
            base_rate=round(n_pos / len(predictions), 4) if predictions else 0.0,
            brier_score=round(compute_brier(predictions), 4),
            auc_roc=round(compute_auc_roc(predictions), 4),
            precision_at_5=round(compute_precision_at_k(predictions, 5), 4),
            precision_at_10=round(compute_precision_at_k(predictions, 10), 4),
            hit_rate_high=round(compute_hit_rate_at_threshold(predictions, 0.7), 4),
            hit_rate_critical=round(compute_hit_rate_at_threshold(predictions, 0.9), 4),
            calibration=compute_calibration(predictions, n_bins=5),
            top_predictions=detailed[:top_k_to_save],
        )

    # ── 滚动回测 ────────────────────────────────────────────────────────

    def run_rolling(
        self,
        start: str | datetime,
        end: str | datetime,
        step_days: int = 60,
        forecast_days: int = 90,
        verbose: bool = True,
    ) -> RollingBacktestResult:
        """
        滚动回测：从 start 到 end，每 step_days 取一个 cutoff，跑一次回测。

        end 必须早于"今天 - forecast_days"，否则未来真值不完整。
        """
        start_dt = start if isinstance(start, datetime) else parse_date(start)
        end_dt = end if isinstance(end, datetime) else parse_date(end)
        if start_dt is None or end_dt is None:
            raise ValueError("start/end 无法解析")

        # 安全检查：end + forecast_days 不能晚于今天
        latest_safe = datetime.now() - timedelta(days=forecast_days)
        if end_dt > latest_safe:
            if verbose:
                print(f"[警告] end={end_dt.date()} 调整为 {latest_safe.date()}（确保真值完整）")
            end_dt = latest_safe

        points: List[BacktestPoint] = []
        cur = start_dt
        while cur <= end_dt:
            if verbose:
                print(f"  回测 cutoff={cur.date()} forecast={forecast_days}d ...", end=" ", flush=True)
            try:
                p = self.run(cur, forecast_days=forecast_days)
                points.append(p)
                if verbose:
                    print(f"brier={p.brier_score:.3f} auc={p.auc_roc:.3f} "
                          f"P@10={p.precision_at_10:.2f} hit@.7={p.hit_rate_high:.2f}")
            except Exception as e:
                if verbose:
                    print(f"FAIL: {e}")
            cur = cur + timedelta(days=step_days)

        if not points:
            raise RuntimeError("滚动回测无任何成功点")

        return RollingBacktestResult(
            points=points,
            avg_brier=round(sum(p.brier_score for p in points) / len(points), 4),
            avg_auc=round(sum(p.auc_roc for p in points) / len(points), 4),
            avg_precision_at_5=round(sum(p.precision_at_5 for p in points) / len(points), 4),
            avg_precision_at_10=round(sum(p.precision_at_10 for p in points) / len(points), 4),
            avg_hit_rate_high=round(sum(p.hit_rate_high for p in points) / len(points), 4),
        )


# ────────────────────────────────────────────────────────────────────────────
# Baseline 对照（用于回答"predictor 比瞎猜/朴素基线好多少"）
# ────────────────────────────────────────────────────────────────────────────

def naive_frequency_baseline(
    db_path: str,
    cutoff: datetime,
    forecast_days: int,
    lookback_days: int = 365,
) -> List[Tuple[float, int, str]]:
    """
    朴素 baseline：以 cutoff 之前 lookback_days 内每条产品线的 DSA 月频率
    线性外推到 forecast_days，给出 P=clip(month_rate*forecast_months/threshold, 0, 1)。

    返回 [(predicted_prob, actual_label, line)]，与主预测器使用同一份真值，可直接比较。
    """
    lookback_start = cutoff - timedelta(days=lookback_days)
    end_dt = cutoff + timedelta(days=forecast_days)

    # 历史频率
    hist_counts: Dict[str, int] = {line: 0 for line in DELL_PRODUCT_LINES.keys()}
    actual_counts: Dict[str, int] = {line: 0 for line in DELL_PRODUCT_LINES.keys()}
    for title, _, pub, data_str in fetch_advisory_rows(db_path):
        pub_dt = parse_date(pub)
        if pub_dt is None:
            continue
        d = parse_advisory_data(data_str)
        affected_text = affected_text_of(d, include_version_range=False)
        for line in classify_dsa(title or "", affected_text):
            if lookback_start <= pub_dt <= cutoff:
                hist_counts[line] += 1
            if cutoff < pub_dt <= end_dt:
                actual_counts[line] += 1

    # 概率：用泊松率 1-exp(-λ*forecast)
    months_lookback = lookback_days / 30.0
    months_forecast = forecast_days / 30.0
    out: List[Tuple[float, int, str]] = []
    for line in DELL_PRODUCT_LINES.keys():
        rate = hist_counts[line] / max(months_lookback, 1.0)
        prob = 1.0 - math.exp(-rate * months_forecast)
        label = 1 if actual_counts[line] > 0 else 0
        out.append((round(prob, 4), label, line))
    return out


def compare_predictor_vs_baseline(
    db_path: str, cutoff: str | datetime, forecast_days: int = 90
) -> Dict[str, Any]:
    """
    并排对比：当前 predictor vs 朴素频率 baseline。

    回答："predictor 这一堆复杂逻辑，比朴素的'看历史频率猜未来'好多少？"
    """
    cutoff_dt = cutoff if isinstance(cutoff, datetime) else parse_date(cutoff)
    if cutoff_dt is None:
        raise ValueError(f"无法解析 cutoff: {cutoff}")

    bt = PredictionBacktester(db_path)
    point = bt.run(cutoff_dt, forecast_days=forecast_days)

    naive = naive_frequency_baseline(db_path, cutoff_dt, forecast_days)
    naive_preds = [(p, y) for p, y, _ in naive]

    return {
        "cutoff": cutoff_dt.date().isoformat(),
        "forecast_days": forecast_days,
        "n_lines": point.n_lines,
        "n_positive": point.n_positive,
        "predictor": {
            "brier": point.brier_score,
            "auc": point.auc_roc,
            "precision_at_10": point.precision_at_10,
            "hit_rate_high": point.hit_rate_high,
        },
        "naive_baseline": {
            "brier": round(compute_brier(naive_preds), 4),
            "auc": round(compute_auc_roc(naive_preds), 4),
            "precision_at_10": round(compute_precision_at_k(naive_preds, 10), 4),
            "hit_rate_high": round(compute_hit_rate_at_threshold(naive_preds, 0.7), 4),
        },
    }




def _format_report(result: RollingBacktestResult) -> str:
    """生成易读的回测报告（中文）"""
    lines = []
    lines.append("=" * 78)
    lines.append("DSA 产品线预测 - 回测报告")
    lines.append("=" * 78)
    lines.append("")
    lines.append(f"  回测点数:          {len(result.points)}")
    lines.append(f"  平均 Brier Score:  {result.avg_brier:.4f}  (越小越好, 0=完美, 0.25=随机)")
    lines.append(f"  平均 AUC-ROC:      {result.avg_auc:.4f}  (0.5=瞎猜, 1.0=完美, >=0.7 较好)")
    lines.append(f"  平均 Precision@5:  {result.avg_precision_at_5:.4f}  (top-5 高风险预测命中率)")
    lines.append(f"  平均 Precision@10: {result.avg_precision_at_10:.4f}  (top-10 高风险预测命中率)")
    lines.append(f"  平均 Hit@p>=0.7:   {result.avg_hit_rate_high:.4f}  (高置信度预测的命中率)")
    lines.append("")
    lines.append("-" * 78)
    lines.append(f"{'cutoff':12s} {'pos/total':>10s} {'base':>6s} {'brier':>7s} "
                 f"{'auc':>6s} {'P@5':>5s} {'P@10':>5s} {'hit>=.7':>8s} {'hit>=.9':>8s}")
    lines.append("-" * 78)
    for p in result.points:
        lines.append(
            f"{p.cutoff_date.date()!s:12s} "
            f"{p.n_positive:>4d}/{p.n_lines:<4d} "
            f"{p.base_rate:>6.2f} "
            f"{p.brier_score:>7.3f} "
            f"{p.auc_roc:>6.3f} "
            f"{p.precision_at_5:>5.2f} "
            f"{p.precision_at_10:>5.2f} "
            f"{p.hit_rate_high:>8.3f} "
            f"{p.hit_rate_critical:>8.3f}"
        )
    lines.append("-" * 78)
    lines.append("")
    lines.append("最近回测点 top-10 预测对照:")
    if result.points:
        last = result.points[-1]
        lines.append(f"  cutoff = {last.cutoff_date.date()}, forecast = {last.forecast_days}d")
        lines.append(f"  {'产品线':40s} {'预测概率':>10s} {'实际DSA':>10s} {'命中':>5s}")
        for tp in last.top_predictions:
            hit = "[Y]" if tp["label"] == 1 else "[N]"
            lines.append(
                f"  {tp['product_line'][:40]:40s} "
                f"{tp['predicted_prob']:>10.3f} "
                f"{tp['actual_dsa_count']:>10d} "
                f"{hit:>5s}"
            )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    """命令行入口：python -m risk.backtest"""
    import argparse
    parser = argparse.ArgumentParser(description="DSA 预测回测")
    parser.add_argument("--db", default="cve_data/cve_database.db", help="SQLite 数据库路径")
    parser.add_argument("--start", default="2024-01-01", help="滚动起点 (YYYY-MM-DD)")
    parser.add_argument("--end", default="2026-02-01", help="滚动终点")
    parser.add_argument("--step-days", type=int, default=60, help="滚动步长（天）")
    parser.add_argument("--forecast-days", type=int, default=90, help="预测窗口")
    parser.add_argument("--single", default=None, help="只跑单点回测，传 cutoff 日期")
    parser.add_argument("--compare", default=None, help="对比 predictor vs naive baseline，传 cutoff 日期")
    parser.add_argument("--out", default=None, help="把结果写入 JSON")
    args = parser.parse_args()

    bt = PredictionBacktester(args.db)
    if args.compare:
        cmp = compare_predictor_vs_baseline(args.db, args.compare, args.forecast_days)
        print(json.dumps(cmp, ensure_ascii=False, indent=2))
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(cmp, f, ensure_ascii=False, indent=2)
        return 0

    if args.single:
        p = bt.run(args.single, forecast_days=args.forecast_days)
        print(json.dumps(p.to_dict(), ensure_ascii=False, indent=2))
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(p.to_dict(), f, ensure_ascii=False, indent=2)
        return 0

    result = bt.run_rolling(
        start=args.start,
        end=args.end,
        step_days=args.step_days,
        forecast_days=args.forecast_days,
    )
    print()
    print(_format_report(result))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, ensure_ascii=False, indent=2)
        print(f"  结果已保存: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
