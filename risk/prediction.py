"""
趋势预测 (risk/prediction.py)

基于历史 CVE 数据的时间序列分析，预测未来 30/60/90 天的风险趋势。
使用简单移动平均 + 线性回归（不强依赖 statsmodels，降级可用）。

典型用法：
    from risk.prediction import TrendPredictor
    predictor = TrendPredictor(kg)
    forecast = predictor.forecast_product("Dell PowerStore", days=30)
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

from knowledge_graph import KnowledgeGraph, NODE_CVE, NODE_CWE, NODE_PRODUCT
from risk.base import TrendForecast
from risk._dsa_base import parse_date as _parse_date


class TrendPredictor:
    """趋势预测器"""

    def __init__(self, kg: KnowledgeGraph, now: Optional[datetime] = None) -> None:
        self.kg = kg
        self.now = now or datetime.now()

    def forecast_product(self, product: str, days: int = 30) -> TrendForecast:
        """
        预测产品未来 N 天的 CVE 趋势。

        方法：基于过去 6 个月的月度 CVE 数量做线性回归外推。
        """
        cves = self.kg.cves_of_product_fast(product)
        monthly_counts = self._monthly_histogram(cves, months=6)

        if not monthly_counts or sum(monthly_counts) == 0:
            return TrendForecast(
                subject=product,
                forecast_days=days,
                predicted_count=0,
                confidence_interval=(0, 0),
                risk_trend="stable",
                method="no_data",
            )

        # 线性回归预测
        n = len(monthly_counts)
        x_vals = list(range(n))
        y_vals = monthly_counts

        slope, intercept = self._linear_regression(x_vals, y_vals)
        months_ahead = days / 30.0
        predicted_monthly = max(0, intercept + slope * (n + months_ahead - 1))
        predicted_count = max(0, round(predicted_monthly * (days / 30.0)))

        # 置信区间（基于标准差）
        std_dev = self._std_dev(y_vals)
        margin = max(1, round(std_dev * 1.5 * (days / 30.0)))
        ci_low = max(0, predicted_count - margin)
        ci_high = predicted_count + margin

        # 趋势判断
        if slope > 0.5:
            trend = "rising"
        elif slope < -0.5:
            trend = "declining"
        else:
            trend = "stable"

        # 热门 CWE
        hot_cwes = self._hot_cwes(cves, months=3)

        return TrendForecast(
            subject=product,
            forecast_days=days,
            predicted_count=predicted_count,
            confidence_interval=(ci_low, ci_high),
            hot_cwes=hot_cwes[:5],
            risk_trend=trend,
            forecast_date=self.now,
            method="linear_regression",
        )

    def forecast_top_risks(self, days: int = 30, k: int = 10) -> List[TrendForecast]:
        """预测风险上升最快的 Top-K 产品"""
        all_products = [
            attr.get("label", n)
            for n, attr in self.kg.G.nodes(data=True)
            if attr.get("type") == NODE_PRODUCT
        ]

        forecasts: List[TrendForecast] = []
        for product in all_products:
            f = self.forecast_product(product, days=days)
            if f.predicted_count > 0:
                forecasts.append(f)

        forecasts.sort(key=lambda f: f.predicted_count, reverse=True)
        return forecasts[:k]

    def cwe_trends(self, months: int = 6) -> List[Tuple[str, float, str]]:
        """
        CWE 类型趋势分析。

        :return: [(CWE ID, 变化率, 趋势方向), ...] 按变化率降序
        """
        cutoff = self.now - timedelta(days=months * 30)
        half = self.now - timedelta(days=(months * 30) // 2)

        cwe_first_half: Counter = Counter()
        cwe_second_half: Counter = Counter()

        for node, attr in self.kg.G.nodes(data=True):
            if attr.get("type") != NODE_CVE:
                continue
            pub = _parse_date(attr.get("published", ""))
            if pub is None or pub < cutoff:
                continue
            for succ in self.kg.G.successors(node):
                if self.kg.G.nodes[succ].get("type") == NODE_CWE:
                    cwe_id = self.kg.G.nodes[succ].get("label", succ)
                    if pub < half:
                        cwe_first_half[cwe_id] += 1
                    else:
                        cwe_second_half[cwe_id] += 1

        results: List[Tuple[str, float, str]] = []
        all_cwes = set(cwe_first_half.keys()) | set(cwe_second_half.keys())
        for cwe in all_cwes:
            first = cwe_first_half.get(cwe, 0)
            second = cwe_second_half.get(cwe, 0)
            if first == 0 and second == 0:
                continue
            change_rate = (second - first) / max(first, 1)
            if change_rate > 0.2:
                trend = "rising"
            elif change_rate < -0.2:
                trend = "declining"
            else:
                trend = "stable"
            results.append((cwe, round(change_rate, 2), trend))

        results.sort(key=lambda x: x[1], reverse=True)
        return results

    # ── 内部方法 ────────────────────────────────────────────────────────

    def _monthly_histogram(self, cve_ids: List[str], months: int = 6) -> List[int]:
        """统计过去 N 个月每月的 CVE 数量"""
        counts = [0] * months
        for cve_id in cve_ids:
            if cve_id not in self.kg.G:
                continue
            pub = _parse_date(self.kg.G.nodes[cve_id].get("published", ""))
            if pub is None:
                continue
            delta_days = (self.now - pub).days
            month_idx = delta_days // 30
            if 0 <= month_idx < months:
                counts[months - 1 - month_idx] += 1  # 最新月在末尾
        return counts

    def _hot_cwes(self, cve_ids: List[str], months: int = 3) -> List[Tuple[str, float]]:
        """最近 N 个月的高频 CWE"""
        cutoff = self.now - timedelta(days=months * 30)
        cwe_counter: Counter = Counter()
        total = 0
        for cve_id in cve_ids:
            if cve_id not in self.kg.G:
                continue
            pub = _parse_date(self.kg.G.nodes[cve_id].get("published", ""))
            if pub is not None and pub < cutoff:
                continue
            total += 1
            for succ in self.kg.G.successors(cve_id):
                if self.kg.G.nodes[succ].get("type") == NODE_CWE:
                    cwe_counter[succ] += 1

        if total == 0:
            return []
        return [(cwe, round(cnt / total, 2)) for cwe, cnt in cwe_counter.most_common(10)]

    @staticmethod
    def _linear_regression(x: List[float], y: List[float]) -> Tuple[float, float]:
        """简单线性回归，返回 (slope, intercept)"""
        n = len(x)
        if n < 2:
            return (0.0, y[0] if y else 0.0)
        sum_x = sum(x)
        sum_y = sum(y)
        sum_xy = sum(xi * yi for xi, yi in zip(x, y))
        sum_x2 = sum(xi * xi for xi in x)
        denom = n * sum_x2 - sum_x * sum_x
        if denom == 0:
            return (0.0, sum_y / n)
        slope = (n * sum_xy - sum_x * sum_y) / denom
        intercept = (sum_y - slope * sum_x) / n
        return (slope, intercept)

    @staticmethod
    def _std_dev(values: List[float]) -> float:
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
        return math.sqrt(variance)


__all__ = ["TrendPredictor"]
