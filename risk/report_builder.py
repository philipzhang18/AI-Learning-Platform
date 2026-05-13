"""
报告编排与建议生成 (risk/report_builder.py)

聚合所有分析模块的输出，生成完整的风险报告。
支持 JSON / Markdown 两种输出格式。

典型用法：
    from risk.report_builder import RiskReportBuilder
    builder = RiskReportBuilder(kg, rules_dir="risk/rules")
    report = builder.analyze_product("Dell PowerStore")
    md = builder.to_markdown(report)
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

from knowledge_graph import KnowledgeGraph, NODE_CVE, NODE_CWE
from risk.base import (
    EntityType,
    Priority,
    Recommendation,
    RiskContext,
    RiskLevel,
    RiskReport,
    RiskScore,
)
from risk.propagation import PropagationAnalyzer
from risk.prediction import TrendPredictor
from risk.rules import RuleEngine
from risk.scoring import RiskScorer
from risk.similarity import ProductSimilarityAnalyzer


class RiskReportBuilder:
    """
    风险报告编排器：聚合评分、传播、预测、规则、相似度分析。
    """

    def __init__(
        self,
        kg: KnowledgeGraph,
        rules_dir: Optional[str | Path] = None,
        now: Optional[datetime] = None,
    ) -> None:
        self.kg = kg
        self.now = now or datetime.now()
        self.scorer = RiskScorer(kg, now=self.now)
        self.propagation = PropagationAnalyzer(kg)
        self.predictor = TrendPredictor(kg, now=self.now)
        self.similarity = ProductSimilarityAnalyzer(kg)

        rules_path = Path(rules_dir) if rules_dir else Path(__file__).parent / "rules"
        self.rule_engine = RuleEngine.from_directory(rules_path)

    def analyze_product(self, product: str) -> RiskReport:
        """对单个产品执行完整风险分析"""
        # 1. 风险评分
        score = self.scorer.score_product(product)

        # 2. 获取关联数据
        cves = self.kg.cves_of_product_fast(product)
        cwes = self._get_product_cwes(product, cves)
        severities = self._get_cve_severities(cves)

        # 3. 传播分析（取前 3 个高危 CVE）
        high_cves = [c for c in cves if self._cve_severity(c) in ("CRITICAL", "HIGH")][:3]
        impact_paths = []
        for cve_id in high_cves:
            paths = self.propagation.trace_impact(cve_id, max_hops=2)
            impact_paths.extend(paths[:5])

        # 4. 趋势预测
        forecast = self.predictor.forecast_product(product, days=30)

        # 5. 规则匹配
        latest_days = self._latest_cve_days(cves)
        ctx = RiskContext(
            entity_id=product,
            entity_type=EntityType.PRODUCT,
            related_cves=cves[:50],
            related_cwes=list(cwes),
            metadata={
                "cve_severities": severities,
                "risk_score": score.score,
                "latest_cve_days": latest_days,
            },
        )
        rule_matches = self.rule_engine.evaluate(ctx)

        # 6. 汇总建议
        recommendations = self._aggregate_recommendations(rule_matches, score, forecast)

        # 7. 统计摘要
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for s in severities:
            if s in severity_counts:
                severity_counts[s] += 1

        return RiskReport(
            report_id=f"RPT-{uuid.uuid4().hex[:8]}",
            subject=product,
            subject_type=EntityType.PRODUCT,
            generated_at=self.now,
            summary=severity_counts,
            risk_scores=[score],
            impact_paths=impact_paths[:15],
            trend_forecast=forecast,
            recommendations=recommendations,
            rule_matches=rule_matches,
            metadata={
                "total_cves": len(cves),
                "total_cwes": len(cwes),
                "similar_products": [
                    (p, s) for p, s in self.similarity.similar_products(product, k=3)
                ],
            },
        )

    def analyze_top_products(self, k: int = 10, min_score: float = 30.0) -> List[RiskReport]:
        """批量分析 Top-K 高风险产品"""
        scores = self.scorer.score_all_products(min_score=min_score, limit=k)
        reports = []
        for s in scores:
            report = self.analyze_product(s.entity_id)
            reports.append(report)
        return reports

    # ── 输出格式 ────────────────────────────────────────────────────────

    def to_json(self, report: RiskReport) -> str:
        """输出 JSON 格式"""
        return json.dumps(report.to_dict(), ensure_ascii=False, indent=2)

    def to_markdown(self, report: RiskReport) -> str:
        """输出 Markdown 格式的风险报告"""
        lines: List[str] = []
        score = report.risk_scores[0] if report.risk_scores else None

        lines.append(f"# 风险分析报告: {report.subject}")
        lines.append(f"")
        lines.append(f"**生成时间**: {report.generated_at.strftime('%Y-%m-%d %H:%M')}")
        lines.append(f"**报告 ID**: {report.report_id}")
        lines.append(f"")

        # 风险评分
        if score:
            level_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}
            emoji = level_emoji.get(score.level.value, "⚪")
            lines.append(f"## 综合风险评分")
            lines.append(f"")
            lines.append(f"**{emoji} {score.score:.1f} / 100 ({score.level.value})**")
            lines.append(f"")
            lines.append(f"| 因子 | 得分 | 权重 | 贡献 |")
            lines.append(f"|------|------|------|------|")
            for k, v in score.factors.items():
                weight = self.scorer.weights.get(k, 0)
                contrib = v * weight
                lines.append(f"| {k} | {v:.1f} | {weight:.0%} | {contrib:.1f} |")
            lines.append(f"")

        # 漏洞统计
        lines.append(f"## 漏洞统计")
        lines.append(f"")
        lines.append(f"| 等级 | 数量 |")
        lines.append(f"|------|------|")
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            lines.append(f"| {level} | {report.summary.get(level, 0)} |")
        lines.append(f"| **总计** | **{report.metadata.get('total_cves', 0)}** |")
        lines.append(f"")

        # 趋势预测
        if report.trend_forecast and report.trend_forecast.method != "no_data":
            f = report.trend_forecast
            trend_arrow = {"rising": "↑ 上升", "stable": "→ 稳定", "declining": "↓ 下降"}
            lines.append(f"## 趋势预测（未来 {f.forecast_days} 天）")
            lines.append(f"")
            lines.append(f"- **预测新增 CVE**: {f.predicted_count} 个 (置信区间: {f.confidence_interval[0]}-{f.confidence_interval[1]})")
            lines.append(f"- **风险趋势**: {trend_arrow.get(f.risk_trend, f.risk_trend)}")
            if f.hot_cwes:
                lines.append(f"- **高频 CWE**: {', '.join(c[0] for c in f.hot_cwes[:3])}")
            lines.append(f"")

        # 预防性维护建议
        if report.recommendations:
            lines.append(f"## 预防性维护建议")
            lines.append(f"")
            for i, rec in enumerate(report.recommendations, 1):
                lines.append(f"### {i}. [{rec.priority.value}] {rec.title}")
                lines.append(f"")
                lines.append(f"- **时间线**: {rec.timeline}")
                lines.append(f"- **类型**: {rec.action_type}")
                lines.append(f"- **工作量**: {rec.estimated_effort}")
                if rec.description:
                    lines.append(f"- **说明**: {rec.description}")
                lines.append(f"")

        # 传播影响
        if report.impact_paths:
            lines.append(f"## 风险传播分析")
            lines.append(f"")
            lines.append(f"| 源 CVE | 影响产品 | 跳数 | 可信度 | 共享 CWE |")
            lines.append(f"|--------|---------|------|--------|---------|")
            for p in report.impact_paths[:10]:
                cwes = ", ".join(p.shared_cwes[:3])
                lines.append(f"| {p.source_cve} | {p.target_product} | {p.hops} | {p.confidence:.0%} | {cwes} |")
            lines.append(f"")

        # 相似产品
        similar = report.metadata.get("similar_products", [])
        if similar:
            lines.append(f"## 相似产品（可能存在同类风险）")
            lines.append(f"")
            for prod, sim in similar:
                lines.append(f"- {prod} (相似度: {sim:.0%})")
            lines.append(f"")

        # 触发规则
        if report.rule_matches:
            lines.append(f"## 触发的安全规则")
            lines.append(f"")
            for m in report.rule_matches:
                lines.append(f"- **[{m.severity.value}]** {m.rule_name} (规则 {m.rule_id})")
            lines.append(f"")

        lines.append(f"---")
        lines.append(f"*本报告由 CVE 风险分析引擎自动生成*")
        return "\n".join(lines)

    # ── 内部方法 ────────────────────────────────────────────────────────

    def _get_product_cwes(self, product: str, cves: List[str]) -> Set[str]:
        cwes: Set[str] = set()
        for cve_id in cves:
            if cve_id not in self.kg.G:
                continue
            for succ in self.kg.G.successors(cve_id):
                if self.kg.G.nodes[succ].get("type") == NODE_CWE:
                    cwes.add(succ)
        return cwes

    def _get_cve_severities(self, cves: List[str]) -> List[str]:
        severities = []
        for cve_id in cves:
            if cve_id not in self.kg.G:
                continue
            sev = (self.kg.G.nodes[cve_id].get("severity") or "").upper()
            if sev:
                severities.append(sev)
        return severities

    def _cve_severity(self, cve_id: str) -> str:
        if cve_id not in self.kg.G:
            return ""
        return (self.kg.G.nodes[cve_id].get("severity") or "").upper()

    def _latest_cve_days(self, cves: List[str]) -> int:
        from risk.scoring import _days_since
        min_days = 9999
        for cve_id in cves:
            if cve_id not in self.kg.G:
                continue
            pub = self.kg.G.nodes[cve_id].get("published", "")
            days = _days_since(pub, self.now)
            if days is not None and days < min_days:
                min_days = days
        return min_days

    def _aggregate_recommendations(
        self, rule_matches, score: RiskScore, forecast
    ) -> List[Recommendation]:
        """聚合规则触发的建议，按优先级排序去重"""
        recs: List[Recommendation] = []
        seen_titles: Set[str] = set()

        for match in rule_matches:
            for rec in match.recommendations:
                if rec.title not in seen_titles:
                    seen_titles.add(rec.title)
                    recs.append(rec)

        # 按优先级排序
        priority_order = {Priority.P0: 0, Priority.P1: 1, Priority.P2: 2, Priority.P3: 3, Priority.P4: 4}
        recs.sort(key=lambda r: priority_order.get(r.priority, 5))
        return recs


__all__ = ["RiskReportBuilder"]
