"""
风险评分引擎 (risk/scoring.py)

基于知识图谱和 SQLite 数据，对产品/CVE 计算综合风险分数 (0-100)。

评分模型（多因子加权）：
  RiskScore = α·CVSS + β·PageRank + γ·Recency
            + δ·SeverityDensity + ε·CWEDiversity + ζ·Exposure

默认权重：α=0.30, β=0.20, γ=0.15, δ=0.15, ε=0.10, ζ=0.10

典型用法：
    from knowledge_graph import KnowledgeGraph
    from risk.scoring import RiskScorer

    kg = KnowledgeGraph.load_cache("cve_data/kg_cache.pkl")
    scorer = RiskScorer(kg)
    result = scorer.score_product("Dell PowerStore")
    print(f"{result.entity_id}: {result.score:.1f} ({result.level.value})")
    print(f"Factors: {result.factors}")
"""
from __future__ import annotations

import math
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

import networkx as nx

from knowledge_graph import (
    KnowledgeGraph,
    NODE_CVE,
    NODE_PRODUCT,
    NODE_CWE,
)
from risk.base import (
    DEFAULT_SCORING_WEIGHTS,
    SEVERITY_WEIGHT_MAP,
    EntityType,
    RiskLevel,
    RiskScore,
    clip,
    normalize_score,
)


# ────────────────────────────────────────────────────────────────────────────
# 辅助函数
# ────────────────────────────────────────────────────────────────────────────

def _parse_iso_date(date_str: str) -> Optional[datetime]:
    """解析 ISO 日期字符串，失败返回 None。

    [已迁移至 risk._dsa_base.parse_date] 保留薄包装维持向后兼容。
    """
    from risk._dsa_base import parse_date as _shared_parse_date
    return _shared_parse_date(date_str)


def _days_since(date_str: str, now: Optional[datetime] = None) -> Optional[int]:
    """计算自给定日期到现在的天数"""
    dt = _parse_iso_date(date_str)
    if dt is None:
        return None
    now = now or datetime.now()
    try:
        # 对齐时区（都用 naive datetime）
        if dt.tzinfo is not None:
            dt = dt.replace(tzinfo=None)
        return max(0, (now - dt).days)
    except (TypeError, ValueError):
        return None


# ────────────────────────────────────────────────────────────────────────────
# 风险评分器
# ────────────────────────────────────────────────────────────────────────────

class RiskScorer:
    """
    风险评分引擎。

    对知识图谱中的产品/CVE 节点计算综合风险分数。
    """

    def __init__(
        self,
        kg: KnowledgeGraph,
        weights: Optional[Dict[str, float]] = None,
        now: Optional[datetime] = None,
    ) -> None:
        """
        :param kg: 已构建的知识图谱实例
        :param weights: 自定义因子权重（None 使用默认值）
        :param now: 当前时间（便于测试时固定）
        """
        self.kg = kg
        self.weights = dict(DEFAULT_SCORING_WEIGHTS)
        if weights:
            self.weights.update(weights)
        self._validate_weights()
        self.now = now or datetime.now()

        # PageRank 缓存（全图计算一次即可）
        self._pagerank_cache: Optional[Dict[str, float]] = None

        # 全图统计缓存
        self._total_products: Optional[int] = None
        self._max_cwe_count: Optional[int] = None

    # ── 权重管理 ────────────────────────────────────────────────────────

    def _validate_weights(self) -> None:
        """验证权重总和为 1.0（容差 0.01）"""
        total = sum(self.weights.values())
        if abs(total - 1.0) > 0.01:
            raise ValueError(
                f"权重总和必须为 1.0，当前为 {total:.3f}。weights={self.weights}"
            )

    # ── PageRank 懒加载 ─────────────────────────────────────────────────

    def _get_pagerank(self) -> Dict[str, float]:
        """懒加载计算全图 PageRank（仅执行一次）"""
        if self._pagerank_cache is None:
            try:
                self._pagerank_cache = nx.pagerank(
                    self.kg.G,
                    alpha=0.85,
                    max_iter=100,
                    tol=1e-6,
                )
            except (nx.PowerIterationFailedConvergence, Exception):
                # 收敛失败或其它异常，降级为入度归一化
                max_in = max(
                    (self.kg.G.in_degree(n) for n in self.kg.G.nodes()),
                    default=1,
                )
                max_in = max(max_in, 1)
                self._pagerank_cache = {
                    n: self.kg.G.in_degree(n) / max_in for n in self.kg.G.nodes()
                }
        return self._pagerank_cache

    # ── 因子计算：CVSS 平均分 ───────────────────────────────────────────

    def _compute_cvss_avg(self, cve_ids: List[str]) -> float:
        """计算 CVE 列表的 CVSS 平均分，归一化到 [0, 100]"""
        if not cve_ids:
            return 0.0
        scores: List[float] = []
        for cve_id in cve_ids:
            if cve_id not in self.kg.G:
                continue
            attr = self.kg.G.nodes[cve_id]
            raw = attr.get("score")
            if raw is None:
                continue
            try:
                scores.append(float(raw))
            except (TypeError, ValueError):
                continue
        if not scores:
            return 0.0
        avg = sum(scores) / len(scores)
        # CVSS 是 0-10，乘 10 归一化
        return clip(avg * 10.0, 0.0, 100.0)

    # ── 因子计算：PageRank ──────────────────────────────────────────────

    def _compute_pagerank_score(self, node: str) -> float:
        """节点的 PageRank 归一化到 [0, 100]"""
        pr = self._get_pagerank()
        value = pr.get(node, 0.0)
        # PageRank 分布极不均匀，用最大值归一化
        max_pr = max(pr.values()) if pr else 1.0
        if max_pr <= 0:
            return 0.0
        return clip((value / max_pr) * 100.0, 0.0, 100.0)

    # ── 因子计算：时间衰减 ─────────────────────────────────────────────

    def _compute_recency(self, cve_ids: List[str]) -> float:
        """
        时间衰减因子：最新 CVE 的发布日期越近，分数越高。
        使用指数衰减：exp(-days / 90)
        """
        if not cve_ids:
            return 0.0
        min_days: Optional[int] = None
        for cve_id in cve_ids:
            if cve_id not in self.kg.G:
                continue
            attr = self.kg.G.nodes[cve_id]
            published = attr.get("published", "")
            days = _days_since(published, self.now)
            if days is not None:
                if min_days is None or days < min_days:
                    min_days = days
        if min_days is None:
            return 0.0
        # exp(-days/90)：30 天 ≈ 0.72，90 天 ≈ 0.37，180 天 ≈ 0.14
        recency = math.exp(-min_days / 90.0)
        return clip(recency * 100.0, 0.0, 100.0)

    # ── 因子计算：严重度密度 ───────────────────────────────────────────

    def _compute_severity_density(self, cve_ids: List[str]) -> float:
        """
        严重度密度：加权平均各严重级别占比。
        weighted_sum = Σ(count_level * weight_level) / total
        """
        if not cve_ids:
            return 0.0
        weighted_sum = 0.0
        total = 0
        for cve_id in cve_ids:
            if cve_id not in self.kg.G:
                continue
            attr = self.kg.G.nodes[cve_id]
            sev = (attr.get("severity") or "").upper()
            w = SEVERITY_WEIGHT_MAP.get(sev, 0.0)
            weighted_sum += w
            total += 1
        if total == 0:
            return 0.0
        return clip((weighted_sum / total) * 100.0, 0.0, 100.0)

    # ── 因子计算：CWE 多样性 ────────────────────────────────────────────

    def _compute_cwe_diversity(self, cve_ids: List[str]) -> float:
        """
        CWE 多样性：产品关联的不同 CWE 数量 / 全图 CWE 总数
        """
        if not cve_ids:
            return 0.0
        cwes: Set[str] = set()
        for cve_id in cve_ids:
            if cve_id not in self.kg.G:
                continue
            for succ in self.kg.G.successors(cve_id):
                if self.kg.G.nodes[succ].get("type") == NODE_CWE:
                    cwes.add(succ)
        if not cwes:
            return 0.0

        # 全图 CWE 总数缓存
        if self._max_cwe_count is None:
            self._max_cwe_count = sum(
                1 for _, a in self.kg.G.nodes(data=True)
                if a.get("type") == NODE_CWE
            )
        max_count = self._max_cwe_count or 1
        # 用对数缩放：log(1+n) / log(1+max)
        ratio = math.log1p(len(cwes)) / math.log1p(max_count) if max_count > 0 else 0.0
        return clip(ratio * 100.0, 0.0, 100.0)

    # ── 因子计算：暴露度 ───────────────────────────────────────────────

    def _compute_exposure(self, product: str, cve_ids: List[str]) -> float:
        """
        暴露度：与当前产品共享 CVE 的其他产品数 / 全图产品总数
        """
        if not cve_ids:
            return 0.0
        shared_products: Set[str] = set()
        product_label = product  # 纯产品名
        for cve_id in cve_ids:
            if cve_id not in self.kg.G:
                continue
            # 找到引用此 CVE 的所有 DSA → 再找出这些 DSA 影响的其他产品
            for dsa in self.kg.G.predecessors(cve_id):
                if self.kg.G.nodes[dsa].get("type") != "dsa":
                    continue
                for p in self.kg.G.successors(dsa):
                    if self.kg.G.nodes[p].get("type") == NODE_PRODUCT:
                        label = self.kg.G.nodes[p].get("label", "")
                        if label and label != product_label:
                            shared_products.add(label)

        # 全图产品总数缓存
        if self._total_products is None:
            self._total_products = sum(
                1 for _, a in self.kg.G.nodes(data=True)
                if a.get("type") == NODE_PRODUCT
            )
        total = self._total_products or 1
        ratio = len(shared_products) / total if total > 0 else 0.0
        # 用平方根缩放（避免少数头部产品过度放大）
        return clip(math.sqrt(ratio) * 100.0, 0.0, 100.0)

    # ── 核心 API：产品评分 ─────────────────────────────────────────────

    def score_product(self, product: str) -> RiskScore:
        """
        对单个产品节点计算综合风险分数。

        :param product: 产品名（如 "Dell PowerStore"）或节点 ID（"product::Dell PowerStore"）
        :return: RiskScore 对象
        """
        # 解析节点
        node = self.kg._resolve_node(product)
        if node not in self.kg.G:
            # 节点不存在，返回空评分
            return RiskScore(
                entity_id=product,
                entity_type=EntityType.PRODUCT,
                score=0.0,
                level=RiskLevel.INFO,
                factors={k: 0.0 for k in self.weights},
                evidence=[],
            )

        # 获取产品 label（去掉 product:: 前缀）
        product_label = self.kg.G.nodes[node].get("label", product)

        # 查询关联 CVE（使用反向索引）
        cve_ids = self.kg.cves_of_product_fast(product_label)

        # 计算各因子
        factors = {
            "cvss_avg": self._compute_cvss_avg(cve_ids),
            "pagerank": self._compute_pagerank_score(node),
            "recency": self._compute_recency(cve_ids),
            "severity_density": self._compute_severity_density(cve_ids),
            "cwe_diversity": self._compute_cwe_diversity(cve_ids),
            "exposure": self._compute_exposure(product_label, cve_ids),
        }

        # 加权求和
        total_score = sum(
            factors[k] * self.weights[k]
            for k in self.weights
            if k in factors
        )
        total_score = clip(total_score, 0.0, 100.0)

        # 证据：最多保留 10 个关键 CVE（按 CVSS 降序）
        evidence = self._select_evidence(cve_ids, max_count=10)

        return RiskScore(
            entity_id=product_label,
            entity_type=EntityType.PRODUCT,
            score=round(total_score, 2),
            level=RiskLevel.from_score(total_score),
            factors={k: round(v, 2) for k, v in factors.items()},
            evidence=evidence,
        )

    # ── 核心 API：CVE 评分 ──────────────────────────────────────────────

    def score_cve(self, cve_id: str) -> RiskScore:
        """
        对单个 CVE 计算风险分数（简化版：CVSS + PageRank + Recency + Severity）。
        """
        cve_id = cve_id.strip().upper()
        if cve_id not in self.kg.G:
            return RiskScore(
                entity_id=cve_id,
                entity_type=EntityType.CVE,
                score=0.0,
                level=RiskLevel.INFO,
                factors={},
                evidence=[],
            )

        attr = self.kg.G.nodes[cve_id]
        raw_score = attr.get("score") or 0.0
        try:
            cvss_score = float(raw_score) * 10.0
        except (TypeError, ValueError):
            cvss_score = 0.0

        factors = {
            "cvss": clip(cvss_score, 0.0, 100.0),
            "pagerank": self._compute_pagerank_score(cve_id),
            "recency": self._compute_recency([cve_id]),
            "severity": SEVERITY_WEIGHT_MAP.get(
                (attr.get("severity") or "").upper(), 0.0
            ) * 100.0,
        }

        # CVE 评分用固定权重（CVSS 占大头）
        weights = {"cvss": 0.5, "pagerank": 0.15, "recency": 0.15, "severity": 0.2}
        total = sum(factors[k] * weights[k] for k in weights)
        total = clip(total, 0.0, 100.0)

        # 证据：关联的 DSA 和 CWE
        evidence: List[str] = []
        evidence.extend(self.kg.dsas_of_cve_fast(cve_id)[:5])
        for succ in self.kg.G.successors(cve_id):
            if self.kg.G.nodes[succ].get("type") == NODE_CWE:
                evidence.append(succ)
                if len(evidence) >= 10:
                    break

        return RiskScore(
            entity_id=cve_id,
            entity_type=EntityType.CVE,
            score=round(total, 2),
            level=RiskLevel.from_score(total),
            factors={k: round(v, 2) for k, v in factors.items()},
            evidence=evidence,
        )

    # ── 核心 API：批量评分 ─────────────────────────────────────────────

    def score_all_products(
        self,
        min_score: float = 0.0,
        limit: Optional[int] = None,
    ) -> List[RiskScore]:
        """
        对图中所有产品节点批量评分。

        :param min_score: 过滤阈值，只返回 score >= min_score 的结果
        :param limit: 最大返回数量（按 score 降序）
        :return: 按 score 降序排列的 RiskScore 列表
        """
        results: List[RiskScore] = []
        for node, attr in self.kg.G.nodes(data=True):
            if attr.get("type") != NODE_PRODUCT:
                continue
            label = attr.get("label", node)
            result = self.score_product(label)
            if result.score >= min_score:
                results.append(result)

        results.sort(key=lambda r: r.score, reverse=True)
        if limit:
            results = results[:limit]
        return results

    # ── 可解释性 ────────────────────────────────────────────────────────

    def explain(self, product: str) -> Dict[str, Any]:
        """
        返回评分的详细解释，用于 UI 展示或调试。

        :return: {
            "score": 87.3,
            "level": "HIGH",
            "factors": {...},
            "contributions": {...},  # 各因子对总分的绝对贡献
            "top_cves": [...],       # 贡献最大的前 5 个 CVE
        }
        """
        score = self.score_product(product)

        # 计算各因子对总分的绝对贡献
        contributions = {
            k: round(score.factors.get(k, 0.0) * self.weights.get(k, 0.0), 2)
            for k in self.weights
        }

        return {
            "entity_id": score.entity_id,
            "score": score.score,
            "level": score.level.value,
            "factors": score.factors,
            "contributions": contributions,
            "weights": self.weights,
            "top_cves": score.evidence[:5],
        }

    # ── 工具方法 ────────────────────────────────────────────────────────

    def _select_evidence(
        self, cve_ids: List[str], max_count: int = 10
    ) -> List[str]:
        """从 CVE 列表中选出最关键的证据（按 CVSS 降序）"""
        scored: List[tuple] = []
        for cid in cve_ids:
            if cid not in self.kg.G:
                continue
            attr = self.kg.G.nodes[cid]
            score = attr.get("score") or 0.0
            try:
                score = float(score)
            except (TypeError, ValueError):
                score = 0.0
            scored.append((cid, score))
        scored.sort(key=lambda x: x[1], reverse=True)
        return [cid for cid, _ in scored[:max_count]]


__all__ = ["RiskScorer"]
