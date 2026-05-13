"""
产品相似度分析 (risk/similarity.py)

基于知识图谱中的 CWE 和 CVE 共享关系计算产品间相似度。
用于：发现同类风险产品、预警"类似产品可能受影响"。

典型用法：
    from risk.similarity import ProductSimilarityAnalyzer
    analyzer = ProductSimilarityAnalyzer(kg)
    similar = analyzer.similar_products("Dell PowerStore", k=5)
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Set, Tuple

from knowledge_graph import KnowledgeGraph, NODE_PRODUCT, NODE_CWE


class ProductSimilarityAnalyzer:
    """产品相似度分析器"""

    def __init__(self, kg: KnowledgeGraph) -> None:
        self.kg = kg
        self._product_cwes_cache: Dict[str, Set[str]] = {}
        self._product_cves_cache: Dict[str, Set[str]] = {}

    def _get_product_cwes(self, product: str) -> Set[str]:
        if product in self._product_cwes_cache:
            return self._product_cwes_cache[product]
        cves = self.kg.cves_of_product_fast(product)
        cwes: Set[str] = set()
        for cve_id in cves:
            if cve_id not in self.kg.G:
                continue
            for succ in self.kg.G.successors(cve_id):
                if self.kg.G.nodes[succ].get("type") == NODE_CWE:
                    cwes.add(succ)
        self._product_cwes_cache[product] = cwes
        return cwes

    def _get_product_cves(self, product: str) -> Set[str]:
        if product in self._product_cves_cache:
            return self._product_cves_cache[product]
        cves = set(self.kg.cves_of_product_fast(product))
        self._product_cves_cache[product] = cves
        return cves

    def similarity(self, product_a: str, product_b: str) -> float:
        """
        计算两个产品的相似度 (0-1)。

        公式：0.6 * Jaccard(CWE_A, CWE_B) + 0.4 * Jaccard(CVE_A, CVE_B)
        """
        cwes_a = self._get_product_cwes(product_a)
        cwes_b = self._get_product_cwes(product_b)
        cves_a = self._get_product_cves(product_a)
        cves_b = self._get_product_cves(product_b)

        cwe_sim = self._jaccard(cwes_a, cwes_b)
        cve_sim = self._jaccard(cves_a, cves_b)

        return round(0.6 * cwe_sim + 0.4 * cve_sim, 4)

    def similar_products(self, product: str, k: int = 5) -> List[Tuple[str, float]]:
        """
        查找与给定产品最相似的 Top-K 产品。

        :return: [(产品名, 相似度), ...] 按相似度降序
        """
        all_products = [
            attr.get("label", n)
            for n, attr in self.kg.G.nodes(data=True)
            if attr.get("type") == NODE_PRODUCT
        ]

        scores: List[Tuple[str, float]] = []
        for other in all_products:
            if other == product:
                continue
            sim = self.similarity(product, other)
            if sim > 0:
                scores.append((other, sim))

        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:k]

    def cluster_products(self, min_similarity: float = 0.3) -> List[List[str]]:
        """
        简单聚类：将相似度 >= min_similarity 的产品归为一组。
        使用 Union-Find 实现连通分量。
        """
        all_products = [
            attr.get("label", n)
            for n, attr in self.kg.G.nodes(data=True)
            if attr.get("type") == NODE_PRODUCT
        ]

        parent: Dict[str, str] = {p: p for p in all_products}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        for i, pa in enumerate(all_products):
            for pb in all_products[i + 1:]:
                if self.similarity(pa, pb) >= min_similarity:
                    union(pa, pb)

        clusters: Dict[str, List[str]] = defaultdict(list)
        for p in all_products:
            clusters[find(p)].append(p)

        return [c for c in clusters.values() if len(c) > 1]

    @staticmethod
    def _jaccard(set_a: Set[str], set_b: Set[str]) -> float:
        if not set_a and not set_b:
            return 0.0
        intersection = len(set_a & set_b)
        union = len(set_a | set_b)
        return intersection / union if union > 0 else 0.0


__all__ = ["ProductSimilarityAnalyzer"]
