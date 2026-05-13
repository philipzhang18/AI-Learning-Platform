"""
风险传播分析 (risk/propagation.py)

分析某个 CVE 或产品的风险如何通过知识图谱传播到其他实体。
核心思路：CVE → DSA → Product 的多跳传播，通过共享 CWE 计算传播可信度。

典型用法：
    from risk.propagation import PropagationAnalyzer
    analyzer = PropagationAnalyzer(kg)
    paths = analyzer.trace_impact("CVE-2024-0001", max_hops=2)
    radius = analyzer.affected_radius("CVE-2024-0001")
"""
from __future__ import annotations

import math
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from knowledge_graph import KnowledgeGraph, NODE_CVE, NODE_DSA, NODE_PRODUCT, NODE_CWE
from risk.base import ImpactPath


class PropagationAnalyzer:
    """风险传播分析器"""

    def __init__(self, kg: KnowledgeGraph, decay_factor: float = 0.6) -> None:
        self.kg = kg
        self.decay_factor = decay_factor

    def trace_impact(self, cve_id: str, max_hops: int = 2) -> List[ImpactPath]:
        """
        追踪 CVE 的传播影响路径。

        传播逻辑：
        - 1-hop: CVE → (DSA mentions) → 直接受影响产品
        - 2-hop: 直接产品 → (共享 DSA) → 间接受影响产品

        :param cve_id: 源 CVE ID
        :param max_hops: 最大传播跳数
        :return: 按可信度降序排列的影响路径列表
        """
        cve_id = cve_id.strip().upper()
        if cve_id not in self.kg.G:
            return []

        source_cwes = self._get_cwes_of_cve(cve_id)
        paths: List[ImpactPath] = []

        # 1-hop: CVE → DSA → Product (直接影响)
        direct_products: Set[str] = set()
        for dsa in self.kg.G.predecessors(cve_id):
            if self.kg.G.nodes[dsa].get("type") != "dsa":
                continue
            for prod_node in self.kg.G.successors(dsa):
                if self.kg.G.nodes[prod_node].get("type") != NODE_PRODUCT:
                    continue
                label = self.kg.G.nodes[prod_node].get("label", prod_node)
                if label in direct_products:
                    continue
                direct_products.add(label)
                paths.append(ImpactPath(
                    source_cve=cve_id,
                    target_product=label,
                    hops=1,
                    path=[cve_id, dsa, prod_node],
                    confidence=1.0,
                    shared_cwes=list(source_cwes),
                ))

        if max_hops < 2:
            return sorted(paths, key=lambda p: p.confidence, reverse=True)

        # 2-hop: 直接产品 → 共享 CVE → 间接产品
        indirect_products: Dict[str, ImpactPath] = {}
        for direct_prod in direct_products:
            prod_node = f"product::{direct_prod}"
            if prod_node not in self.kg.G:
                continue
            for dsa2 in self.kg.G.predecessors(prod_node):
                if self.kg.G.nodes[dsa2].get("type") != "dsa":
                    continue
                for cve2_node in self.kg.G.successors(dsa2):
                    if self.kg.G.nodes[cve2_node].get("type") != NODE_CVE:
                        continue
                    if cve2_node == cve_id:
                        continue
                    cve2_cwes = self._get_cwes_of_cve(cve2_node)
                    shared = source_cwes & cve2_cwes
                    if not shared:
                        continue
                    # 找 cve2 影响的其他产品
                    for dsa3 in self.kg.G.predecessors(cve2_node):
                        if self.kg.G.nodes[dsa3].get("type") != "dsa":
                            continue
                        for prod3 in self.kg.G.successors(dsa3):
                            if self.kg.G.nodes[prod3].get("type") != NODE_PRODUCT:
                                continue
                            label3 = self.kg.G.nodes[prod3].get("label", prod3)
                            if label3 in direct_products:
                                continue
                            confidence = (len(shared) / max(len(source_cwes), 1)) * self.decay_factor
                            if label3 not in indirect_products or confidence > indirect_products[label3].confidence:
                                indirect_products[label3] = ImpactPath(
                                    source_cve=cve_id,
                                    target_product=label3,
                                    hops=2,
                                    path=[cve_id, prod_node, cve2_node, prod3],
                                    confidence=round(confidence, 3),
                                    shared_cwes=list(shared),
                                )

        paths.extend(indirect_products.values())
        return sorted(paths, key=lambda p: (-p.confidence, p.hops))

    def affected_radius(self, cve_id: str, max_hops: int = 2) -> Dict[int, List[str]]:
        """按跳数返回受影响产品"""
        paths = self.trace_impact(cve_id, max_hops=max_hops)
        result: Dict[int, List[str]] = defaultdict(list)
        for p in paths:
            result[p.hops].append(p.target_product)
        return dict(result)

    def shared_vulnerabilities(self, product_a: str, product_b: str) -> List[str]:
        """两个产品的共享漏洞"""
        cves_a = set(self.kg.cves_of_product_fast(product_a))
        cves_b = set(self.kg.cves_of_product_fast(product_b))
        return sorted(cves_a & cves_b)

    def _get_cwes_of_cve(self, cve_id: str) -> Set[str]:
        if cve_id not in self.kg.G:
            return set()
        cwes: Set[str] = set()
        for succ in self.kg.G.successors(cve_id):
            if self.kg.G.nodes[succ].get("type") == NODE_CWE:
                cwes.add(succ)
        return cwes


__all__ = ["PropagationAnalyzer"]
