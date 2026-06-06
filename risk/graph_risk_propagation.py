"""
产品组件共享图谱推理 (risk/graph_risk_propagation.py)

核心假设
--------
1. 如果产品A 和产品B 共享多个 CVE（经 DSA 中介），它们很可能共享底层组件
2. 共享组件越多，一个产品出 DSA 后另一个也出 DSA 的概率越高

这是本项目的**差异化能力**：竞品只看单产品历史频率，我们通过图谱做风险传导。

------------------------------------------------------------
实现
------------------------------------------------------------
1. component_sharing_matrix：
   - 对每对 (产品A, 产品B)，计算 Jaccard(CVEs_A, CVEs_B)
   - Jaccard > 0.1 → 视为共享组件

2. propagate_risk：
   - 当产品X 出新 DSA 时，通过共享矩阵传播风险到关联产品
   - 传播强度 = Jaccard(X, Y) × event_severity_weight

3. predict_next_affected：
   - 给定一组刚出 DSA 的产品，预测下一个最可能受影响的
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx

from knowledge_graph import KnowledgeGraph, NODE_CVE, NODE_DSA, NODE_PRODUCT


# ────────────────────────────────────────────────────────────────────────────
# 数据结构
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class ProductPairSharing:
    """产品对的组件共享分数"""
    product_a: str
    product_b: str
    shared_cve_count: int
    jaccard: float  # |A∩B| / |A∪B|


@dataclass
class PropagatedRisk:
    """风险传导结果"""
    product: str
    risk_score: float       # 传导到该产品的累积风险
    source_products: List[str]  # 哪些源产品传导了风险
    shared_cves: int        # 与源产品共享的 CVE 数


# ────────────────────────────────────────────────────────────────────────────
# 图谱风险传导器
# ────────────────────────────────────────────────────────────────────────────

class GraphRiskPropagator:
    """
    基于知识图谱的产品风险传导。

    用法：
        kg = KnowledgeGraph.from_sqlite("cve_data/cve_database.db")
        kg.build()
        prop = GraphRiskPropagator(kg)
        # 查看产品间共享程度
        matrix = prop.component_sharing_matrix()
        # 某产品出 DSA 后传导风险
        risks = prop.propagate_risk("PowerEdge R740", severity=0.9)
        # 预测下一个受影响的
        preds = prop.predict_next_affected(["PowerEdge R740", "iDRAC9"])
    """

    def __init__(self, kg: KnowledgeGraph, min_jaccard: float = 0.05) -> None:
        self.kg = kg
        self.min_jaccard = min_jaccard
        self._product_cve_sets: Optional[Dict[str, Set[str]]] = None
        self._sharing_matrix: Optional[Dict[Tuple[str, str], float]] = None

    def _ensure_product_cve_sets(self) -> Dict[str, Set[str]]:
        """构建 {product_label: set(cve_ids)} 映射"""
        if self._product_cve_sets is not None:
            return self._product_cve_sets

        if not self.kg._built:
            self.kg.build()

        product_cves: Dict[str, Set[str]] = {}
        for node, attr in self.kg.G.nodes(data=True):
            if attr.get("type") != NODE_PRODUCT:
                continue
            label = attr.get("label", node)
            # 通过 DSA 中介找到该产品关联的 CVE
            cves: Set[str] = set()
            for dsa in self.kg.G.predecessors(node):
                if self.kg.G.nodes[dsa].get("type") != NODE_DSA:
                    continue
                for c in self.kg.G.successors(dsa):
                    if self.kg.G.nodes[c].get("type") == NODE_CVE:
                        cves.add(c)
            if cves:  # 只保留有 CVE 关联的产品
                product_cves[label] = cves

        self._product_cve_sets = product_cves
        return product_cves

    def component_sharing_matrix(
        self, top_k: int = 50
    ) -> List[ProductPairSharing]:
        """
        计算产品对之间的 CVE 共享分数（Jaccard 相似度）。

        返回 Jaccard 最高的 top_k 对。
        Jaccard(A,B) = |CVEs_A ∩ CVEs_B| / |CVEs_A ∪ CVEs_B|

        直觉：如果两个产品被同一批 CVE 影响，它们很可能共享底层组件。
        """
        product_cves = self._ensure_product_cve_sets()
        products = list(product_cves.keys())

        pairs: List[ProductPairSharing] = []
        for i in range(len(products)):
            for j in range(i + 1, len(products)):
                a, b = products[i], products[j]
                cves_a, cves_b = product_cves[a], product_cves[b]
                intersection = cves_a & cves_b
                if not intersection:
                    continue
                union = cves_a | cves_b
                jaccard = len(intersection) / len(union) if union else 0.0
                if jaccard >= self.min_jaccard:
                    pairs.append(ProductPairSharing(
                        product_a=a, product_b=b,
                        shared_cve_count=len(intersection),
                        jaccard=round(jaccard, 4),
                    ))

        # 按 Jaccard 降序
        pairs.sort(key=lambda p: -p.jaccard)
        return pairs[:top_k]

    def propagate_risk(
        self,
        source_product: str,
        severity: float = 1.0,
        decay: float = 1.0,
        top_k: int = 20,
    ) -> List[PropagatedRisk]:
        """
        当 source_product 出现新 DSA 时，通过图谱传播风险到关联产品。

        传播公式：risk(Y) = jaccard(X, Y) × severity × decay
        - severity: 事件严重程度权重（CVSS/10 或自定义）
        - decay: 全局衰减系数
        """
        product_cves = self._ensure_product_cve_sets()
        if source_product not in product_cves:
            # 尝试模糊匹配
            source_product = self._fuzzy_match(source_product)
            if source_product is None:
                return []

        source_cves = product_cves[source_product]
        results: List[PropagatedRisk] = []

        for product, cves in product_cves.items():
            if product == source_product:
                continue
            shared = source_cves & cves
            if not shared:
                continue
            union = source_cves | cves
            jaccard = len(shared) / len(union) if union else 0.0
            risk_score = jaccard * severity * decay
            if risk_score > 0.01:  # 过滤噪声
                results.append(PropagatedRisk(
                    product=product,
                    risk_score=round(risk_score, 4),
                    source_products=[source_product],
                    shared_cves=len(shared),
                ))

        results.sort(key=lambda r: -r.risk_score)
        return results[:top_k]

    def predict_next_affected(
        self,
        affected_products: List[str],
        top_k: int = 10,
    ) -> List[PropagatedRisk]:
        """
        给定一组已出 DSA 的产品，预测下一个最可能受影响的。

        多源传导：risk(Y) = sum(jaccard(Xi, Y)) for Xi in affected_products
        """
        product_cves = self._ensure_product_cve_sets()

        # 解析源产品
        resolved_sources: List[str] = []
        for p in affected_products:
            if p in product_cves:
                resolved_sources.append(p)
            else:
                match = self._fuzzy_match(p)
                if match:
                    resolved_sources.append(match)
        if not resolved_sources:
            return []

        # 累积风险
        risk_map: Dict[str, float] = defaultdict(float)
        shared_map: Dict[str, int] = defaultdict(int)
        source_map: Dict[str, List[str]] = defaultdict(list)

        for source in resolved_sources:
            source_cves = product_cves[source]
            for product, cves in product_cves.items():
                if product in resolved_sources:
                    continue
                shared = source_cves & cves
                if not shared:
                    continue
                union = source_cves | cves
                jaccard = len(shared) / len(union) if union else 0.0
                risk_map[product] += jaccard
                shared_map[product] += len(shared)
                source_map[product].append(source)

        results: List[PropagatedRisk] = []
        for product, score in risk_map.items():
            results.append(PropagatedRisk(
                product=product,
                risk_score=round(score, 4),
                source_products=source_map[product],
                shared_cves=shared_map[product],
            ))

        results.sort(key=lambda r: -r.risk_score)
        return results[:top_k]

    def _fuzzy_match(self, name: str) -> Optional[str]:
        """简单模糊匹配：在已知产品中找包含 name 的"""
        product_cves = self._ensure_product_cve_sets()
        name_lower = name.lower()
        for product in product_cves:
            if name_lower in product.lower():
                return product
        return None

    def summary(self) -> Dict[str, Any]:
        """图谱风险传导模块摘要统计"""
        product_cves = self._ensure_product_cve_sets()
        pairs = self.component_sharing_matrix(top_k=100)
        return {
            "n_products": len(product_cves),
            "n_products_with_10plus_cves": sum(1 for v in product_cves.values() if len(v) >= 10),
            "n_sharing_pairs": len(pairs),
            "top_sharing_pair": asdict(pairs[0]) if pairs else None,
            "avg_jaccard_top10": round(sum(p.jaccard for p in pairs[:10]) / max(len(pairs[:10]), 1), 4),
        }


# ────────────────────────────────────────────────────────────────────────────
# CLI / 演示
# ────────────────────────────────────────────────────────────────────────────

def main() -> int:
    import json

    print("构建知识图谱...")
    kg = KnowledgeGraph.from_sqlite("cve_data/cve_database.db")
    kg.build()

    prop = GraphRiskPropagator(kg, min_jaccard=0.05)
    print(f"知识图谱节点: {kg.G.number_of_nodes()}, 边: {kg.G.number_of_edges()}")

    # 摘要
    s = prop.summary()
    print(f"\n产品数: {s['n_products']} (>=10 CVEs: {s['n_products_with_10plus_cves']})")
    print(f"共享对数(jaccard>=0.05): {s['n_sharing_pairs']}")
    if s["top_sharing_pair"]:
        tp = s["top_sharing_pair"]
        print(f"最强共享: {tp['product_a']} <-> {tp['product_b']} "
              f"(jaccard={tp['jaccard']}, shared_cves={tp['shared_cve_count']})")

    # Top-10 共享对
    print("\n--- Top-10 产品共享对 ---")
    pairs = prop.component_sharing_matrix(top_k=10)
    print(f"{'产品A':30s} {'产品B':30s} {'Jaccard':>8s} {'共享CVE':>8s}")
    for p in pairs:
        print(f"{p.product_a[:30]:30s} {p.product_b[:30]:30s} "
              f"{p.jaccard:>8.4f} {p.shared_cve_count:>8d}")

    # 风险传导示例
    if pairs:
        source = pairs[0].product_a
        print(f"\n--- 风险传导: {source} 出 DSA 后 ---")
        risks = prop.propagate_risk(source, severity=0.9)
        for r in risks[:10]:
            print(f"  {r.product[:40]:40s} risk={r.risk_score:.4f} shared={r.shared_cves}")

    # 多源预测
    print(f"\n--- 预测: PowerEdge + iDRAC 出 DSA 后，下一个是谁？ ---")
    preds = prop.predict_next_affected(["PowerEdge", "iDRAC"])
    for r in preds[:10]:
        print(f"  {r.product[:40]:40s} risk={r.risk_score:.4f} "
              f"sources={r.source_products} shared={r.shared_cves}")

    # 保存完整结果
    result = {
        "summary": s,
        "top_sharing_pairs": [asdict(p) for p in prop.component_sharing_matrix(top_k=30)],
    }
    with open("graph_risk_propagation_result.json", "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print("\n结果已保存: graph_risk_propagation_result.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
