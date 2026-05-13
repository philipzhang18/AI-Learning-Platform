"""
知识图谱模块（轻量版）

基于 NetworkX + SQLite 现有数据，在内存中构建有向图，
支持 CVE × DSA × Product × CWE 四类节点的关联查询、统计与可视化。

设计原则：
- 不引入 Neo4j 等重型图数据库，单进程内存图即可服务 GUI 层
- 数据源是只读的：不修改 SQLite，仅读取 cves / dell_advisories 两张主表
- 构图可按 limit / since 过滤，避免一次加载 12 万 CVE 拖慢启动

典型用法：
    from knowledge_graph import KnowledgeGraph

    kg = KnowledgeGraph.from_sqlite("cve_data/cve_database.db")
    kg.build(limit_cve=5000)                      # 内存图
    print(kg.stats())                             # 节点/边计数
    kg.neighbors_of("CVE-2018-3640", relation="mentioned_in")
    kg.top_products(k=10)
    kg.export_graphml("cve_graph.graphml")
"""
from __future__ import annotations

import json
import pickle
import re
import sqlite3
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import networkx as nx


# ────────────────────────────────────────────────────────────────────────────
# 节点 / 边 常量
# ────────────────────────────────────────────────────────────────────────────

NODE_CVE = "cve"
NODE_DSA = "dsa"
NODE_PRODUCT = "product"
NODE_CWE = "cwe"

REL_MENTIONS = "mentions"            # DSA -> CVE
REL_AFFECTS = "affects"              # DSA -> Product
REL_CLASSIFIED_AS = "classified_as"  # CVE -> CWE

NODE_COLORS = {
    NODE_CVE: "#3498db",      # 蓝
    NODE_DSA: "#e67e22",      # 橙
    NODE_PRODUCT: "#27ae60",  # 绿
    NODE_CWE: "#8e44ad",      # 紫
}


# ────────────────────────────────────────────────────────────────────────────
# 辅助：CVE ID 清洗 / 产品名归一
# ────────────────────────────────────────────────────────────────────────────

# 兼容 "CVE-2024-1234,CVE-2024-1235"、"CVE-2024-1234 CVE-2024-1234"（重复）
_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def parse_cve_ids(raw: Optional[str]) -> List[str]:
    """从 DSA.cve_ids 原文中提取去重后的 CVE ID 列表（大写规范化）。"""
    if not raw:
        return []
    found = _CVE_ID_RE.findall(raw)
    seen: Set[str] = set()
    result: List[str] = []
    for cid in found:
        cu = cid.upper()
        if cu not in seen:
            seen.add(cu)
            result.append(cu)
    return result


# 段落/脏数据的典型特征（出现其一即判为非产品名）
_PRODUCT_REJECT_PREFIX = ("*", "-", "#", ">", "•", "·")
_PRODUCT_REJECT_SUBSTR = (
    "Affected products:", "Remediation:", "Summary:", "Article Type:",
    "http://", "https://", "DSA-", "Hotfix", "Scoring Guide",
    "vulnerabilities", "security update", "mitigate", "operating system",
    "Find answers", "Security patch",
)


def normalize_product_name(name: str) -> str:
    """产品名归一：压缩空白、去首尾标点。"""
    if not name:
        return ""
    return re.sub(r"\s+", " ", name).strip(" ,.;:-—")


def _is_valid_product_name(s: str) -> bool:
    """粗过滤：排除段落/URL/占位等明显非产品名的字符串。"""
    if not s:
        return False
    # 长度：产品名很少超过 80 字符
    if len(s) > 80 or len(s) < 2:
        return False
    low = s.lower()
    if low in {"multiple", "none", "n/a", "-", "multiple third-party component"}:
        return False
    if s.startswith(_PRODUCT_REJECT_PREFIX):
        return False
    for pat in _PRODUCT_REJECT_SUBSTR:
        if pat.lower() in low:
            return False
    # 必须包含字母（纯数字 / 纯标点不是产品名）
    if not re.search(r"[A-Za-z]", s):
        return False
    return True


def _extract_products_from_dsa(dsa_data: Dict[str, Any], title: str) -> List[str]:
    """优先从 data.affected_products[*].name 取，回退到标题正则。"""
    products: List[str] = []
    ap = dsa_data.get("affected_products") if isinstance(dsa_data, dict) else None
    if isinstance(ap, list):
        for item in ap:
            if not isinstance(item, dict):
                continue
            n = normalize_product_name(item.get("name") or item.get("model") or "")
            if _is_valid_product_name(n):
                products.append(n)
    if products:
        return sorted(set(products))
    # 回退：从标题里粗抓 "Dell XXX"
    if title:
        m = re.search(r"(Dell\s+[A-Za-z0-9 /\-]+?)\s+(?:for|Multiple|Vulnerabilit)",
                      title, re.IGNORECASE)
        if m:
            candidate = normalize_product_name(m.group(1))
            if _is_valid_product_name(candidate):
                return [candidate]
    return []


# ────────────────────────────────────────────────────────────────────────────
# 构图
# ────────────────────────────────────────────────────────────────────────────

class KnowledgeGraph:
    """
    CVE × DSA × Product × CWE 内存知识图谱。

    节点属性：
        - type: cve | dsa | product | cwe
        - label: 展示用文本
        - severity: （仅 cve/dsa）CVSS 或 impact 等级
        - 其它原始属性按需挂载

    边属性：
        - relation: mentions | affects | classified_as
    """

    def __init__(self) -> None:
        self.G: nx.DiGraph = nx.DiGraph()
        self._built: bool = False

        # 反向索引：加速高频查询
        self._product_to_cves: Dict[str, Set[str]] = {}
        self._cve_to_products: Dict[str, Set[str]] = {}
        self._cve_to_dsas: Dict[str, Set[str]] = {}
        self._dsa_to_cves: Dict[str, Set[str]] = {}

        # 元数据
        self._build_time: Optional[str] = None
        self._cache_version: str = "1.0"

    # ── 构造器 ──────────────────────────────────────────────────────────

    @classmethod
    def from_sqlite(cls, db_path: str | Path) -> "KnowledgeGraph":
        kg = cls()
        kg._db_path = str(db_path)
        return kg

    @classmethod
    def from_connection(cls, conn: sqlite3.Connection) -> "KnowledgeGraph":
        kg = cls()
        kg._external_conn = conn
        return kg

    @classmethod
    def load_cache(cls, cache_path: str | Path) -> "KnowledgeGraph":
        """
        从缓存文件快速加载已构建的图。

        :param cache_path: 缓存文件路径（.pkl 格式）
        :return: 已构建的 KnowledgeGraph 实例
        """
        cache_path = Path(cache_path)
        if not cache_path.exists():
            raise FileNotFoundError(f"缓存文件不存在: {cache_path}")

        with open(cache_path, "rb") as f:
            data = pickle.load(f)

        # 验证缓存版本
        if data.get("cache_version") != "1.0":
            raise ValueError(f"缓存版本不兼容: {data.get('cache_version')}")

        kg = cls()
        kg.G = data["graph"]
        kg._product_to_cves = data["product_to_cves"]
        kg._cve_to_products = data["cve_to_products"]
        kg._cve_to_dsas = data["cve_to_dsas"]
        kg._dsa_to_cves = data["dsa_to_cves"]
        kg._build_time = data.get("build_time")
        kg._cache_version = data.get("cache_version", "1.0")
        kg._built = True
        return kg

    # ── 构图主流程 ───────────────────────────────────────────────────────

    def build(
        self,
        limit_cve: Optional[int] = None,
        limit_dsa: Optional[int] = None,
        severity_whitelist: Optional[Iterable[str]] = None,
    ) -> "KnowledgeGraph":
        """
        读取 SQLite 构图。

        :param limit_cve: 最多加载多少条 CVE 节点（None 全量）
        :param limit_dsa: 最多加载多少条 DSA 节点（None 全量）
        :param severity_whitelist: 仅加载 CVE 严重等级在白名单内的记录
                                   （e.g. {"CRITICAL", "HIGH"}），None 不过滤
        """
        conn = self._get_conn()
        own = not hasattr(self, "_external_conn")
        try:
            self._load_dsa(conn, limit=limit_dsa)
            self._load_cve(conn, limit=limit_cve, severity_whitelist=severity_whitelist)
            self._built = True
            self._build_time = datetime.now().isoformat()
        finally:
            if own and hasattr(self, "_owned_conn"):
                self._owned_conn.close()
                del self._owned_conn
        return self

    def _get_conn(self) -> sqlite3.Connection:
        if hasattr(self, "_external_conn"):
            return self._external_conn  # type: ignore[attr-defined]
        conn = sqlite3.connect(self._db_path)  # type: ignore[attr-defined]
        self._owned_conn = conn
        return conn

    def _load_dsa(self, conn: sqlite3.Connection, limit: Optional[int]) -> None:
        cur = conn.cursor()
        # 按发布日期倒序取，保证 limit 是"最新 N 条"而非随机前 N 条
        sql = (
            "SELECT dsa_id, title, cve_ids, data "
            "FROM dell_advisories "
            "ORDER BY COALESCE(published_date, collected_date, '') DESC"
        )
        if limit:
            sql += f" LIMIT {int(limit)}"
        for dsa_id, title, cve_ids_raw, data_raw in cur.execute(sql):
            if not dsa_id:
                continue
            dsa_id = dsa_id.strip().upper()
            data_obj: Dict[str, Any] = {}
            if data_raw:
                try:
                    data_obj = json.loads(data_raw)
                except (json.JSONDecodeError, TypeError):
                    data_obj = {}
            severity = data_obj.get("severity") or data_obj.get("impact") or ""
            self.G.add_node(
                dsa_id,
                type=NODE_DSA,
                label=dsa_id,
                title=title or "",
                severity=str(severity),
                published=data_obj.get("published_date", ""),
                link=data_obj.get("link", ""),
            )
            # DSA -> CVE
            cve_list = []
            for cve_id in parse_cve_ids(cve_ids_raw):
                if cve_id not in self.G:
                    # 先创建占位 CVE 节点；若后续 _load_cve 命中会被覆盖属性
                    self.G.add_node(cve_id, type=NODE_CVE, label=cve_id, severity="")
                self.G.add_edge(dsa_id, cve_id, relation=REL_MENTIONS)
                cve_list.append(cve_id)

                # 更新反向索引：CVE -> DSA
                if cve_id not in self._cve_to_dsas:
                    self._cve_to_dsas[cve_id] = set()
                self._cve_to_dsas[cve_id].add(dsa_id)

            # 更新反向索引：DSA -> CVE
            if cve_list:
                self._dsa_to_cves[dsa_id] = set(cve_list)

            # DSA -> Product
            for prod in _extract_products_from_dsa(data_obj, title or ""):
                node = f"product::{prod}"
                if node not in self.G:
                    self.G.add_node(node, type=NODE_PRODUCT, label=prod)
                self.G.add_edge(dsa_id, node, relation=REL_AFFECTS)

                # 更新反向索引：Product -> CVE (通过 DSA 中介)
                if prod not in self._product_to_cves:
                    self._product_to_cves[prod] = set()
                self._product_to_cves[prod].update(cve_list)

                # 更新反向索引：CVE -> Product
                for cve_id in cve_list:
                    if cve_id not in self._cve_to_products:
                        self._cve_to_products[cve_id] = set()
                    self._cve_to_products[cve_id].add(prod)

    def _load_cve(
        self,
        conn: sqlite3.Connection,
        limit: Optional[int],
        severity_whitelist: Optional[Iterable[str]],
    ) -> None:
        cur = conn.cursor()
        # 同样按发布日期倒序，limit 表示"最新 N 条 CVE"
        sql = (
            "SELECT cve_id, data FROM cves "
            "ORDER BY COALESCE(published_date, last_modified, '') DESC"
        )
        if limit:
            sql += f" LIMIT {int(limit)}"
        wl: Optional[Set[str]] = (
            {s.upper() for s in severity_whitelist} if severity_whitelist else None
        )
        for cve_id, data_raw in cur.execute(sql):
            if not cve_id or not data_raw:
                continue
            cve_id = cve_id.strip().upper()
            try:
                data_obj = json.loads(data_raw)
            except (json.JSONDecodeError, TypeError):
                continue
            severity = (data_obj.get("cvss_severity") or "").upper()
            if wl and severity not in wl:
                # 不丢弃已经被 DSA 引用的占位节点，但不添加 CWE 边
                continue
            # 更新/创建 CVE 节点属性
            attrs = {
                "type": NODE_CVE,
                "label": cve_id,
                "severity": severity,
                "score": data_obj.get("cvss_score"),
                "published": data_obj.get("published_date", ""),
                "description": (data_obj.get("description") or "")[:240],
            }
            if cve_id in self.G:
                self.G.nodes[cve_id].update(attrs)
            else:
                self.G.add_node(cve_id, **attrs)
            # CVE -> CWE
            for cwe in data_obj.get("weaknesses") or []:
                if not isinstance(cwe, str) or not cwe:
                    continue
                cwe = cwe.strip().upper()
                if cwe not in self.G:
                    self.G.add_node(cwe, type=NODE_CWE, label=cwe)
                self.G.add_edge(cve_id, cwe, relation=REL_CLASSIFIED_AS)

    # ── 只读查询 ────────────────────────────────────────────────────────

    def stats(self) -> Dict[str, int]:
        """返回节点与边的分类计数。"""
        counts = {f"node:{t}": 0 for t in (NODE_CVE, NODE_DSA, NODE_PRODUCT, NODE_CWE)}
        for _, attr in self.G.nodes(data=True):
            key = f"node:{attr.get('type', 'unknown')}"
            counts[key] = counts.get(key, 0) + 1
        for rel in (REL_MENTIONS, REL_AFFECTS, REL_CLASSIFIED_AS):
            counts[f"edge:{rel}"] = 0
        for _, _, attr in self.G.edges(data=True):
            key = f"edge:{attr.get('relation', 'unknown')}"
            counts[key] = counts.get(key, 0) + 1
        counts["nodes_total"] = self.G.number_of_nodes()
        counts["edges_total"] = self.G.number_of_edges()
        counts["build_time"] = self._build_time or "N/A"
        return counts

    def neighbors_of(
        self,
        node: str,
        relation: Optional[str] = None,
        direction: str = "out",
    ) -> List[str]:
        """
        返回邻居节点列表。

        :param node: 源节点 id（已规范化，例如 "CVE-2024-1234" / "DSA-2024-056" / "product::PowerStore"）
        :param relation: 过滤边类型；None 不过滤
        :param direction: "out" | "in" | "both"
        """
        node = self._resolve_node(node)
        if node not in self.G:
            return []
        results: List[str] = []
        if direction in ("out", "both"):
            for _, v, attr in self.G.out_edges(node, data=True):
                if relation is None or attr.get("relation") == relation:
                    results.append(v)
        if direction in ("in", "both"):
            for u, _, attr in self.G.in_edges(node, data=True):
                if relation is None or attr.get("relation") == relation:
                    results.append(u)
        # 去重保序
        seen: Set[str] = set()
        out: List[str] = []
        for n in results:
            if n not in seen:
                seen.add(n)
                out.append(n)
        return out

    def products_of_cve(self, cve_id: str) -> List[str]:
        """某 CVE 影响到的 Dell 产品（经过 DSA 中介）。"""
        cve_id = cve_id.strip().upper()
        if cve_id not in self.G:
            return []
        prods: Set[str] = set()
        for dsa in self.G.predecessors(cve_id):
            if self.G.nodes[dsa].get("type") != NODE_DSA:
                continue
            for p in self.G.successors(dsa):
                if self.G.nodes[p].get("type") == NODE_PRODUCT:
                    prods.add(self.G.nodes[p].get("label", p))
        return sorted(prods)

    def cves_of_product(self, product_name: str) -> List[str]:
        """某产品受影响的 CVE 清单（经过 DSA 中介）。"""
        node = f"product::{normalize_product_name(product_name)}"
        if node not in self.G:
            return []
        cves: Set[str] = set()
        for dsa in self.G.predecessors(node):
            if self.G.nodes[dsa].get("type") != NODE_DSA:
                continue
            for c in self.G.successors(dsa):
                if self.G.nodes[c].get("type") == NODE_CVE:
                    cves.add(c)
        return sorted(cves)

    def dsas_of_cve(self, cve_id: str) -> List[str]:
        cve_id = cve_id.strip().upper()
        return [u for u in self.G.predecessors(cve_id)
                if self.G.nodes[u].get("type") == NODE_DSA]

    def top_products(self, k: int = 10) -> List[Tuple[str, int]]:
        """按关联 CVE 数量排序的产品 Top-K。"""
        counts: Counter = Counter()
        for node, attr in self.G.nodes(data=True):
            if attr.get("type") != NODE_PRODUCT:
                continue
            counts[attr.get("label", node)] = len(self.cves_of_product(attr.get("label", node)))
        return counts.most_common(k)

    def top_cwes(self, k: int = 10) -> List[Tuple[str, int]]:
        """按入度（被多少 CVE 归类）排序的 CWE Top-K。"""
        counts: Counter = Counter()
        for node, attr in self.G.nodes(data=True):
            if attr.get("type") != NODE_CWE:
                continue
            counts[attr.get("label", node)] = self.G.in_degree(node)
        return counts.most_common(k)

    # ── 子图抽取 ────────────────────────────────────────────────────────

    def ego_subgraph(self, node: str, radius: int = 1) -> nx.DiGraph:
        """
        以 node 为中心、最多 radius 跳的无向邻域子图（用于可视化）。
        """
        node = self._resolve_node(node)
        if node not in self.G:
            return nx.DiGraph()
        # 基于无向视图计算邻域，再取原图诱导子图，保留边方向
        undirected = self.G.to_undirected(as_view=True)
        nodes = set(nx.single_source_shortest_path_length(undirected, node, cutoff=radius).keys())
        return self.G.subgraph(nodes).copy()

    # ── 导出 ────────────────────────────────────────────────────────────

    def export_graphml(self, path: str | Path) -> None:
        """导出为 GraphML（可在 Gephi / yEd / Cytoscape 中打开）。"""
        # GraphML 不支持 None，做一次清洗
        H = self.G.copy()
        for _, attr in H.nodes(data=True):
            for k, v in list(attr.items()):
                if v is None:
                    attr[k] = ""
        nx.write_graphml(H, str(path))

    def export_json(self, path: str | Path) -> None:
        """导出为 node-link JSON，便于 Web 前端 / D3 使用。"""
        data = nx.node_link_data(self.G, edges="links")
        Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def save_cache(self, cache_path: str | Path) -> None:
        """
        将构建好的图序列化到磁盘（持久化缓存）。

        :param cache_path: 缓存文件路径（.pkl 格式）
        """
        if not self._built:
            raise RuntimeError("图尚未构建，无法保存缓存")

        cache_path = Path(cache_path)
        cache_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "cache_version": self._cache_version,
            "graph": self.G,
            "product_to_cves": dict(self._product_to_cves),
            "cve_to_products": dict(self._cve_to_products),
            "cve_to_dsas": dict(self._cve_to_dsas),
            "dsa_to_cves": dict(self._dsa_to_cves),
            "build_time": self._build_time,
        }

        with open(cache_path, "wb") as f:
            pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)

    # ── 快速查询（使用反向索引） ────────────────────────────────────────

    def products_of_cve_fast(self, cve_id: str) -> List[str]:
        """
        使用反向索引快速查询 CVE 影响的产品（O(1) 复杂度）。

        :param cve_id: CVE ID（例如 "CVE-2024-1234"）
        :return: 产品名列表（已排序）
        """
        cve_id = cve_id.strip().upper()
        return sorted(self._cve_to_products.get(cve_id, set()))

    def cves_of_product_fast(self, product_name: str) -> List[str]:
        """
        使用反向索引快速查询产品受影响的 CVE（O(1) 复杂度）。

        :param product_name: 产品名（例如 "Dell PowerStore"）
        :return: CVE ID 列表（已排序）
        """
        prod = normalize_product_name(product_name)
        return sorted(self._product_to_cves.get(prod, set()))

    def dsas_of_cve_fast(self, cve_id: str) -> List[str]:
        """
        使用反向索引快速查询 CVE 关联的 DSA（O(1) 复杂度）。

        :param cve_id: CVE ID（例如 "CVE-2024-1234"）
        :return: DSA ID 列表（已排序）
        """
        cve_id = cve_id.strip().upper()
        return sorted(self._cve_to_dsas.get(cve_id, set()))

    # ── 内部 ────────────────────────────────────────────────────────────

    def _resolve_node(self, node: str) -> str:
        """
        节点 ID 解析（支持模糊匹配产品简称）：
        1. 原样命中 → 直接返回
        2. 加 product:: 前缀命中 → 返回
        3. 转大写命中 CVE/DSA 节点 → 返回
        4. 产品名子串模糊匹配（大小写不敏感）：
           在产品节点里找 label 包含输入串的，选关联度（入度）最高的一条
        """
        if node in self.G:
            return node
        candidates = [f"product::{normalize_product_name(node)}", node.upper()]
        for c in candidates:
            if c in self.G:
                return c
        # 模糊：产品节点子串匹配
        key = (node or "").strip().lower()
        if key:
            matches: List[Tuple[str, int]] = []
            for n, attr in self.G.nodes(data=True):
                if attr.get("type") != NODE_PRODUCT:
                    continue
                label = str(attr.get("label", "")).lower()
                if key in label:
                    matches.append((n, self.G.in_degree(n)))
            if matches:
                # 选关联度最高（入度最大）的产品节点
                matches.sort(key=lambda kv: kv[1], reverse=True)
                return matches[0][0]
        return node

    def fuzzy_candidates(self, query: str, limit: int = 15) -> List[Tuple[str, str, int]]:
        """
        产品名模糊匹配候选（供 UI 下拉展示）。

        :return: [(node_id, label, in_degree), ...] 按关联度降序
        """
        key = (query or "").strip().lower()
        if not key:
            return []
        out: List[Tuple[str, str, int]] = []
        for n, attr in self.G.nodes(data=True):
            if attr.get("type") != NODE_PRODUCT:
                continue
            label = str(attr.get("label", ""))
            if key in label.lower():
                out.append((n, label, self.G.in_degree(n)))
        out.sort(key=lambda kv: kv[2], reverse=True)
        return out[:limit]


# ────────────────────────────────────────────────────────────────────────────
# 可视化（仅在调用者显式传入 matplotlib Axes 时工作，避免强依赖 GUI）
# ────────────────────────────────────────────────────────────────────────────

def draw_subgraph(subG: nx.DiGraph, ax, layout: str = "spring", seed: int = 42) -> None:
    """
    在给定 matplotlib Axes 上绘制子图。

    :param subG: 子图（通常来自 KnowledgeGraph.ego_subgraph）
    :param ax: matplotlib Axes 对象
    :param layout: spring | kamada_kawai | circular
    :param seed: 布局随机种子（保证多次绘制一致）
    """
    if subG.number_of_nodes() == 0:
        ax.text(0.5, 0.5, "(no data)", ha="center", va="center", transform=ax.transAxes)
        ax.set_axis_off()
        return

    if layout == "kamada_kawai" and subG.number_of_nodes() > 1:
        pos = nx.kamada_kawai_layout(subG)
    elif layout == "circular":
        pos = nx.circular_layout(subG)
    else:
        pos = nx.spring_layout(subG, seed=seed, k=0.9)

    # 按节点类型分组着色
    for ntype, color in NODE_COLORS.items():
        nodes = [n for n, a in subG.nodes(data=True) if a.get("type") == ntype]
        if not nodes:
            continue
        nx.draw_networkx_nodes(
            subG, pos, nodelist=nodes, node_color=color,
            node_size=600, alpha=0.85, ax=ax,
        )

    nx.draw_networkx_edges(
        subG, pos, ax=ax, edge_color="#888", arrows=True,
        arrowsize=12, width=1.0, alpha=0.7,
    )
    labels = {n: a.get("label", n) for n, a in subG.nodes(data=True)}
    nx.draw_networkx_labels(subG, pos, labels=labels, font_size=8, ax=ax)

    edge_labels = {(u, v): a.get("relation", "") for u, v, a in subG.edges(data=True)}
    if edge_labels:
        nx.draw_networkx_edge_labels(
            subG, pos, edge_labels=edge_labels, font_size=7,
            font_color="#555", ax=ax,
        )

    ax.set_axis_off()


__all__ = [
    "KnowledgeGraph",
    "draw_subgraph",
    "parse_cve_ids",
    "normalize_product_name",
    "NODE_CVE", "NODE_DSA", "NODE_PRODUCT", "NODE_CWE",
    "REL_MENTIONS", "REL_AFFECTS", "REL_CLASSIFIED_AS",
    "NODE_COLORS",
]
