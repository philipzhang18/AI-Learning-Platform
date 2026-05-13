"""knowledge_graph 模块单元测试（使用内存 SQLite 样本）"""
import json
import os
import sqlite3
import tempfile
import time
import pytest
import sys

# 保证 import 顶层模块
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from knowledge_graph import (
    KnowledgeGraph,
    parse_cve_ids,
    normalize_product_name,
    NODE_CVE, NODE_DSA, NODE_PRODUCT, NODE_CWE,
    REL_MENTIONS, REL_AFFECTS, REL_CLASSIFIED_AS,
)


# ────────────────────────────────────────────────────────────────────────────
# 纯函数测试
# ────────────────────────────────────────────────────────────────────────────

class TestParseCveIds:
    def test_comma_separated(self):
        assert parse_cve_ids("CVE-2024-1234,CVE-2024-5678") == [
            "CVE-2024-1234", "CVE-2024-5678"]

    def test_whitespace_and_duplicate(self):
        # 常见脏数据："CVE-2024-7562  CVE-2024-7562"
        assert parse_cve_ids("CVE-2024-7562  CVE-2024-7562") == ["CVE-2024-7562"]

    def test_mixed_case(self):
        assert parse_cve_ids("cve-2024-1234,CVE-2024-5678") == [
            "CVE-2024-1234", "CVE-2024-5678"]

    def test_empty(self):
        assert parse_cve_ids("") == []
        assert parse_cve_ids(None) == []

    def test_garbage(self):
        assert parse_cve_ids("no cve here") == []


class TestNormalizeProductName:
    def test_basic(self):
        assert normalize_product_name("  Dell  PowerStore  ") == "Dell PowerStore"

    def test_trailing_punct(self):
        assert normalize_product_name("Dell VxRail,") == "Dell VxRail"

    def test_empty(self):
        assert normalize_product_name("") == ""
        assert normalize_product_name(None) == ""


# ────────────────────────────────────────────────────────────────────────────
# 构图测试：用临时 SQLite 数据库
# ────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_db(tmp_path):
    """构造最小可用的 SQLite：2 条 DSA + 3 条 CVE。"""
    db = tmp_path / "test.db"
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE cves (
            cve_id TEXT PRIMARY KEY,
            data TEXT,
            last_modified TEXT,
            published_date TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE dell_advisories (
            dsa_id TEXT PRIMARY KEY,
            title TEXT,
            cve_ids TEXT,
            data TEXT,
            published_date TEXT,
            collected_date TEXT,
            link TEXT
        )
    """)

    # ── CVE 样本 ───────────────────────────────────────────────
    cves = [
        ("CVE-2024-0001", {
            "cve_id": "CVE-2024-0001",
            "description": "Critical RCE in PowerStore",
            "cvss_score": 9.8,
            "cvss_severity": "CRITICAL",
            "weaknesses": ["CWE-78"],
        }),
        ("CVE-2024-0002", {
            "cve_id": "CVE-2024-0002",
            "description": "Medium XSS",
            "cvss_score": 5.4,
            "cvss_severity": "MEDIUM",
            "weaknesses": ["CWE-79"],
        }),
        ("CVE-2024-0003", {
            "cve_id": "CVE-2024-0003",
            "description": "Low info",
            "cvss_score": 3.1,
            "cvss_severity": "LOW",
            "weaknesses": [],
        }),
    ]
    for cid, d in cves:
        cur.execute("INSERT INTO cves(cve_id, data) VALUES (?, ?)",
                    (cid, json.dumps(d)))

    # ── DSA 样本 ──────────────────────────────────────────────
    dsa_a = {
        "dell_security_advisory": "DSA-2024-001",
        "title": "Security Update for Dell PowerStore",
        "cve_ids": ["CVE-2024-0001", "CVE-2024-0002"],
        "severity": "Critical",
        "impact": "Critical",
        "affected_products": [
            {"name": "Dell PowerStore", "model": "Dell PowerStore"}
        ],
    }
    dsa_b = {
        "dell_security_advisory": "DSA-2024-002",
        "title": "Security Update for Dell VxRail",
        "cve_ids": ["CVE-2024-0002", "CVE-2024-0003"],
        "severity": "High",
        "impact": "High",
        "affected_products": [
            {"name": "Dell VxRail", "model": "Dell VxRail"}
        ],
    }
    cur.execute(
        "INSERT INTO dell_advisories(dsa_id, title, cve_ids, data) VALUES (?, ?, ?, ?)",
        ("DSA-2024-001", dsa_a["title"], "CVE-2024-0001,CVE-2024-0002",
         json.dumps(dsa_a)),
    )
    cur.execute(
        "INSERT INTO dell_advisories(dsa_id, title, cve_ids, data) VALUES (?, ?, ?, ?)",
        ("DSA-2024-002", dsa_b["title"], "CVE-2024-0002,CVE-2024-0003",
         json.dumps(dsa_b)),
    )
    conn.commit()
    conn.close()
    return str(db)


class TestBuildGraph:
    def test_build_basic(self, sample_db):
        kg = KnowledgeGraph.from_sqlite(sample_db).build()
        stats = kg.stats()
        # 3 CVE + 2 DSA + 2 Product + 2 CWE
        assert stats["node:cve"] == 3
        assert stats["node:dsa"] == 2
        assert stats["node:product"] == 2
        assert stats["node:cwe"] == 2
        # mentions: 2+2=4; affects: 2; classified_as: 2
        assert stats["edge:mentions"] == 4
        assert stats["edge:affects"] == 2
        assert stats["edge:classified_as"] == 2

    def test_products_of_cve(self, sample_db):
        kg = KnowledgeGraph.from_sqlite(sample_db).build()
        prods = kg.products_of_cve("CVE-2024-0002")
        # CVE-2024-0002 被两个 DSA 引用，故影响 PowerStore 与 VxRail
        assert set(prods) == {"Dell PowerStore", "Dell VxRail"}

    def test_cves_of_product(self, sample_db):
        kg = KnowledgeGraph.from_sqlite(sample_db).build()
        cves = kg.cves_of_product("Dell PowerStore")
        assert set(cves) == {"CVE-2024-0001", "CVE-2024-0002"}

    def test_dsas_of_cve(self, sample_db):
        kg = KnowledgeGraph.from_sqlite(sample_db).build()
        dsas = set(kg.dsas_of_cve("CVE-2024-0002"))
        assert dsas == {"DSA-2024-001", "DSA-2024-002"}

    def test_severity_whitelist(self, sample_db):
        kg = KnowledgeGraph.from_sqlite(sample_db).build(
            severity_whitelist={"CRITICAL"})
        # CRITICAL 只有 CVE-2024-0001，其余 CVE 节点只作为 DSA 占位存在，
        # 但不会建 classified_as 边
        stats = kg.stats()
        assert stats["edge:classified_as"] == 1  # 仅 CVE-2024-0001 -> CWE-78

    def test_neighbors_of(self, sample_db):
        kg = KnowledgeGraph.from_sqlite(sample_db).build()
        # 从 DSA-2024-001 出边 mentions 指向 2 个 CVE
        cves = kg.neighbors_of("DSA-2024-001", relation=REL_MENTIONS,
                               direction="out")
        assert set(cves) == {"CVE-2024-0001", "CVE-2024-0002"}
        # affects 指向 1 个产品
        prods = kg.neighbors_of("DSA-2024-001", relation=REL_AFFECTS,
                                direction="out")
        assert len(prods) == 1

    def test_top_products(self, sample_db):
        kg = KnowledgeGraph.from_sqlite(sample_db).build()
        top = dict(kg.top_products(k=5))
        # PowerStore: 2 CVE；VxRail: 2 CVE
        assert top.get("Dell PowerStore") == 2
        assert top.get("Dell VxRail") == 2

    def test_top_cwes(self, sample_db):
        kg = KnowledgeGraph.from_sqlite(sample_db).build()
        top = dict(kg.top_cwes(k=5))
        assert top.get("CWE-78") == 1
        assert top.get("CWE-79") == 1

    def test_ego_subgraph(self, sample_db):
        kg = KnowledgeGraph.from_sqlite(sample_db).build()
        sub = kg.ego_subgraph("CVE-2024-0001", radius=1)
        # 邻居：DSA-2024-001（入边 mentions）、CWE-78（出边 classified_as）
        assert sub.number_of_nodes() == 3
        assert "DSA-2024-001" in sub
        assert "CWE-78" in sub
        assert "CVE-2024-0001" in sub

    def test_ego_subgraph_unknown(self, sample_db):
        kg = KnowledgeGraph.from_sqlite(sample_db).build()
        sub = kg.ego_subgraph("CVE-9999-9999")
        assert sub.number_of_nodes() == 0

    def test_resolve_product_shortname(self, sample_db):
        """允许传 'Dell PowerStore' 自动补全 product:: 前缀。"""
        kg = KnowledgeGraph.from_sqlite(sample_db).build()
        sub = kg.ego_subgraph("Dell PowerStore", radius=1)
        assert sub.number_of_nodes() >= 2  # 产品节点 + 至少一个 DSA

    def test_fuzzy_resolve_product_substring(self, sample_db):
        """输入简称 'PowerStore' 应模糊解析到 'Dell PowerStore'。"""
        kg = KnowledgeGraph.from_sqlite(sample_db).build()
        resolved = kg._resolve_node("PowerStore")
        assert resolved == "product::Dell PowerStore"
        sub = kg.ego_subgraph("PowerStore", radius=1)
        assert sub.number_of_nodes() >= 2

    def test_fuzzy_candidates(self, sample_db):
        kg = KnowledgeGraph.from_sqlite(sample_db).build()
        cands = kg.fuzzy_candidates("power", limit=5)
        labels = {label for _, label, _ in cands}
        assert "Dell PowerStore" in labels
        # 大小写不敏感
        cands2 = kg.fuzzy_candidates("POWER", limit=5)
        assert {l for _, l, _ in cands2} == labels

    def test_fuzzy_candidates_empty(self, sample_db):
        kg = KnowledgeGraph.from_sqlite(sample_db).build()
        assert kg.fuzzy_candidates("") == []
        assert kg.fuzzy_candidates("nonexistent") == []


class TestExport:
    def test_export_graphml(self, sample_db, tmp_path):
        kg = KnowledgeGraph.from_sqlite(sample_db).build()
        out = tmp_path / "g.graphml"
        kg.export_graphml(out)
        assert out.exists() and out.stat().st_size > 0

    def test_export_json(self, sample_db, tmp_path):
        kg = KnowledgeGraph.from_sqlite(sample_db).build()
        out = tmp_path / "g.json"
        kg.export_json(out)
        data = json.loads(out.read_text(encoding="utf-8"))
        assert "nodes" in data
        assert "links" in data  # edges="links" 参数
        assert len(data["nodes"]) == 9  # 3 CVE + 2 DSA + 2 Product + 2 CWE


class TestDrawSubgraph:
    def test_draw_smoke(self, sample_db):
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from knowledge_graph import draw_subgraph

        kg = KnowledgeGraph.from_sqlite(sample_db).build()
        sub = kg.ego_subgraph("CVE-2024-0001", radius=1)
        fig, ax = plt.subplots()
        draw_subgraph(sub, ax)
        # 不验证像素，只确保不抛异常
        plt.close(fig)

    def test_draw_empty(self):
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import networkx as nx
        from knowledge_graph import draw_subgraph

        fig, ax = plt.subplots()
        draw_subgraph(nx.DiGraph(), ax)
        plt.close(fig)


# ────────────────────────────────────────────────────────────────────────────
# 优化功能测试：缓存 + 快速查询
# ────────────────────────────────────────────────────────────────────────────

class TestCachePersistence:
    def test_save_and_load_cache(self, sample_db, tmp_path):
        """测试缓存保存和加载"""
        cache_path = tmp_path / "kg_cache.pkl"

        # 构建并保存缓存
        kg1 = KnowledgeGraph.from_sqlite(sample_db).build()
        stats1 = kg1.stats()
        kg1.save_cache(cache_path)

        assert cache_path.exists()
        assert cache_path.stat().st_size > 0

        # 从缓存加载
        kg2 = KnowledgeGraph.load_cache(cache_path)
        stats2 = kg2.stats()

        # 验证统计信息一致
        assert stats1["nodes_total"] == stats2["nodes_total"]
        assert stats1["edges_total"] == stats2["edges_total"]
        assert stats1["node:cve"] == stats2["node:cve"]
        assert stats1["node:dsa"] == stats2["node:dsa"]

    def test_cache_preserves_reverse_index(self, sample_db, tmp_path):
        """测试缓存保留反向索引"""
        cache_path = tmp_path / "kg_cache.pkl"

        kg1 = KnowledgeGraph.from_sqlite(sample_db).build()
        products1 = kg1.products_of_cve_fast("CVE-2024-0002")

        kg1.save_cache(cache_path)
        kg2 = KnowledgeGraph.load_cache(cache_path)
        products2 = kg2.products_of_cve_fast("CVE-2024-0002")

        assert set(products1) == set(products2)

    def test_save_cache_without_build_raises_error(self, tmp_path):
        """测试未构建图时保存缓存会抛出异常"""
        kg = KnowledgeGraph()
        cache_path = tmp_path / "kg_cache.pkl"

        with pytest.raises(RuntimeError, match="图尚未构建"):
            kg.save_cache(cache_path)

    def test_load_nonexistent_cache_raises_error(self, tmp_path):
        """测试加载不存在的缓存会抛出异常"""
        cache_path = tmp_path / "nonexistent.pkl"

        with pytest.raises(FileNotFoundError):
            KnowledgeGraph.load_cache(cache_path)


class TestFastQueries:
    def test_products_of_cve_fast(self, sample_db):
        """测试快速查询 CVE 影响的产品"""
        kg = KnowledgeGraph.from_sqlite(sample_db).build()

        # CVE-2024-0002 被两个 DSA 引用，影响 PowerStore 和 VxRail
        products = kg.products_of_cve_fast("CVE-2024-0002")
        assert set(products) == {"Dell PowerStore", "Dell VxRail"}

    def test_cves_of_product_fast(self, sample_db):
        """测试快速查询产品受影响的 CVE"""
        kg = KnowledgeGraph.from_sqlite(sample_db).build()

        cves = kg.cves_of_product_fast("Dell PowerStore")
        assert set(cves) == {"CVE-2024-0001", "CVE-2024-0002"}

    def test_dsas_of_cve_fast(self, sample_db):
        """测试快速查询 CVE 关联的 DSA"""
        kg = KnowledgeGraph.from_sqlite(sample_db).build()

        dsas = kg.dsas_of_cve_fast("CVE-2024-0002")
        assert set(dsas) == {"DSA-2024-001", "DSA-2024-002"}

    def test_fast_query_consistency(self, sample_db):
        """测试快速查询与原查询结果一致"""
        kg = KnowledgeGraph.from_sqlite(sample_db).build()

        cve_id = "CVE-2024-0002"

        # 对比原方法和快速方法
        products_slow = kg.products_of_cve(cve_id)
        products_fast = kg.products_of_cve_fast(cve_id)
        assert set(products_slow) == set(products_fast)

        dsas_slow = kg.dsas_of_cve(cve_id)
        dsas_fast = kg.dsas_of_cve_fast(cve_id)
        assert set(dsas_slow) == set(dsas_fast)

    def test_fast_query_empty_result(self, sample_db):
        """测试快速查询不存在的节点返回空列表"""
        kg = KnowledgeGraph.from_sqlite(sample_db).build()

        assert kg.products_of_cve_fast("CVE-9999-9999") == []
        assert kg.cves_of_product_fast("Nonexistent Product") == []
        assert kg.dsas_of_cve_fast("CVE-9999-9999") == []


class TestPerformance:
    def test_cache_load_speed(self, sample_db, tmp_path):
        """测试缓存加载速度（应该比构图快）"""
        cache_path = tmp_path / "kg_cache.pkl"

        # 首次构图
        start = time.time()
        kg1 = KnowledgeGraph.from_sqlite(sample_db).build()
        build_time = time.time() - start
        kg1.save_cache(cache_path)

        # 从缓存加载
        start = time.time()
        kg2 = KnowledgeGraph.load_cache(cache_path)
        load_time = time.time() - start

        # 缓存加载应该更快（至少快 2 倍）
        assert load_time < build_time / 2

    def test_fast_query_speed(self, sample_db):
        """测试快速查询速度（应该比遍历图快）"""
        kg = KnowledgeGraph.from_sqlite(sample_db).build()
        cve_id = "CVE-2024-0002"

        # 预热
        kg.products_of_cve(cve_id)
        kg.products_of_cve_fast(cve_id)

        # 测试原方法
        start = time.time()
        for _ in range(100):
            kg.products_of_cve(cve_id)
        slow_time = time.time() - start

        # 测试快速方法
        start = time.time()
        for _ in range(100):
            kg.products_of_cve_fast(cve_id)
        fast_time = time.time() - start

        # 快速方法应该更快（至少快 5 倍）
        assert fast_time < slow_time / 5
