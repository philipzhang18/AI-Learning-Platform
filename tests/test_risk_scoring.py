"""risk 模块单元测试：评分引擎 + 规则引擎"""
import json
import os
import sqlite3
import sys
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from knowledge_graph import KnowledgeGraph
from risk.base import (
    RiskLevel, EntityType, Priority, RiskScore, RiskContext,
    Recommendation, RuleMatch, normalize_score, clip,
    DEFAULT_SCORING_WEIGHTS,
)
from risk.scoring import RiskScorer, _days_since, _parse_iso_date
from risk.rules import Rule, RuleEngine, OPERATORS


# ────────────────────────────────────────────────────────────────────────────
# Fixtures
# ────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_db(tmp_path):
    """构造最小可用的 SQLite：2 条 DSA + 3 条 CVE"""
    db = tmp_path / "test.db"
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE cves (
            cve_id TEXT PRIMARY KEY, data TEXT,
            last_modified TEXT, published_date TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE dell_advisories (
            dsa_id TEXT PRIMARY KEY, title TEXT, cve_ids TEXT,
            data TEXT, published_date TEXT, collected_date TEXT, link TEXT
        )
    """)

    cves = [
        ("CVE-2024-0001", {
            "cve_id": "CVE-2024-0001",
            "description": "Critical RCE in PowerStore",
            "cvss_score": 9.8, "cvss_severity": "CRITICAL",
            "weaknesses": ["CWE-78"],
            "published_date": "2026-05-01",
        }),
        ("CVE-2024-0002", {
            "cve_id": "CVE-2024-0002",
            "description": "Medium XSS",
            "cvss_score": 5.4, "cvss_severity": "MEDIUM",
            "weaknesses": ["CWE-79"],
            "published_date": "2026-04-15",
        }),
        ("CVE-2024-0003", {
            "cve_id": "CVE-2024-0003",
            "description": "High privilege escalation",
            "cvss_score": 8.1, "cvss_severity": "HIGH",
            "weaknesses": ["CWE-269"],
            "published_date": "2026-03-01",
        }),
    ]
    for cid, d in cves:
        cur.execute("INSERT INTO cves(cve_id, data, published_date) VALUES (?, ?, ?)",
                    (cid, json.dumps(d), d.get("published_date", "")))

    dsa_a = {
        "severity": "Critical",
        "affected_products": [{"name": "Dell PowerStore"}],
        "published_date": "2026-05-01",
    }
    dsa_b = {
        "severity": "High",
        "affected_products": [{"name": "Dell VxRail"}],
        "published_date": "2026-04-15",
    }
    cur.execute(
        "INSERT INTO dell_advisories(dsa_id, title, cve_ids, data) VALUES (?, ?, ?, ?)",
        ("DSA-2024-001", "Security Update for Dell PowerStore",
         "CVE-2024-0001,CVE-2024-0002", json.dumps(dsa_a)),
    )
    cur.execute(
        "INSERT INTO dell_advisories(dsa_id, title, cve_ids, data) VALUES (?, ?, ?, ?)",
        ("DSA-2024-002", "Security Update for Dell VxRail",
         "CVE-2024-0002,CVE-2024-0003", json.dumps(dsa_b)),
    )
    conn.commit()
    conn.close()
    return str(db)


@pytest.fixture
def kg(sample_db):
    return KnowledgeGraph.from_sqlite(sample_db).build()


@pytest.fixture
def scorer(kg):
    from datetime import datetime
    return RiskScorer(kg, now=datetime(2026, 5, 13))


# ────────────────────────────────────────────────────────────────────────────
# base.py 测试
# ────────────────────────────────────────────────────────────────────────────

class TestBase:
    def test_risk_level_from_score(self):
        assert RiskLevel.from_score(95) == RiskLevel.CRITICAL
        assert RiskLevel.from_score(80) == RiskLevel.HIGH
        assert RiskLevel.from_score(60) == RiskLevel.MEDIUM
        assert RiskLevel.from_score(30) == RiskLevel.LOW
        assert RiskLevel.from_score(10) == RiskLevel.INFO

    def test_normalize_score(self):
        assert normalize_score(5.0, 0.0, 10.0) == 50.0
        assert normalize_score(0.0, 0.0, 10.0) == 0.0
        assert normalize_score(10.0, 0.0, 10.0) == 100.0
        assert normalize_score(15.0, 0.0, 10.0) == 100.0  # 超出范围裁剪

    def test_clip(self):
        assert clip(0.5) == 0.5
        assert clip(-1.0) == 0.0
        assert clip(2.0) == 1.0

    def test_risk_score_to_dict(self):
        rs = RiskScore(
            entity_id="test", entity_type=EntityType.PRODUCT,
            score=85.0, level=RiskLevel.HIGH,
        )
        d = rs.to_dict()
        assert d["entity_id"] == "test"
        assert d["level"] == "HIGH"
        assert d["entity_type"] == "product"


# ────────────────────────────────────────────────────────────────────────────
# scoring.py 测试
# ────────────────────────────────────────────────────────────────────────────

class TestScoringHelpers:
    def test_parse_iso_date(self):
        dt = _parse_iso_date("2026-05-01")
        assert dt is not None
        assert dt.year == 2026 and dt.month == 5

    def test_parse_iso_date_with_time(self):
        dt = _parse_iso_date("2026-05-01T12:30:00")
        assert dt is not None

    def test_parse_iso_date_empty(self):
        assert _parse_iso_date("") is None
        assert _parse_iso_date(None) is None

    def test_days_since(self):
        from datetime import datetime
        days = _days_since("2026-05-01", now=datetime(2026, 5, 13))
        assert days == 12


class TestRiskScorer:
    def test_score_product_basic(self, scorer):
        result = scorer.score_product("Dell PowerStore")
        assert isinstance(result, RiskScore)
        assert result.entity_id == "Dell PowerStore"
        assert result.entity_type == EntityType.PRODUCT
        assert 0 <= result.score <= 100
        assert result.level in RiskLevel

    def test_score_product_has_factors(self, scorer):
        result = scorer.score_product("Dell PowerStore")
        assert "cvss_avg" in result.factors
        assert "pagerank" in result.factors
        assert "recency" in result.factors
        assert "severity_density" in result.factors
        assert "cwe_diversity" in result.factors
        assert "exposure" in result.factors

    def test_score_product_nonexistent(self, scorer):
        result = scorer.score_product("Nonexistent Product")
        assert result.score == 0.0
        assert result.level == RiskLevel.INFO

    def test_score_cve(self, scorer):
        result = scorer.score_cve("CVE-2024-0001")
        assert result.score > 0
        assert result.entity_type == EntityType.CVE
        # CVSS 9.8 的 CVE 应该得分较高
        assert result.score >= 50

    def test_score_cve_nonexistent(self, scorer):
        result = scorer.score_cve("CVE-9999-9999")
        assert result.score == 0.0

    def test_score_all_products(self, scorer):
        results = scorer.score_all_products()
        assert len(results) >= 2  # PowerStore + VxRail
        # 按分数降序
        for i in range(len(results) - 1):
            assert results[i].score >= results[i + 1].score

    def test_score_all_products_with_filter(self, scorer):
        results = scorer.score_all_products(min_score=50.0)
        for r in results:
            assert r.score >= 50.0

    def test_explain(self, scorer):
        explanation = scorer.explain("Dell PowerStore")
        assert "score" in explanation
        assert "factors" in explanation
        assert "contributions" in explanation
        assert "weights" in explanation
        # 贡献度之和应约等于总分
        total_contrib = sum(explanation["contributions"].values())
        assert abs(total_contrib - explanation["score"]) < 1.0

    def test_custom_weights(self, kg):
        from datetime import datetime
        custom_weights = {
            "cvss_avg": 0.50, "pagerank": 0.10, "recency": 0.10,
            "severity_density": 0.10, "cwe_diversity": 0.10, "exposure": 0.10,
        }
        scorer = RiskScorer(kg, weights=custom_weights, now=datetime(2026, 5, 13))
        result = scorer.score_product("Dell PowerStore")
        assert result.score > 0

    def test_invalid_weights_raises(self, kg):
        with pytest.raises(ValueError, match="权重总和"):
            RiskScorer(kg, weights={"cvss_avg": 0.5})


# ────────────────────────────────────────────────────────────────────────────
# rules.py 测试
# ────────────────────────────────────────────────────────────────────────────

class TestOperators:
    def test_equals(self):
        assert OPERATORS["equals"]("CRITICAL", "critical")
        assert not OPERATORS["equals"]("HIGH", "CRITICAL")

    def test_in(self):
        assert OPERATORS["in"]("CWE-78", ["CWE-78", "CWE-94"])
        assert OPERATORS["in"](["CWE-78", "CWE-79"], ["CWE-78", "CWE-94"])
        assert not OPERATORS["in"]("CWE-200", ["CWE-78", "CWE-94"])

    def test_greater_than(self):
        assert OPERATORS["greater_than"](80, 75)
        assert not OPERATORS["greater_than"](50, 75)

    def test_contains(self):
        assert OPERATORS["contains"]("Dell PowerStore", "Power")
        assert OPERATORS["contains"](["Dell PowerStore", "VxRail"], "Power")

    def test_regex(self):
        assert OPERATORS["regex"]("Dell PowerStore 3000", r"PowerStore \d+")
        assert not OPERATORS["regex"]("Dell VxRail", r"PowerStore \d+")


class TestRule:
    def test_rule_creation(self):
        raw = {
            "rule_id": "TEST-001",
            "name": "Test Rule",
            "severity": "HIGH",
            "conditions": [
                {"type": "cve_severity", "operator": "equals", "value": "CRITICAL"}
            ],
            "recommendations": [
                {"title": "Fix it", "priority": "P0", "timeline": "立即", "action_type": "patch"}
            ],
        }
        rule = Rule(raw)
        assert rule.rule_id == "TEST-001"
        assert rule.severity == RiskLevel.HIGH

    def test_rule_matches(self):
        raw = {
            "rule_id": "TEST-002",
            "name": "CWE Match",
            "severity": "CRITICAL",
            "conditions": [
                {"type": "cwe_match", "operator": "in", "value": ["CWE-78", "CWE-94"]}
            ],
            "recommendations": [],
        }
        rule = Rule(raw)
        ctx = RiskContext(
            entity_id="Dell PowerStore",
            entity_type=EntityType.PRODUCT,
            related_cwes=["CWE-78", "CWE-200"],
        )
        assert rule.matches(ctx)

    def test_rule_not_matches(self):
        raw = {
            "rule_id": "TEST-003",
            "name": "No Match",
            "severity": "HIGH",
            "conditions": [
                {"type": "cwe_match", "operator": "in", "value": ["CWE-78"]}
            ],
            "recommendations": [],
        }
        rule = Rule(raw)
        ctx = RiskContext(
            entity_id="Dell VxRail",
            entity_type=EntityType.PRODUCT,
            related_cwes=["CWE-200"],
        )
        assert not rule.matches(ctx)

    def test_rule_build_recommendations(self):
        raw = {
            "rule_id": "TEST-004",
            "name": "With Recs",
            "severity": "HIGH",
            "conditions": [
                {"type": "cve_count", "operator": "greater_than", "value": 0}
            ],
            "recommendations": [
                {"title": "Apply patch", "priority": "P0",
                 "timeline": "24h", "action_type": "patch"},
                {"title": "Monitor", "priority": "P2",
                 "timeline": "7d", "action_type": "monitor"},
            ],
        }
        rule = Rule(raw)
        ctx = RiskContext(
            entity_id="Test",
            entity_type=EntityType.PRODUCT,
            related_cves=["CVE-2024-0001"],
        )
        assert rule.matches(ctx)
        recs = rule.build_recommendations(ctx)
        assert len(recs) == 2
        assert recs[0].priority == Priority.P0
        assert recs[1].action_type == "monitor"


class TestRuleEngine:
    def test_load_from_directory(self):
        rules_dir = os.path.join(ROOT, "risk", "rules")
        engine = RuleEngine.from_directory(rules_dir)
        assert len(engine) >= 8  # 至少 8 条预置规则

    def test_evaluate_matches(self):
        raw = {
            "rule_id": "TEST-E01",
            "name": "Critical RCE",
            "severity": "CRITICAL",
            "conditions": [
                {"type": "cve_severity", "operator": "in", "value": ["CRITICAL"]},
                {"type": "cwe_match", "operator": "in", "value": ["CWE-78"]},
            ],
            "recommendations": [
                {"title": "Patch now", "priority": "P0",
                 "timeline": "立即", "action_type": "patch"},
            ],
        }
        engine = RuleEngine([Rule(raw)])
        ctx = RiskContext(
            entity_id="Dell PowerStore",
            entity_type=EntityType.PRODUCT,
            related_cves=["CVE-2024-0001"],
            related_cwes=["CWE-78"],
            metadata={"cve_severities": ["CRITICAL"]},
        )
        matches = engine.evaluate(ctx)
        assert len(matches) == 1
        assert matches[0].rule_id == "TEST-E01"
        assert len(matches[0].recommendations) == 1

    def test_evaluate_no_match(self):
        raw = {
            "rule_id": "TEST-E02",
            "name": "No Match",
            "severity": "HIGH",
            "conditions": [
                {"type": "cve_severity", "operator": "equals", "value": "CRITICAL"},
            ],
            "recommendations": [],
        }
        engine = RuleEngine([Rule(raw)])
        ctx = RiskContext(
            entity_id="Test",
            entity_type=EntityType.PRODUCT,
            metadata={"cve_severities": ["LOW"]},
        )
        matches = engine.evaluate(ctx)
        assert len(matches) == 0

    def test_any_match_mode(self):
        raw = {
            "rule_id": "TEST-E03",
            "name": "Any Mode",
            "severity": "MEDIUM",
            "match_mode": "any",
            "conditions": [
                {"type": "cve_severity", "operator": "equals", "value": "CRITICAL"},
                {"type": "cwe_match", "operator": "in", "value": ["CWE-200"]},
            ],
            "recommendations": [],
        }
        engine = RuleEngine([Rule(raw)])
        # 只满足第二个条件
        ctx = RiskContext(
            entity_id="Test",
            entity_type=EntityType.PRODUCT,
            related_cwes=["CWE-200"],
            metadata={"cve_severities": ["LOW"]},
        )
        matches = engine.evaluate(ctx)
        assert len(matches) == 1  # any 模式，一个满足即可
