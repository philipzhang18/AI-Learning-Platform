"""
规则引擎 (risk/rules.py)

声明式风险规则引擎：从 YAML 文件加载规则，对实体上下文进行匹配，
触发对应的预防性维护建议。

规则文件格式 (YAML)：

    rule_id: R001
    name: 未修复的关键远程代码执行漏洞
    severity: CRITICAL
    description: ...
    conditions:                    # 全部满足才触发
      - type: cve_severity         # 条件类型
        operator: equals           # 比较操作符
        value: CRITICAL            # 期望值
      - type: cwe_match
        operator: in
        value: [CWE-78, CWE-94]
    recommendations:
      - title: ...
        priority: P0
        timeline: 24 小时内
        action_type: patch

支持的条件类型：
- cve_severity      CVE 严重等级（依赖 context.metadata.cve_severities）
- cwe_match         CWE 类型匹配（依赖 context.related_cwes）
- cve_count         关联 CVE 总数
- product_name      产品名匹配
- score_above       风险评分高于阈值（需要 metadata.risk_score）
- age_days          最新 CVE 年龄（需要 metadata.latest_cve_days）

支持的操作符：equals, not_equals, in, not_in, greater_than, less_than,
            contains, regex
"""
from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import yaml

from risk.base import (
    Priority,
    Recommendation,
    RiskContext,
    RiskLevel,
    RuleMatch,
)


# ────────────────────────────────────────────────────────────────────────────
# 操作符实现
# ────────────────────────────────────────────────────────────────────────────

OperatorFunc = Callable[[Any, Any], bool]


def _op_equals(actual: Any, expected: Any) -> bool:
    if actual is None:
        return False
    return str(actual).upper() == str(expected).upper()


def _op_not_equals(actual: Any, expected: Any) -> bool:
    return not _op_equals(actual, expected)


def _op_in(actual: Any, expected: Any) -> bool:
    if actual is None or not isinstance(expected, (list, tuple, set)):
        return False
    if isinstance(actual, (list, tuple, set)):
        # 任一元素命中即可
        actual_set = {str(a).upper() for a in actual}
        expected_set = {str(e).upper() for e in expected}
        return bool(actual_set & expected_set)
    return str(actual).upper() in {str(e).upper() for e in expected}


def _op_not_in(actual: Any, expected: Any) -> bool:
    return not _op_in(actual, expected)


def _op_greater_than(actual: Any, expected: Any) -> bool:
    try:
        return float(actual) > float(expected)
    except (TypeError, ValueError):
        return False


def _op_less_than(actual: Any, expected: Any) -> bool:
    try:
        return float(actual) < float(expected)
    except (TypeError, ValueError):
        return False


def _op_contains(actual: Any, expected: Any) -> bool:
    if actual is None:
        return False
    if isinstance(actual, (list, tuple, set)):
        return any(str(expected).lower() in str(a).lower() for a in actual)
    return str(expected).lower() in str(actual).lower()


def _op_regex(actual: Any, expected: Any) -> bool:
    if actual is None:
        return False
    try:
        pattern = re.compile(str(expected), re.IGNORECASE)
    except re.error:
        return False
    if isinstance(actual, (list, tuple, set)):
        return any(pattern.search(str(a)) for a in actual)
    return bool(pattern.search(str(actual)))


OPERATORS: Dict[str, OperatorFunc] = {
    "equals": _op_equals,
    "not_equals": _op_not_equals,
    "in": _op_in,
    "not_in": _op_not_in,
    "greater_than": _op_greater_than,
    "less_than": _op_less_than,
    "contains": _op_contains,
    "regex": _op_regex,
}


# ────────────────────────────────────────────────────────────────────────────
# 字段提取器（从 RiskContext 提取条件比较值）
# ────────────────────────────────────────────────────────────────────────────

FieldExtractor = Callable[[RiskContext], Any]


def _extract_cve_severity(ctx: RiskContext) -> List[str]:
    """从 metadata.cve_severities 提取，回退到根据 metadata.cve_details"""
    severities = ctx.metadata.get("cve_severities", [])
    if severities:
        return [str(s).upper() for s in severities]
    details = ctx.metadata.get("cve_details", [])
    return [
        str(d.get("severity", "")).upper()
        for d in details
        if isinstance(d, dict)
    ]


def _extract_cwe(ctx: RiskContext) -> List[str]:
    return [str(c).upper() for c in ctx.related_cwes]


def _extract_cve_count(ctx: RiskContext) -> int:
    return len(ctx.related_cves)


def _extract_product_name(ctx: RiskContext) -> str:
    if ctx.entity_type.value == "product":
        return ctx.entity_id
    return ctx.metadata.get("product_name", "")


def _extract_risk_score(ctx: RiskContext) -> float:
    return float(ctx.metadata.get("risk_score", 0.0))


def _extract_age_days(ctx: RiskContext) -> int:
    return int(ctx.metadata.get("latest_cve_days", 9999))


FIELD_EXTRACTORS: Dict[str, FieldExtractor] = {
    "cve_severity": _extract_cve_severity,
    "cwe_match": _extract_cwe,
    "cve_count": _extract_cve_count,
    "product_name": _extract_product_name,
    "score_above": _extract_risk_score,
    "age_days": _extract_age_days,
}


# ────────────────────────────────────────────────────────────────────────────
# 规则数据类
# ────────────────────────────────────────────────────────────────────────────

class Rule:
    """单条规则的内存表示"""

    def __init__(self, raw: Dict[str, Any]) -> None:
        self.rule_id: str = str(raw.get("rule_id", ""))
        self.name: str = str(raw.get("name", ""))
        self.description: str = str(raw.get("description", ""))
        self.severity: RiskLevel = self._parse_severity(raw.get("severity", "MEDIUM"))
        self.conditions: List[Dict[str, Any]] = list(raw.get("conditions", []))
        self.match_mode: str = str(raw.get("match_mode", "all")).lower()  # all | any
        self.recommendations_raw: List[Dict[str, Any]] = list(
            raw.get("recommendations", [])
        )
        self.tags: List[str] = list(raw.get("tags", []))

        if not self.rule_id:
            raise ValueError(f"规则缺少 rule_id：{raw}")
        if self.match_mode not in ("all", "any"):
            raise ValueError(
                f"规则 {self.rule_id}: match_mode 必须为 'all' 或 'any'"
            )

    @staticmethod
    def _parse_severity(raw: Any) -> RiskLevel:
        try:
            return RiskLevel(str(raw).upper())
        except ValueError:
            return RiskLevel.MEDIUM

    def _evaluate_condition(self, cond: Dict[str, Any], ctx: RiskContext) -> bool:
        """评估单个条件"""
        cond_type = cond.get("type")
        op_name = cond.get("operator", "equals")
        expected = cond.get("value")

        extractor = FIELD_EXTRACTORS.get(cond_type)
        if extractor is None:
            return False

        op_func = OPERATORS.get(op_name)
        if op_func is None:
            return False

        actual = extractor(ctx)
        return bool(op_func(actual, expected))

    def matches(self, ctx: RiskContext) -> bool:
        """检查上下文是否满足本规则的所有条件"""
        if not self.conditions:
            return False
        results = [self._evaluate_condition(c, ctx) for c in self.conditions]
        if self.match_mode == "any":
            return any(results)
        return all(results)

    def build_recommendations(self, ctx: RiskContext) -> List[Recommendation]:
        """根据规则定义生成 Recommendation 实例"""
        recs: List[Recommendation] = []
        for raw in self.recommendations_raw:
            try:
                priority = Priority(str(raw.get("priority", "P2")).upper())
            except ValueError:
                priority = Priority.P2
            rec = Recommendation(
                rec_id=str(raw.get("rec_id") or f"REC-{uuid.uuid4().hex[:8]}"),
                title=str(raw.get("title", "")),
                description=str(raw.get("description", "")),
                priority=priority,
                timeline=str(raw.get("timeline", "30 天内")),
                action_type=str(raw.get("action_type", "config")),
                evidence=list(ctx.related_cves[:5]),
                related_cves=list(ctx.related_cves[:10]),
                related_products=(
                    [ctx.entity_id] if ctx.entity_type.value == "product" else []
                ),
                estimated_effort=str(raw.get("estimated_effort", "中")),
                rule_id=self.rule_id,
            )
            recs.append(rec)
        return recs


# ────────────────────────────────────────────────────────────────────────────
# 规则引擎
# ────────────────────────────────────────────────────────────────────────────

class RuleEngine:
    """
    规则引擎：加载、管理和执行规则。
    """

    def __init__(self, rules: Optional[List[Rule]] = None) -> None:
        self.rules: List[Rule] = list(rules) if rules else []

    @classmethod
    def from_directory(cls, rules_dir: str | Path) -> "RuleEngine":
        """
        从目录加载所有 YAML 规则文件（支持 *.yaml / *.yml）。
        """
        engine = cls()
        path = Path(rules_dir)
        if not path.exists() or not path.is_dir():
            return engine
        for fp in sorted(path.glob("*.y*ml")):
            try:
                engine.load_file(fp)
            except (yaml.YAMLError, ValueError) as e:
                # 加载失败的规则跳过，但不影响其他规则
                print(f"[RuleEngine] 加载 {fp.name} 失败: {e}")
        return engine

    def load_file(self, file_path: str | Path) -> int:
        """从单个 YAML 文件加载规则。文件可包含一条或多条（list）规则"""
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if data is None:
            return 0
        items = data if isinstance(data, list) else [data]
        loaded = 0
        for item in items:
            if not isinstance(item, dict):
                continue
            rule = Rule(item)
            self.rules.append(rule)
            loaded += 1
        return loaded

    def add_rule(self, rule: Rule) -> None:
        """动态添加规则"""
        self.rules.append(rule)

    def evaluate(self, context: RiskContext) -> List[RuleMatch]:
        """对给定上下文评估所有规则，返回匹配结果"""
        matches: List[RuleMatch] = []
        for rule in self.rules:
            try:
                if rule.matches(context):
                    matches.append(
                        RuleMatch(
                            rule_id=rule.rule_id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            matched_entity=context.entity_id,
                            matched_evidence=list(context.related_cves[:5]),
                            recommendations=rule.build_recommendations(context),
                        )
                    )
            except (KeyError, ValueError, TypeError):
                # 单条规则匹配失败不应影响整体
                continue
        return matches

    def __len__(self) -> int:
        return len(self.rules)

    def __repr__(self) -> str:
        return f"RuleEngine(rules={len(self.rules)})"


__all__ = ["Rule", "RuleEngine", "OPERATORS", "FIELD_EXTRACTORS"]
