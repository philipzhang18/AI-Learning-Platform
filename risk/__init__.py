"""
风险分析模块 (risk/)

基于知识图谱的 CVE 风险预测与预防性维护建议系统。

子模块：
- base: 数据结构与通用接口
- scoring: 风险评分引擎
- rules: 规则引擎
- propagation: 风险传播分析（Phase 2）
- prediction: 趋势预测（Phase 3）
- similarity: 产品相似度（Phase 2）
- recommender: 预防性维护建议（Phase 4）
- report_builder: 报告编排（Phase 4）
"""
from risk.base import (
    RiskLevel,
    EntityType,
    Priority,
    RiskScore,
    ImpactPath,
    Recommendation,
    TrendForecast,
    RuleMatch,
    RiskContext,
    RiskReport,
    Analyzer,
    DEFAULT_SCORING_WEIGHTS,
    SEVERITY_WEIGHT_MAP,
    normalize_score,
    clip,
)

__all__ = [
    "RiskLevel",
    "EntityType",
    "Priority",
    "RiskScore",
    "ImpactPath",
    "Recommendation",
    "TrendForecast",
    "RuleMatch",
    "RiskContext",
    "RiskReport",
    "Analyzer",
    "DEFAULT_SCORING_WEIGHTS",
    "SEVERITY_WEIGHT_MAP",
    "normalize_score",
    "clip",
]

__version__ = "1.0.0"
