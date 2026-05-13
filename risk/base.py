"""
风险分析模块 - 基础数据结构与通用接口

定义风险分析系统中所有模块共享的数据类、枚举、常量与抽象基类。
本模块为整个 risk/ 包的基础设施，不依赖任何其他 risk/ 子模块。
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


# ────────────────────────────────────────────────────────────────────────────
# 枚举定义
# ────────────────────────────────────────────────────────────────────────────

class RiskLevel(str, Enum):
    """风险等级（继承 str 便于序列化）"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_score(cls, score: float) -> "RiskLevel":
        """根据 0-100 分数映射到风险等级"""
        if score >= 90:
            return cls.CRITICAL
        if score >= 75:
            return cls.HIGH
        if score >= 50:
            return cls.MEDIUM
        if score >= 25:
            return cls.LOW
        return cls.INFO


class EntityType(str, Enum):
    """风险评估实体类型"""
    PRODUCT = "product"
    CVE = "cve"
    DSA = "dsa"


class Priority(str, Enum):
    """建议优先级"""
    P0 = "P0"  # 立即（24h 内）
    P1 = "P1"  # 紧急（48h 内）
    P2 = "P2"  # 高（7d 内）
    P3 = "P3"  # 中（30d 内）
    P4 = "P4"  # 低（计划内）


# ────────────────────────────────────────────────────────────────────────────
# 评分权重（默认值）
# ────────────────────────────────────────────────────────────────────────────

DEFAULT_SCORING_WEIGHTS: Dict[str, float] = {
    "cvss_avg": 0.30,           # CVSS 平均分
    "pagerank": 0.20,            # 图 PageRank
    "recency": 0.15,             # 时间衰减
    "severity_density": 0.15,    # 高危漏洞密度
    "cwe_diversity": 0.10,       # CWE 多样性（攻击面广度）
    "exposure": 0.10,            # 暴露度（共享漏洞数）
}


# 严重度密度子权重（计算 severity_density 因子时使用）
SEVERITY_WEIGHT_MAP: Dict[str, float] = {
    "CRITICAL": 1.0,
    "HIGH": 0.7,
    "MEDIUM": 0.4,
    "LOW": 0.1,
    "": 0.0,  # 未知严重度
}


# ────────────────────────────────────────────────────────────────────────────
# 核心数据类
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class RiskScore:
    """单个实体的风险评分结果

    设计要点：
    - factors 字段记录各因子贡献度，用于可解释性
    - evidence 字段记录支撑评分的关键节点（CVE/DSA ID）
    - score 范围 0-100，level 由 score 推导
    """
    entity_id: str
    entity_type: EntityType
    score: float  # 0-100
    level: RiskLevel
    factors: Dict[str, float] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)
    computed_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["computed_at"] = self.computed_at.isoformat()
        d["entity_type"] = self.entity_type.value
        d["level"] = self.level.value
        return d


@dataclass
class ImpactPath:
    """风险传播路径

    示例：CVE-2024-XXX -> Dell PowerStore -> [共享 CWE-78] -> Dell Unity
    """
    source_cve: str
    target_product: str
    hops: int
    path: List[str]  # 节点序列，便于可视化
    confidence: float  # 0-1
    shared_cwes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Recommendation:
    """单条预防性维护建议"""
    rec_id: str
    title: str
    description: str
    priority: Priority
    timeline: str  # 自然语言时间线，如"24 小时内"
    action_type: str  # patch | config | monitor | architect | response
    evidence: List[str] = field(default_factory=list)
    related_cves: List[str] = field(default_factory=list)
    related_products: List[str] = field(default_factory=list)
    estimated_effort: str = "中"  # 低 | 中 | 高
    rule_id: Optional[str] = None  # 来源规则 ID

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["priority"] = self.priority.value
        return d


@dataclass
class TrendForecast:
    """趋势预测结果"""
    subject: str  # 产品名 / CWE 名
    forecast_days: int
    predicted_count: int  # 预测新增 CVE 数
    confidence_interval: Tuple[int, int]
    hot_cwes: List[Tuple[str, float]] = field(default_factory=list)
    risk_trend: str = "stable"  # rising | stable | declining
    forecast_date: datetime = field(default_factory=datetime.now)
    method: str = "naive"  # 使用的预测方法

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["forecast_date"] = self.forecast_date.isoformat()
        d["confidence_interval"] = list(self.confidence_interval)
        return d


@dataclass
class RuleMatch:
    """规则匹配结果"""
    rule_id: str
    rule_name: str
    severity: RiskLevel
    matched_entity: str
    matched_evidence: List[str] = field(default_factory=list)
    recommendations: List[Recommendation] = field(default_factory=list)


@dataclass
class RiskContext:
    """风险分析上下文（传给各分析引擎的统一输入）"""
    entity_id: str
    entity_type: EntityType
    related_cves: List[str] = field(default_factory=list)
    related_products: List[str] = field(default_factory=list)
    related_cwes: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskReport:
    """完整风险报告（聚合所有分析结果）"""
    report_id: str
    subject: str
    subject_type: EntityType
    generated_at: datetime
    summary: Dict[str, int] = field(default_factory=dict)  # {"critical":3,"high":12,...}
    risk_scores: List[RiskScore] = field(default_factory=list)
    impact_paths: List[ImpactPath] = field(default_factory=list)
    trend_forecast: Optional[TrendForecast] = None
    recommendations: List[Recommendation] = field(default_factory=list)
    rule_matches: List[RuleMatch] = field(default_factory=list)
    ai_narrative: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "subject": self.subject,
            "subject_type": self.subject_type.value,
            "generated_at": self.generated_at.isoformat(),
            "summary": self.summary,
            "risk_scores": [s.to_dict() for s in self.risk_scores],
            "impact_paths": [p.to_dict() for p in self.impact_paths],
            "trend_forecast": self.trend_forecast.to_dict() if self.trend_forecast else None,
            "recommendations": [r.to_dict() for r in self.recommendations],
            "rule_matches": [
                {
                    "rule_id": m.rule_id,
                    "rule_name": m.rule_name,
                    "severity": m.severity.value,
                    "matched_entity": m.matched_entity,
                    "matched_evidence": m.matched_evidence,
                    "recommendations": [r.to_dict() for r in m.recommendations],
                }
                for m in self.rule_matches
            ],
            "ai_narrative": self.ai_narrative,
            "metadata": self.metadata,
        }


# ────────────────────────────────────────────────────────────────────────────
# 抽象基类（用于扩展性）
# ────────────────────────────────────────────────────────────────────────────

class Analyzer(ABC):
    """所有分析引擎的基类"""
    name: str = "base"

    @abstractmethod
    def analyze(self, context: RiskContext) -> Any:
        """执行分析并返回结果"""
        ...


# ────────────────────────────────────────────────────────────────────────────
# 工具函数
# ────────────────────────────────────────────────────────────────────────────

def normalize_score(value: float, min_val: float = 0.0, max_val: float = 100.0) -> float:
    """将任意范围的值归一化到 [0, 100]"""
    if max_val == min_val:
        return 0.0
    normalized = (value - min_val) / (max_val - min_val) * 100.0
    return max(0.0, min(100.0, normalized))


def clip(value: float, low: float = 0.0, high: float = 1.0) -> float:
    """裁剪到 [low, high] 范围"""
    return max(low, min(high, value))


__all__ = [
    "RiskLevel",
    "EntityType",
    "Priority",
    "DEFAULT_SCORING_WEIGHTS",
    "SEVERITY_WEIGHT_MAP",
    "RiskScore",
    "ImpactPath",
    "Recommendation",
    "TrendForecast",
    "RuleMatch",
    "RiskContext",
    "RiskReport",
    "Analyzer",
    "normalize_score",
    "clip",
]
