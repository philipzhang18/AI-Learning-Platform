# CVE 风险分析与预防性维护系统 - 整体架构设计方案

## 📋 文档概览

| 项目 | 内容 |
|------|------|
| 文档名称 | CVE Risk Analysis & Preventive Maintenance System Design |
| 版本 | v1.0 |
| 创建日期 | 2026-05-13 |
| 目标 | 基于知识图谱实现 CVE 风险预测与预防性维护建议 |
| 设计原则 | 分层解耦、可扩展、与现有架构无侵入式集成 |

---

## 1. 项目现状分析

### 1.1 现有架构概览

```
┌─────────────────────────────────────────────────────────────┐
│                  表现层 (Presentation)                      │
│         cve_integrated_gui.py (Tkinter, 9 个 Tab)           │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                  业务/服务层 (Service)                      │
│   collect_cves.py │ dell_security_scraper.py │ ai_client.py │
│   knowledge_graph.py (✅ 已优化)                            │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                  数据访问层 (DAO)                           │
│       dao/dell_dao.py │ dao/dell_kb_dao.py                  │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                  存储层 (Storage)                           │
│    SQLite (主) │ WSL Redis (缓存) │ kg_cache.pkl (图)       │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 已有资产

| 资产 | 状态 | 可复用能力 |
|------|------|-----------|
| 知识图谱 (CVE × DSA × Product × CWE) | ✅ 已完成 | 图结构 + 反向索引 + 持久化缓存 |
| SQLite 数据库 (117K CVE + 2.3K DSA) | ✅ 已就绪 | 原始数据源，支持 FTS5 全文搜索 |
| AI 集成（Claude / Qwen / Ollama） | ✅ 已就绪 | LLM 推理、自然语言建议生成 |
| Redis 缓存层 | ✅ 已就绪 | 热数据加速、计算结果缓存 |
| i18n 双语支持 | ✅ 已就绪 | 报告/界面的中英文切换 |

### 1.3 缺失能力（需要新建）

- ❌ 风险量化评分引擎（CVSS + 图拓扑 + 时间衰减）
- ❌ 图算法分析（PageRank、社区检测、传播路径）
- ❌ 趋势预测（时间序列 + CWE 聚类）
- ❌ 预防性维护规则引擎
- ❌ 风险报告生成器（可视化 + 自然语言）

---

## 2. 设计目标与核心问题

### 2.1 业务目标

本系统要回答的核心问题：

1. **"哪些产品风险最高？"** — 风险评分与排序
2. **"这个 CVE 会影响哪些其他产品？"** — 风险传播分析
3. **"未来 30 天可能出现哪些高风险漏洞？"** — 趋势预测
4. **"我应该优先修复什么？"** — 优先级建议
5. **"具体如何预防？"** — 维护清单生成

### 2.2 技术目标

| 目标 | 量化指标 |
|------|---------|
| 性能 | 单次风险评分 <100ms，全量产品评分 <5s |
| 准确性 | 高风险识别召回率 >90%，误报率 <15% |
| 可解释性 | 每个建议都附带推理路径与证据节点 |
| 可扩展性 | 新增算法/规则不修改核心代码，插件化注册 |
| 非侵入 | 不修改现有 knowledge_graph.py 核心，通过扩展实现 |

### 2.3 非目标（明确排除）

- ❌ 不实现实时漏洞扫描（需要运行时探针，超出静态分析范围）
- ❌ 不替代专业威胁情报平台（如 Recorded Future）
- ❌ 不做代码级漏洞检测（SAST/DAST 是另一类工具）

---

## 3. 整体架构设计

### 3.1 分层架构图

```
┌─────────────────────────────────────────────────────────────────┐
│  L5 - 表现层 (Presentation Layer)                               │
│  ┌─────────────────────────────────────────────────────┐        │
│  │ RiskAnalysisTab (GUI)   │  CLI: analyze_risk.py    │        │
│  │ - 风险仪表板            │  - 批量分析脚本          │        │
│  │ - 风险产品 Top-N        │  - 定时报告生成          │        │
│  │ - 详细风险报告          │                           │        │
│  │ - 预防建议清单          │                           │        │
│  └─────────────────────────────────────────────────────┘        │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│  L4 - 报告编排层 (Orchestration)                                │
│  ┌─────────────────────────────────────────────────────┐        │
│  │ risk/report_builder.py                              │        │
│  │ - 聚合多个分析模块的输出                            │        │
│  │ - 生成结构化风险报告 (JSON + Markdown + HTML)       │        │
│  │ - 集成 AI 增强（自然语言解释）                      │        │
│  └─────────────────────────────────────────────────────┘        │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│  L3 - 分析引擎层 (Analysis Engines) ★ 核心新增模块              │
│  ┌───────────────┬───────────────┬────────────────┐             │
│  │ risk/         │ risk/         │ risk/          │             │
│  │ scoring.py    │ propagation.py│ prediction.py  │             │
│  │ 风险评分      │ 传播分析      │ 趋势预测       │             │
│  ├───────────────┼───────────────┼────────────────┤             │
│  │ risk/         │ risk/         │ risk/          │             │
│  │ similarity.py │ rules.py      │ recommender.py │             │
│  │ 产品相似度    │ 规则引擎      │ 建议生成       │             │
│  └───────────────┴───────────────┴────────────────┘             │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│  L2 - 图谱基础层 (Graph Foundation) ✅ 已完成                   │
│  ┌─────────────────────────────────────────────────────┐        │
│  │ knowledge_graph.py                                  │        │
│  │ - KnowledgeGraph (CVE × DSA × Product × CWE)        │        │
│  │ - 反向索引 / 持久化缓存 / 快速查询                  │        │
│  └─────────────────────────────────────────────────────┘        │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│  L1 - 数据访问层 (DAO) ✅ 已完成                                │
│  dao/dell_dao.py  │  dao/cve_dao.py  │  SQLite  │  Redis         │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 模块划分与职责

新增 `risk/` 目录，与现有 `dao/`、`tests/` 同级：

```
E:\AI\Claude\CVE\
├── knowledge_graph.py          # L2 - 已完成
├── dao/                        # L1 - 已完成
├── risk/                       # L3 - ★ 新增目录
│   ├── __init__.py
│   ├── base.py                 # 基类与通用接口
│   ├── scoring.py              # 风险评分引擎
│   ├── propagation.py          # 风险传播分析
│   ├── prediction.py           # 趋势预测
│   ├── similarity.py           # 产品相似度分析
│   ├── rules.py                # 规则引擎（可插拔）
│   ├── recommender.py          # 预防性维护建议生成
│   ├── report_builder.py       # L4 - 报告编排
│   └── rules/                  # 规则定义目录
│       ├── critical_rce.yaml
│       ├── privilege_escalation.yaml
│       └── supply_chain.yaml
├── tests/
│   └── test_risk_*.py          # 各模块单元测试
└── docs/
    └── risk_analysis_design.md # 本文档
```

---

## 4. 核心算法设计

### 4.1 风险评分模型 (Risk Scoring)

**目标**：为每个产品节点计算综合风险分数 (0-100)

**公式设计**（多因子加权）：

```
RiskScore(product) = α·CVSS_Avg + β·PageRank + γ·Recency + δ·Severity_Density
                      + ε·CWE_Diversity + ζ·Exposure

其中：
  α = 0.30  CVSS 平均分（漏洞严重度）
  β = 0.20  图 PageRank（节点在图中的重要性）
  γ = 0.15  时间衰减因子（越近的漏洞权重越高）
  δ = 0.15  高危漏洞密度（CRITICAL/HIGH 占比）
  ε = 0.10  CWE 多样性（攻击面广度）
  ζ = 0.10  暴露度（与其他产品的共享漏洞数）
```

**各因子定义**：

| 因子 | 计算方法 | 范围 |
|------|---------|------|
| CVSS_Avg | 产品关联所有 CVE 的 CVSS 分数平均 | 0-10 → 归一化 0-100 |
| PageRank | NetworkX `nx.pagerank(G, alpha=0.85)` | 0-1 → ×100 |
| Recency | `exp(-days_since_latest_cve / 90)` | 0-1 → ×100 |
| Severity_Density | (Critical*1.0 + High*0.7 + Medium*0.4 + Low*0.1) / total | 0-1 → ×100 |
| CWE_Diversity | 关联不同 CWE 数量 / 理论最大值 | 0-1 → ×100 |
| Exposure | 共享 CVE 的邻居产品数 / 全产品数 | 0-1 → ×100 |

**风险等级映射**：

```
90-100  紧急 (Critical)     — 立即处理
75-89   高危 (High)          — 48 小时内处理
50-74   中危 (Medium)        — 7 天内处理
25-49   低危 (Low)           — 30 天内处理
0-24    可忽略 (Info)         — 定期关注
```

**接口设计**：

```python
class RiskScorer:
    def __init__(self, kg: KnowledgeGraph, weights: Optional[Dict] = None):
        """可自定义权重"""

    def score_product(self, product: str) -> RiskScore:
        """单个产品评分，返回结构化结果"""

    def score_all_products(self) -> List[RiskScore]:
        """批量评分所有产品"""

    def score_cve(self, cve_id: str) -> RiskScore:
        """单个 CVE 评分（用于排序）"""

    def explain(self, product: str) -> Dict[str, float]:
        """返回各因子贡献度，用于可解释性"""
```

### 4.2 风险传播分析 (Risk Propagation)

**目标**：识别某个高危 CVE 可能影响的间接产品范围

**算法**：双向 BFS + 加权传播

```
给定 CVE₀，传播模型：
  Step 1: 查询 CVE₀ 的直接受影响产品 P₀
  Step 2: 对 P₀ 中每个产品，查询它共享的其他 CVE
  Step 3: 对共享 CVE，查询它们影响的其他产品 P₁
  Step 4: 计算传播路径的可信度衰减：
          confidence = (shared_cwe_count / total_cwe) * decay_factor^hop

  输出：按传播可信度排序的影响产品列表
```

**接口设计**：

```python
class PropagationAnalyzer:
    def trace_impact(self, cve_id: str, max_hops: int = 2) -> List[ImpactPath]:
        """追踪 CVE 的传播影响路径"""

    def affected_radius(self, cve_id: str) -> Dict[int, List[str]]:
        """按跳数返回受影响产品（1 跳直接，2+ 跳间接）"""

    def shared_vulnerabilities(self, product_a: str, product_b: str) -> List[str]:
        """两个产品的共享漏洞（供应链风险指标）"""
```

### 4.3 趋势预测 (Trend Prediction)

**目标**：基于历史数据预测未来 30/60/90 天的风险趋势

**数据特征**：
- 每月新增 CVE 数量（按产品/CWE 聚合）
- CVSS 分数分布变化
- CWE 类型频率演变

**算法选择**：
- **短期预测 (30 天)**：指数平滑 (Holt-Winters)
- **中期预测 (90 天)**：线性回归 + 季节性分解
- **模式识别**：CWE 聚类（K-Means on 高维特征）

**预测输出**：

```python
@dataclass
class TrendForecast:
    product: str
    predicted_new_cves: int           # 预测新增 CVE 数
    confidence_interval: Tuple[int, int]  # 置信区间
    hot_cwes: List[Tuple[str, float]]  # 预测高频 CWE
    risk_trend: str                    # "rising" | "stable" | "declining"
    forecast_date: str                 # 预测截止日期
```

**接口设计**：

```python
class TrendPredictor:
    def forecast_product(self, product: str, days: int = 30) -> TrendForecast:
        """单产品趋势预测"""

    def forecast_top_risks(self, days: int = 30, k: int = 10) -> List[TrendForecast]:
        """Top-K 高风险上升产品"""

    def cwe_trends(self, days: int = 90) -> Dict[str, float]:
        """CWE 类型上升率"""
```

### 4.4 产品相似度分析 (Similarity)

**目标**：找出与高危产品相似的产品，预警"同类风险"

**相似度定义**：

```
similarity(A, B) = 0.5 * Jaccard(CWE_A, CWE_B)
                 + 0.3 * Jaccard(CVE_A, CVE_B)
                 + 0.2 * name_similarity(A, B)
```

**应用场景**：
- Dell PowerStore 被发现重大漏洞 → 自动预警同类产品 Dell Unity、Dell VxRail
- 新产品上线 → 基于相似产品历史漏洞预测潜在风险

**接口设计**：

```python
class ProductSimilarityAnalyzer:
    def similar_products(self, product: str, k: int = 5) -> List[Tuple[str, float]]:
        """查找相似产品 Top-K"""

    def cluster_products(self, n_clusters: int = 10) -> Dict[int, List[str]]:
        """产品聚类"""
```

### 4.5 规则引擎 (Rule Engine)

**目标**：定义可扩展的风险规则，支持声明式配置

**规则定义格式** (YAML)：

```yaml
# risk/rules/critical_rce.yaml
rule_id: R001
name: 未修复的关键远程代码执行漏洞
severity: CRITICAL
conditions:
  - type: cve_severity
    operator: equals
    value: CRITICAL
  - type: cwe_match
    operator: in
    value: [CWE-78, CWE-94, CWE-502]  # RCE 相关 CWE
  - type: age_days
    operator: greater_than
    value: 30
recommendations:
  - priority: P0
    action: 立即应用官方补丁
    timeline: 24 小时内
  - priority: P0
    action: 实施网络隔离作为临时缓解
    timeline: 立即
```

**规则匹配引擎**：

```python
class RuleEngine:
    def __init__(self, rules_dir: Path):
        """从 rules/ 目录加载所有 YAML 规则"""

    def evaluate(self, context: RiskContext) -> List[RuleMatch]:
        """对给定上下文评估所有规则"""

    def add_rule(self, rule: Rule) -> None:
        """动态添加规则"""
```

### 4.6 预防性维护建议生成 (Recommender)

**目标**：综合所有分析结果，生成结构化+自然语言建议

**建议类型**：

| 类型 | 示例 | 生成来源 |
|------|------|---------|
| 补丁优先级 | "立即应用 DSA-2024-XXX" | 规则引擎 |
| 配置加固 | "禁用 SMBv1 协议" | CWE 关联规则 |
| 监控增强 | "增加对 XX 端口的日志" | 传播分析 |
| 架构调整 | "考虑升级到 PowerStore X 系列" | 相似度分析 |
| 应急预案 | "准备 IR 响应流程" | 趋势预测 |

**接口设计**：

```python
class PreventiveRecommender:
    def recommend_for_product(self, product: str) -> List[Recommendation]:
        """为产品生成维护建议"""

    def recommend_for_organization(self, products: List[str]) -> OrganizationPlan:
        """为整个组织的产品组合生成综合计划"""

    def recommend_with_ai(self, product: str) -> str:
        """调用 LLM 生成自然语言建议（可选）"""
```

---

## 5. 数据模型设计

### 5.1 核心数据结构

```python
# risk/base.py

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from enum import Enum


class RiskLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class RiskScore:
    """单个实体的风险评分结果"""
    entity_id: str                    # 产品名或 CVE ID
    entity_type: str                  # "product" | "cve"
    score: float                      # 0-100
    level: RiskLevel
    factors: Dict[str, float]         # 各因子贡献度
    evidence: List[str]               # 证据节点（CVE/DSA ID）
    computed_at: datetime = field(default_factory=datetime.now)


@dataclass
class ImpactPath:
    """风险传播路径"""
    source_cve: str
    target_product: str
    hops: int
    path: List[str]                   # 节点序列
    confidence: float                 # 0-1


@dataclass
class Recommendation:
    """单条预防性维护建议"""
    rec_id: str
    title: str
    description: str
    priority: str                     # P0/P1/P2/P3
    timeline: str                     # "立即" / "24 小时" / "7 天" / "30 天"
    action_type: str                  # "patch" / "config" / "monitor" / "architect"
    evidence: List[str]
    related_cves: List[str]
    estimated_effort: str             # "低" / "中" / "高"


@dataclass
class RiskReport:
    """完整风险报告"""
    report_id: str
    subject: str                      # 产品名或组织名
    generated_at: datetime
    summary: Dict[str, int]           # {"critical": 3, "high": 12, ...}
    risk_scores: List[RiskScore]
    impact_analysis: List[ImpactPath]
    trend_forecast: Optional['TrendForecast']
    recommendations: List[Recommendation]
    ai_narrative: Optional[str]       # AI 生成的自然语言摘要
```

### 5.2 与现有数据库的关系

**无侵入原则**：不修改现有表结构，通过新表存储分析结果

```sql
-- 新增表：风险评分历史（可选，用于趋势可视化）
CREATE TABLE IF NOT EXISTS risk_scores_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id TEXT NOT NULL,
    entity_type TEXT NOT NULL,         -- 'product' | 'cve'
    score REAL NOT NULL,
    level TEXT NOT NULL,
    factors_json TEXT,
    computed_at TEXT NOT NULL,
    INDEX idx_entity (entity_id, computed_at)
);

-- 新增表：生成的建议（用于跟踪执行状态）
CREATE TABLE IF NOT EXISTS recommendations (
    rec_id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    priority TEXT,
    status TEXT DEFAULT 'pending',    -- pending | in_progress | done | dismissed
    created_at TEXT NOT NULL,
    updated_at TEXT,
    evidence_json TEXT
);
```

---

## 6. 数据流设计

### 6.1 完整分析流水线

```
┌──────────┐
│  用户    │
│ (GUI/CLI)│
└────┬─────┘
     │ "分析 Dell PowerStore 风险"
     ▼
┌─────────────────────┐
│ RiskAnalysisService │ ← 统一入口
└────┬────────────────┘
     │
     ├─► KnowledgeGraph.load_cache() ..................... 加载图
     │
     ├─► RiskScorer.score_product() ...................... 计算风险分
     │       ├─ CVSS 聚合（查 SQLite）
     │       ├─ PageRank（查图）
     │       ├─ 时间衰减（查图节点属性）
     │       └─ 其他因子...
     │
     ├─► PropagationAnalyzer.trace_impact() ............... 传播分析
     │       └─ 图遍历（ego_subgraph + 加权）
     │
     ├─► TrendPredictor.forecast_product() ................ 趋势预测
     │       └─ 时间序列模型（历史数据 → 30/60/90 天）
     │
     ├─► ProductSimilarityAnalyzer.similar_products() ...... 相似产品
     │       └─ 图嵌入 / Jaccard 相似度
     │
     ├─► RuleEngine.evaluate() ............................. 规则匹配
     │       └─ 加载 rules/*.yaml，匹配产生告警
     │
     ├─► PreventiveRecommender.recommend_for_product() ..... 建议生成
     │       ├─ 聚合以上所有输出
     │       ├─ 规则触发的建议
     │       └─ [可选] AI 增强的自然语言
     │
     ▼
┌─────────────────────┐
│  ReportBuilder      │ ← 编排
│  - JSON / MD / HTML │
└────┬────────────────┘
     │
     ▼
┌─────────────────────┐
│  返回用户           │
│  + 存储到 SQLite    │
└─────────────────────┘
```

### 6.2 缓存策略

| 缓存层 | 存储位置 | TTL | 用途 |
|--------|---------|-----|------|
| L0 - 图结构缓存 | `kg_cache.pkl` | 24h | 图对象（已实现） |
| L1 - 评分结果缓存 | Redis | 1h | 避免重复计算 |
| L2 - 历史评分 | SQLite | 永久 | 趋势分析数据源 |
| L3 - AI 生成内容 | Redis | 6h | 减少 API 调用 |

---

## 7. GUI 集成方案

### 7.1 新增 Tab：风险分析

在现有 9 个 Tab 基础上新增第 10 个 Tab："风险分析"

```
┌────────────────────────────────────────────────────────────────┐
│  [NVD] [Dell] [Dell KB] [AI 分析] [解决方案] [学习] [统计]     │
│  [知识图谱] [日志] [★ 风险分析]  ← 新增                        │
└────────────────────────────────────────────────────────────────┘
```

### 7.2 Tab 内部布局

```
┌──────────────────────────────────────────────────────────────┐
│ 风险分析仪表板                                    [刷新][导出] │
├──────────────┬──────────────────────────────────────────────┤
│              │ ┌──────────────────────────────────────────┐ │
│ 风险产品     │ │  风险评分仪表盘（径向图）                │ │
│ Top-10       │ │  当前产品: Dell PowerStore               │ │
│              │ │  综合评分: 87.3 (HIGH)                   │ │
│ 1. PowerStore│ │                                          │ │
│    87.3 HIGH │ │  因子分解:                               │ │
│ 2. VxRail    │ │  ■ CVSS: 8.5/10  ████████░░              │ │
│    82.1 HIGH │ │  ■ PageRank: 0.75  ███████░░             │ │
│ 3. Unity     │ │  ■ 时效性: 0.92  █████████░              │ │
│    76.4 HIGH │ │  ■ 严重度密度: 0.68  ███████░░           │ │
│              │ └──────────────────────────────────────────┘ │
│ [筛选]       │                                                │
│ ☑ Critical   │ ┌──────────────────────────────────────────┐ │
│ ☑ High       │ │  预防性维护建议                          │ │
│ ☐ Medium     │ │  [P0] 立即应用 DSA-2024-123              │ │
│ ☐ Low        │ │  [P0] 实施网络分段                       │ │
│              │ │  [P1] 升级固件至 v3.2+                   │ │
│              │ │  [P2] 启用增强日志                       │ │
│              │ └──────────────────────────────────────────┘ │
│              │                                                │
│              │ ┌──────────────────────────────────────────┐ │
│              │ │  趋势预测（未来 30 天）                  │ │
│              │ │  [折线图：历史 + 预测]                   │ │
│              │ │  预测新增 CVE: 5 ± 2 个                  │ │
│              │ │  风险趋势: ↑ 上升                        │ │
│              │ └──────────────────────────────────────────┘ │
└──────────────┴──────────────────────────────────────────────┘
```

### 7.3 与知识图谱 Tab 的联动

- 在知识图谱 Tab 选中某个产品 → 右键菜单"分析风险" → 跳转到风险分析 Tab
- 风险分析 Tab 中的"查看影响图" → 跳转到知识图谱 Tab 并聚焦对应节点

---

## 8. 技术选型

| 能力 | 选用方案 | 理由 |
|------|---------|------|
| 图算法 | NetworkX (已用) | 与现有 kg 无缝集成 |
| 时间序列预测 | statsmodels (Holt-Winters) | 轻量，适合小数据量 |
| 聚类算法 | scikit-learn (K-Means) | 已有依赖，成熟 |
| 规则配置 | PyYAML | 声明式、可维护 |
| 可视化 | matplotlib + tkinter | 已用，保持一致 |
| AI 增强 | 复用现有 `ai_client.py` | 统一 Claude/Qwen 调用 |
| 缓存 | 复用现有 Redis | 不引入新依赖 |

**新增依赖**（添加到 requirements.txt）：

```
statsmodels>=0.14.0    # 时间序列预测
scikit-learn>=1.3.0    # 聚类（可能已有）
PyYAML>=6.0            # 规则配置
```

---

## 9. 实施路线图

### Phase 1: 核心评分引擎（3-4 天）

**交付物**：
- `risk/base.py` - 数据结构
- `risk/scoring.py` - 风险评分
- `risk/rules.py` - 规则引擎（基础版）
- `tests/test_risk_scoring.py` - 单元测试

**验收标准**：
- ✅ 能够对 Top-100 产品计算风险分（<5s）
- ✅ 评分因子分解可解释
- ✅ 单元测试覆盖率 >80%

### Phase 2: 传播与相似度分析（2-3 天）

**交付物**：
- `risk/propagation.py` - 传播分析
- `risk/similarity.py` - 相似度分析
- `tests/test_risk_propagation.py`

**验收标准**：
- ✅ 2-hop 传播分析 <500ms
- ✅ 相似度 Top-10 查询 <100ms

### Phase 3: 趋势预测（2-3 天）

**交付物**：
- `risk/prediction.py` - 趋势预测
- `tests/test_risk_prediction.py`

**验收标准**：
- ✅ 30 天预测 MAPE <25%（与历史回测）
- ✅ 单产品预测 <1s

### Phase 4: 建议生成与报告（2-3 天）

**交付物**：
- `risk/recommender.py` - 建议生成
- `risk/report_builder.py` - 报告编排
- `risk/rules/*.yaml` - 预置规则库（10+ 条）

**验收标准**：
- ✅ 生成结构化 JSON + Markdown + HTML 三种格式
- ✅ AI 增强的自然语言摘要（可选）

### Phase 5: GUI 集成（2 天）

**交付物**：
- GUI 新增"风险分析" Tab
- 与知识图谱 Tab 联动
- i18n 双语支持

**验收标准**：
- ✅ Tab 加载 <2s
- ✅ 用户操作流畅，无卡顿

### Phase 6: 端到端测试与优化（1-2 天）

**交付物**：
- `benchmark_risk_analysis.py` - 性能基准
- 集成测试
- 用户文档

**总工作量**：约 12-17 天

---

## 10. 风险与对策

| 风险 | 影响 | 对策 |
|------|------|------|
| 数据不足导致预测不准 | 趋势预测失真 | 回退到规则引擎，明确标注置信度 |
| 图规模过大，评分慢 | 用户等待 | 分层评分（热产品优先）+ 后台批处理 |
| 规则维护负担 | 规则库过时 | YAML 配置 + 社区规则分享机制 |
| AI API 调用超限 | 成本/可用性 | Redis 缓存 + 降级到纯规则模式 |
| 误报率高 | 用户不信任 | 提供"反馈机制"，用户可标记误报，累积训练数据 |

---

## 11. 可扩展性设计

### 11.1 算法插件化

所有分析引擎继承统一基类，支持运行时注册：

```python
# risk/base.py
class Analyzer(ABC):
    name: str

    @abstractmethod
    def analyze(self, context: RiskContext) -> AnalysisResult:
        ...

# 注册机制
_registry: Dict[str, Type[Analyzer]] = {}

def register_analyzer(name: str):
    def decorator(cls):
        _registry[name] = cls
        return cls
    return decorator
```

### 11.2 未来扩展方向

| 扩展 | 工作量 | 价值 |
|------|-------|------|
| 接入外部威胁情报（MITRE ATT&CK） | 高 | 大幅提升预测准确度 |
| 接入 EPSS (Exploit Prediction Scoring System) | 中 | 量化"被利用概率" |
| 图神经网络 (GNN) 替代 PageRank | 高 | 更精准的节点重要性 |
| 多租户支持（不同组织资产清单） | 中 | SaaS 化潜力 |
| 历史事件回测 | 中 | 算法验证与持续优化 |

---

## 12. 验收指标总结

| 类别 | 指标 | 目标值 |
|------|------|-------|
| **性能** | 单产品风险评分延迟 | <100ms |
| | 全量产品评分（~300 个产品） | <5s |
| | GUI Tab 加载 | <2s |
| | 报告生成 | <3s |
| **准确性** | 高风险召回率 | >90% |
| | 误报率 | <15% |
| | 30 天趋势预测 MAPE | <25% |
| **可用性** | 单元测试覆盖率 | >80% |
| | 规则库规模 | 初期 10+ 条 |
| | 三种输出格式 | JSON/MD/HTML |
| **可解释性** | 评分因子可追溯 | 100% |
| | 建议附带证据链 | 100% |

---

## 13. 附录

### 13.1 与现有模块的依赖关系

```
risk/scoring.py      ──uses──► knowledge_graph.py, dao/dell_dao.py
risk/propagation.py  ──uses──► knowledge_graph.py
risk/prediction.py   ──uses──► dao/dell_dao.py, dao/cve_dao.py
risk/similarity.py   ──uses──► knowledge_graph.py
risk/rules.py        ──uses──► risk/base.py
risk/recommender.py  ──uses──► risk/*, ai_client.py
risk/report_builder.py──uses──► risk/*, i18n.py
GUI 新 Tab           ──uses──► risk/report_builder.py
```

### 13.2 参考文献

- NIST SP 800-30: Guide for Conducting Risk Assessments
- CVSS v3.1 Specification Document
- MITRE ATT&CK Framework
- EPSS (Exploit Prediction Scoring System)
- Graph Neural Networks for Cybersecurity (Arxiv)

---

**文档状态**: ✅ 待评审
**下一步**: 等待用户确认后，按 Phase 1 开始实施

*本设计遵循项目现有"轻量级、非侵入式"的架构理念，所有新增模块都可独立运行和测试，不影响现有功能。*
