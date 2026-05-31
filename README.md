# 智能知识管理平台

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-5.6.0-orange.svg)](CHANGELOG.md)

以**知识管理**为核心的智能平台，通过多渠道收集学习资料（播客、文件、网页、数据库数据），采用 AI 方法进行深度学习与分析。

---

## 代码规模

| 指标 | 数值 |
|------|------|
| Python 总代码行数 | ~18,000 行 |
| 主程序 (cve_integrated_gui.py) | ~14,000 行 |
| 核心 Python 文件 | 19 个（含 knowledge_graph.py） |
| GUI 标签页 | 10 个主标签 + 3 个子标签 |
| 数据库表 | 28 张（含 FTS 虚拟表） |
| 数据库大小 | ~496 MB |
| CVE 漏洞记录 | 117,330 条 |
| Dell 安全公告 | 2,358 条 |

---

## 功能概览

### 🌐 国际化支持
- **中英文界面切换** — 支持中文和英文界面，可在应用内切换
- **语言持久化** — 语言设置自动保存，重启后保持
- **完整国际化** — 界面元素、按钮、消息提示、日志输出、AI 分析报告全面支持双语
- **AI 报告双语** — 单条和多行 AI 分析报告按当前界面语言输出（含图标、星级严重等级、粗体关键点）
- **导出双语** — 解决方案历史导出 HTML/Markdown/CSV/TXT 在英文模式下全部输出英文

### 内容收集
- **NVD CVE 数据采集** — 从 NVD 获取最新漏洞数据，支持自定义时间范围
- **Dell 安全公告** — 多策略抓取（Exa API / HTTP / Selenium），支持单条 URL 抓取
- **Dell 技术库** — 单条 kbdoc URL 抓取技术文档，提取文章编号/内容/解决方案
- **IT 新闻简报** — 自动采集科技新闻，AI 生成每日简报和播客脚本
- **网页/文件/RSS** — 支持从任意 URL、本地文件加载学习内容

### AI 深度学习
- **费曼学习法** — AI 辅助的交互式学习对话，支持关键字搜索数据库内容
- **智能摘要** — 加载资料后自动生成核心摘要、主题提炼、5 个分层学习问题（可点击填入）
- **来源引用** — AI 回答带 [📚] 引用标记，严格基于资料回答（防幻觉约束）
- **学习产物** — 一键生成时间线、思维导图、学习指南、FAQ、对话播客（可保存/复制）
- **AI 分析** — 漏洞分析、新闻解读、知识点深度分析（Claude / Qwen 多模型）
- **CVE-Dell 关联** — 自动匹配漏洞与厂商公告的关联关系，双击查看详情

### 数据可视化
- **统计分析** — 严重等级饼图、月度增长趋势图（13个月）、数据汇聚图
- **图表缩放** — 支持 70%-160% 缩放控制
- **统计卡片** — 7 张实时数据卡片（NVD/Dell/关联/严重等级分布）

### 智能预测（产品线 / 版本 / 微码三层）
- **产品线级 DSA 概率** — Poisson 速率模型，29 条 Dell 产品线，30/60/90 天 P(≥1 DSA) + 80% 置信区间
- **版本级预测** — Phase 2 三件套：VMR 验证 / Bayesian 年龄调整先验 / Bootstrap 500 次抽样 CI
- **微码级风险评分** — 产品线 × 机型 × 类型 × 版本四元组，0~100 exposure_score（freq + severity + recency 三因子）
- **CISA KEV 加权** — 已被野外利用的 CVE 自动加分（每个 +5，上限 +15），本地 7 天缓存
- **范围语义解析** — 自动展开 `prior to`、`X to Y`、`X and later` 等表述到具体版本集
- **反向查询** — "我有 R640 BIOS 2.10.0，受哪些 DSA 影响" 直接命中
- **三层联动** — 选中产品线自动过滤微码 Tab，钻取式分析

### 知识图谱（已合并到智能预测 Tab）
- **内存图谱** — 基于 NetworkX 在内存中构建 CVE × DSA × 产品 × CWE 四类节点的有向图，无需 Neo4j 等重型数据库
- **关联查询** — 从 CVE 反查受影响 Dell 产品、从产品查关联 CVE、CWE 漏洞类型分布
- **交互可视化** — tkinter 内嵌 matplotlib 画布，节点按类型着色（CVE 蓝 / DSA 橙 / 产品绿 / CWE 紫），支持 spring / kamada_kawai / circular 三种布局
- **邻域钻取** — 输入节点 ID + 邻域半径绘制局部子图，双击邻居节点跳转为新中心
- **采样过滤** — 可限制 CVE/DSA 采样数量与严重度白名单（CRITICAL/HIGH/MEDIUM/LOW），避免一次加载 12 万 CVE
- **标准导出** — GraphML（可在 Gephi / yEd / Cytoscape 打开）、node-link JSON（D3.js 可用）

### 辅助功能
- **TTS 播报** — 新闻简报语音播放（Windows SAPI）
- **数据导出** — 支持全部 8 个数据源，Markdown / TXT / HTML 格式，指定编号单条导出、选中项导出、按数量批量导出，输出完整内容不截断
- **数据导入** — Dell技术库 Markdown/TXT 格式导入（含多行内容解析）

---

## 快速开始

### 环境要求
- Python 3.8+
- Windows 10/11（推荐）
- 可选：WSL2 + Redis（高性能缓存）

### 安装依赖
```bash
pip install -r requirements.txt
```

### 启动方式

**方式一：SQLite 轻量模式（推荐）**
```
双击运行：start_cve_gui.bat
```

**方式二：混合模式（SQLite + WSL Redis）**
```
双击运行：start_cve_with_wsl_redis.bat
```

**方式三：命令行**
```bash
python cve_integrated_gui.py
```

### API Key 配置

复制 `.env.example` 为 `.env`，填入实际密钥：
```
NVD_API_KEY=your_nvd_api_key
DASHSCOPE_API_KEY=your_qwen_api_key
CLAUDE_API_KEY=your_claude_api_key
EXA_API_KEY=your_exa_api_key
```

---

## 技术架构

```
智能知识管理平台
├── 数据层
│   ├── SQLite（主存储，WAL 模式，496MB）
│   └── Redis（可选缓存，WSL 部署）
├── 采集层
│   ├── NVD REST API（CVE 数据）
│   ├── Exa API + HTTP + Selenium（Dell 公告 / 网页）
│   └── RSS / 本地文件
├── AI 层
│   ├── Claude API（Anthropic）
│   ├── Qwen API（阿里云百炼）
│   └── Ollama（本地模型，可选）
└── 界面层
    └── tkinter GUI（9 主标签 + 3 子标签）
```

---

## 项目结构

```
├── cve_integrated_gui.py      # 主程序（~14,000 行，GUI 入口）
├── i18n.py                    # 国际化文本（zh_CN / en_US 双语词典）
├── collect_cves.py            # NVD CVE 数据采集器
├── dell_security_scraper.py   # Dell 安全公告爬虫（支持 i18n 日志回调）
├── knowledge_graph.py         # 知识图谱模块（NetworkX 内存图）
├── redis_manager.py           # Redis 缓存管理
├── llm_config.py              # LLM API 配置
├── ai_client.py               # 统一 OpenAI 客户端初始化
├── config.py                  # 集中配置（颜色/字体/AI/DB/UI）
├── db_layer.py                # 学习模块 DAO 层
├── db_backup.py               # SQLite 数据库备份/恢复
├── error_utils.py             # 统一错误处理装饰器
├── learn_enhancements.py      # 学习增强功能模块
├── qwen_assistant.py          # Qwen AI 助手（CLI）
├── ollama_llm_service.py      # Ollama 本地模型 + 向量搜索
├── dao/                       # 数据访问层
│   ├── cve_dao.py             # CVE 数据访问
│   ├── dell_dao.py            # Dell 公告数据访问
│   └── dell_kb_dao.py         # Dell 技术库数据访问
├── tests/                     # pytest 单元测试
│   └── test_knowledge_graph.py  # 知识图谱模块测试（23 条用例）
├── scripts/                   # 维护脚本
├── requirements.txt           # Python 依赖
├── start_cve_gui.bat          # 启动脚本（SQLite 轻量模式）
├── start_cve_with_wsl_redis.bat # 启动脚本（WSL Redis 混合模式）
├── .env.example               # 环境变量模板
├── CLAUDE.md                  # Claude 开发配置
├── CONFIG.md                  # 系统配置指南
└── docs/                      # 技术文档
```

---

## GUI 标签页

| 标签页 | 功能 |
|--------|------|
| 📰 IT新闻简报 | 科技新闻采集与 AI 简报生成 |
| 📊 NVD CVE 数据 | CVE 漏洞数据采集、搜索、删除 |
| 🏢 Dell 安全公告 | Dell 安全公告抓取与管理 |
| 🔗 CVE-DSA 关联 | 漏洞与公告自动关联匹配，支持多行联合分析 |
| 💡 AI 解决方案 | AI 分析历史记录与导出（双语 HTML/MD/CSV/TXT） |
| 📖 Dell技术库 | Dell 技术文档抓取、导入导出 |
| 📈 统计分析 | 数据可视化（饼图/趋势图/汇聚图） |
| 🔮 智能预测 | 知识图谱 + 产品线 / 版本 / 微码三层 DSA 风险预测，含 CISA KEV 加权 |
| 🧠 智能学习 | 费曼学习法 AI 对话、学习产物生成 |
| 📝 操作日志 | 系统运行日志 |
| ┗ 📰 每日简报 | 新闻简报浏览与 TTS 播报（IT新闻子标签） |
| ┗ 🎙️ 播客脚本 | AI 生成播客脚本（IT新闻子标签） |
| ┗ 📅 历史资讯 | 历史新闻归档浏览（IT新闻子标签） |

---

## 智能预测使用指南

「🔮 智能预测」标签页整合了知识图谱可视化与 Dell DSA 三层风险预测，是项目的核心能力之一。

### 三层预测架构

```
产品线级 (29 条)        — Poisson 速率模型，输出 30/60/90 天 P(≥1 DSA)
   ↓ 数据稀疏回退
版本级 (Phase 2 三件套)  — VMR 验证 / Bayesian 先验 / Bootstrap CI
   ↓ 命中具体微码
微码级 (exposure_score)  — 产品线 × 机型 × 类型 × 版本 四元组评分（0~100）
```

每层独立可解释，下一层数据不足时自动回退到上一层。

### 工具栏 4 个按钮

| 按钮 | 功能 | 典型耗时 |
|------|------|----------|
| ▶ 全量分析 | 构建知识图谱 + 风险评分 | 10-30s（首次） |
| 🎯 产品线DSA预测 | 29 条产品线 30/60/90 天 Poisson 概率 | 5-10s |
| 🔬 微码风险 | Top 50 微码版本评分 + KEV 加权 | 5-10s（首次构建索引）|
| 导出报告 | Markdown/JSON 三层结果 | 即时 |

> 周期单选 30/60/90 天仅影响产品线级 DSA 预测；微码评分基于历史固定窗口。

### 微码风险评分公式

```
exposure_score (0~100)
  = freq_score (50%)      = (展开命中数 / 全局最大命中数) × 50
  + severity_score (25%)  = (CVSS/10 × 20) + min(15, KEV命中数 × 5)
  + recency_score (25%)   = (1 − 月数距最近一次出现 / 24) × 25
```

**KEV 加成**：CISA Known Exploited Vulnerabilities Catalog 中已被野外利用的 CVE，每个 +5 分，上限 +15。
KEV 数据 7 天本地缓存（`cve_data/kev_catalog.json`），离线也能用旧缓存。

**风险带**：EXTREME ≥ 75 / HIGH ≥ 55 / MEDIUM ≥ 35 / LOW ≥ 15 / MINIMAL < 15

### 微码 Tab 5 大功能

#### 1. 反向查询
回答运维核心问题"我家这个版本受哪些 DSA 影响？"

```
机型: R640    类型: BIOS    版本: 2.10.0    [查询]
```

支持单一字段或组合：
- 仅机型 `R640` → 该机型所有相关 DSA
- 机型 + 类型 `R640 + BIOS` → R640 BIOS 所有 DSA
- 三者全填 → 含 < / <= / >= / 直接命中各路径，结合范围语义自动展开
- 显示命中数 + KEV 引用数 + 最近 5 条 DSA 标题

#### 2. 显示模式过滤
| 选项 | 含义 |
|------|------|
| 全部 | 默认，所有微码 key |
| 仅有版本 | 排除 `unversioned` 大类，专注具体版本风险 |
| 仅大类 | 仅看 `unversioned`（如 "Client BIOS / BIOS / unversioned"），用于产品线级整体趋势 |

#### 3. 产品线联动
微码 Tab 内置产品线下拉框；当用户在 DSA 预测表格选中某产品线（如 PowerEdge）时，下拉框自动同步过滤微码 Tab，**实现"产品线 → 微码"两层钻取**。

#### 4. 范围语义解析
DSA 描述中的版本范围全部自动展开：
- `"prior to 2.11.0"` → `<` 锚点
- `"2.10.0 and earlier"` → `<=` 锚点
- `"3.0.8 to 3.0.11"` → 闭区间，拆为 `>=3.0.8` + `<=3.0.11`
- `"7.2 and later"` / `"X onwards"` → `>=` 锚点

#### 5. 双源 CVSS
DSA 自身无 CVSS 字段，分两步取值：
1. 优先：DSA 引用的 CVE-IDs 反查 `cves.cvss_score`，取最大值（NVD 命中率 ~43%）
2. 兜底：DSA `severity` 文本映射（CRITICAL=9.5 / HIGH=7.5 / MEDIUM=5.0 / LOW=3.0）

最终 CVSS 覆盖率 100%，平均分 7.70。

### 知识图谱（已合并到智能预测）

知识图谱可视化能力保留在「智能预测」Tab 的左侧统计区与图谱画布：

- 节点：CVE 蓝 / DSA 橙 / Product 绿 / CWE 紫
- 边：`mentions`（DSA→CVE）/ `affects`（DSA→Product）/ `classified_as`（CVE→CWE）
- 选中产品后右栏自动渲染 ego 子图（半径 1）

#### 脚本调用

```python
from knowledge_graph import KnowledgeGraph

kg = KnowledgeGraph.from_sqlite("cve_data/cve_database.db")
kg.build(limit_cve=5000, severity_whitelist={"CRITICAL", "HIGH"})

print(kg.stats())
kg.products_of_cve("CVE-2024-1234")
kg.cves_of_product("Dell VxRail")
kg.dsas_of_cve("CVE-2018-3640")
kg.top_products(k=10)

sub = kg.ego_subgraph("CVE-2018-3640", radius=1)
kg.export_graphml("kg.graphml")
kg.export_json("kg.json")
```

#### 微码评估脚本调用

```python
from risk.dsa_prediction_microcode import MicrocodeRiskAssessor

ass = MicrocodeRiskAssessor("cve_data/cve_database.db")

# 全量 Top N（含 KEV 加权）
top = ass.assess_all(top=50)
for s in top[:5]:
    print(s.exposure_score, s.risk_band, s.key.display(), f"KEV={s.kev_hit_count}")

# 按产品线/微码类型过滤
pe_bios = ass.assess_all(
    product_line_filter="PowerEdge (服务器)",
    firmware_type_filter="BIOS",
    top=10,
)

# 反向查询
hits = ass.query_by_microcode(model="R640", firmware_type="BIOS", version="2.10.0")
for h in hits:
    print(h["published"].date(), h["title"], "KEV:", len(h["kev_cves"]))

# 覆盖率统计
print(ass.coverage_summary())
```

#### 产品线 / 版本级预测脚本

```python
from risk.dsa_prediction import DSAProductLinePredictor
from risk.dsa_prediction_version import DSAVersionPredictor

# 产品线级（29 条）
predictor = DSAProductLinePredictor("cve_data/cve_database.db")
results = predictor.forecast_all(forecast_days=90)
for r in results[:5]:
    print(r.product_line, f"P={r.probability:.1%}", r.risk_level)

# 版本级（含 Phase 2 三件套）
v_pred = DSAVersionPredictor("cve_data/cve_database.db")
versions = v_pred.forecast_all_versions(forecast_days=90)
for v in versions[:5]:
    print(v.version_display, f"P={v.probability:.1%}",
          f"VMR={v.vmr_value}", f"CI={v.ci_method}")
```

### 节点与边的语义

| 节点 | 颜色 | 来源 |
|------|------|------|
| `cve` | 🔵 蓝 | `cves.data.cve_id` |
| `dsa` | 🟠 橙 | `dell_advisories.dsa_id` |
| `product` | 🟢 绿 | `dell_advisories.data.affected_products[*].name`，回退到标题正则 |
| `cwe` | 🟣 紫 | `cves.data.weaknesses[*]` |

| 边 | 方向 | 含义 |
|----|------|------|
| `mentions` | DSA → CVE | DSA 公告引用该 CVE |
| `affects` | DSA → Product | DSA 公告影响该产品 |
| `classified_as` | CVE → CWE | 该 CVE 被归类为某种 CWE 漏洞类型 |

### 验证脚本

```bash
# Phase 2 三件套回归 + 微码 smoke test
python risk/smoke_phase2_microcode.py

# 完整可行性验证（CVSS 覆盖、Top N 排序、3 层对照）
python risk/feasibility_report.py
```

### 运行测试

```bash
pytest tests/test_knowledge_graph.py -v
```

共 23 个用例，覆盖 CVE ID 解析 / 产品名归一 / 构图 / 查询 / 子图抽取 / GraphML-JSON 导出 / 可视化烟雾测试。

---

## 版本历史

| 版本 | 日期 | 主要变更 |
|------|------|----------|
| v5.6.0 | 2026-05-12 | 新增🕸 知识图谱标签页（NetworkX 内存图，CVE × DSA × 产品 × CWE 四类节点 / 三类关系），支持邻域子图可视化、GraphML/JSON 导出，23 条单元测试 |
| v5.5.0 | 2026-05-10 | 全面双语化（GUI/日志/AI 报告/导出），AI 联合分析富排版（图标/星级/粗体），修复进度条初始化 Bug |
| v5.4.0 | 2026-04-26 | 智能学习增强（自动摘要/来源引用/学习产物），项目架构优化 |
| v5.3.0 | 2026-04-10 | 数据导入导出面板，8 数据源 3 格式导出，Dell 技术库导入 |
| v5.2.0 | 2026-04-08 | 统计分析可视化增强，智能学习关键字搜索，关联详情修复 |
| v5.1.0 | 2026-03-30 | 新增 Dell 技术库标签页，解决方案 HTML 导出 |
| v5.0.0 | 2026-03-14 | 重命名为"智能知识管理平台"，项目清理，架构优化 |
| v4.4.0 | 2025-11-05 | SQLite 主存储 + 双写一致性架构 |

详见 [CHANGELOG.md](CHANGELOG.md)

---

## License

MIT License
