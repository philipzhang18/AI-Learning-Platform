# Changelog

## [v5.6.1] - 2026-06-14

### Fixed — 国际化与启动体验
- **智能预测标签页全面国际化**：`unified_risk_tab.py` 此前约 60 处硬编码中文（工具栏按钮、
  表格列头、Notebook 子标签、状态/摘要/因子拆解文本、运行时提示）在英文模式下仍显示中文。
  现统一抽取为 `ur_*` i18n key（zh_CN/en_US 各 138 条，占位符两语言完全对等），英文模式下全部正确显示英文
- **微码产品线过滤 key 一致性**：下拉框默认值与渲染过滤逻辑此前一边用 `t("ur_micro_pl_all")`、
  一边硬编码 `"(全部)"`，英文模式下过滤会失效；现统一走 i18n key
- **启动脚本显示运行环境版本**：`start_cve_gui.bat` 不再打印解释器明文绝对路径，改为显示
  Python 运行环境版本（如 `Python 运行环境: 3.14.0`）；修复 `for /f` 嵌套双引号导致取版本失败显示"未知"的问题
- **补齐 tkcalendar 依赖**：IT 新闻简报标签页"日历·资讯存档"模块所需的 `tkcalendar` 此前缺失于
  所有依赖清单，换环境部署会退化为提示文字；现加入 `requirements.txt`
- **产品系列下拉框规范化**：智能模型预测标签页的产品系列列表此前混入微码版本号
  （如 `Dell PowerMaxOS 5978.714.714`、`Dell EMC VPLEX 6.2.0`、`Dell VxRail 8.0.300`），
  版本号被当作系列名。新增 `risk/product_taxonomy.normalize_series_name()` 纯函数剥离尾部点分版本串
  （保留 `PowerStore 1000T` / `Unity 600F` 这类无点型号位），知识图谱与数据库两条加载路径统一规范化 + 去重
  （Top-100 → 93 条，版本号清零），系列名剥离后仍能正常匹配历史 DSA 并产出预测（已端到端验证）

## [v5.6.0] - 2026-06-13

### Fixed — 交付就绪度修复（可交付他人使用）
- **启动脚本可移植化 + 统一入口**：合并 `start_cve_gui.bat` 与 `start_cve_with_wsl_redis.bat` 为单一入口
  `start_cve_gui.bat`，去除硬编码绝对路径（改用 `%~dp0` 脚本目录 + 解释器自动探测：本地 `.venv` →
  `KMP_PYTHON` → 系统 PATH），并自动探测 WSL Redis：可用则启用缓存模式，否则优雅降级为 SQLite 轻量模式。
  统一为 UTF-8(无BOM)+CRLF+`chcp 65001`，解决 cmd.exe 因 LF 行尾解析错位崩溃的问题
- **产品型号预测查询 bug**：修复 `_mp_query_matched_dsa` 三处缺陷——列名 `advisory_id`→`dsa_id`、
  CVSS 从 `cves.data` JSON 提取（非独立列）、匹配字段以 title 为主（`affected_products.name` 常为 "Multiple"）
- **文件不存在友好提示**：新增 `_validate_file_path` 统一校验，5 个文件读取点（Markdown/学习文件/NVD/Dell/CSV）
  在读取前预检查，文件不存在时给出清晰提示而非原始 `[Errno 2]` OS 错误
- **pytest 整体可运行**：修复测试模块在 import 时替换 `sys.stdout/stderr` 导致 `pytest tests/` 整体崩溃
  （`I/O operation on closed file`）的问题，pytest 环境下跳过编码重配置
- **系列预测器误匹配 bug**：修复 `_query_series_history` 中运算符优先级错误，
  导致不存在的产品也匹配到大量历史 DSA（现正确返回 0）
- **knowledge_graph 抖动测试**：性能计时断言改为带阈值容差 + 正确性校验，消除小数据集下 `0.0 < 0.0` 误报
- **裸 except 清零**：生产代码所有裸 `except:` 收窄为具体异常类型
- **静默吞错可诊断**：新增模块级 `logging`（`KMP_LOG_LEVEL` 可调），DB 写入/缓存写入失败改为记录日志

### Added — 工程化交付能力
- **可 pip 安装**：`pyproject.toml` 新增 `[build-system]` / `[project]` 段，
  支持 `pip install -e ".[data,dev]"`，并生成 `kmp-gui` 控制台入口
- **依赖锁定**：`requirements.txt` 全部加上下界版本约束，新增 `requirements.lock` 精确快照；补齐 `cryptography`
- **CI 全量测试**：GitHub Actions 由手挑 6 文件改为全量 `pytest tests/`，覆盖 risk/ 与集成测试

## [v5.5.0] - 2026-05-31

### Added — DSA 智能预测与风险分析
- Dell 产品线 DSA 序列预测（Poisson 模型 + 生命周期调整 + EOSS 数据）
- 统一风险分析标签页（unified_risk_tab）：版本级/系列级/微码级预测
- 知识图谱风险传播（CVE × DSA × 产品 × CWE 关联分析）
- 预测回测框架 + Grid Search 权重校准（Brier 0.096→0.068）

## [v5.4.0] - 2026-04-26

### Added — 智能学习功能增强（NotebookLM 风格）
- **Phase 1 资料自动摘要**：加载学习内容后，AI 自动生成核心摘要、3-5 个核心主题、5 个分层学习问题
- **Phase 1 来源引用**：AI 回答带 [📚] 引用标记，要求严格基于资料回答（防幻觉约束）
- **Phase 1 智能摘要 UI**：左侧面板新增"✨ 智能摘要"区域，建议问题可点击直接填入输入框
- **Phase 3 学习产物生成**：左侧面板新增"📦 学习产物"区域，5 个生成按钮：
  - 📅 学习时间线（按阶段展示进度）
  - 🧠 思维导图（Mermaid 格式）
  - 📖 学习指南（结构化路径）
  - ❓ 常见问题 FAQ
  - 🎙 对话播客（双人对话脚本，可直接 TTS 播放）
- **数据库表扩展**：
  - `learn_sessions` 增加 `auto_summary`、`key_topics`、`suggested_questions`
  - 新增 `notebooks`、`notebook_sources` 表（笔记本工作区）
  - 新增 `learn_artifacts` 表（学习产物存储）
  - `flashcards` 增加 `source_refs` 字段

### Added — 项目架构优化
- 新增 [config.py](config.py)：集中管理颜色、字体、AI/DB/UI 配置
- 新增 [ai_client.py](ai_client.py)：统一 OpenAI 客户端初始化
- 新增 [db_layer.py](db_layer.py)：学习模块 DAO 层
- 新增 [error_utils.py](error_utils.py)：统一错误处理装饰器
- 新增 [db_backup.py](db_backup.py)：SQLite 数据库一键备份/恢复
- 新增 [learn_enhancements.py](learn_enhancements.py)：学习增强功能模块

### Added — UI 改进
- 统计分析页面默认缩放从 110% 改为 **100%**
- 所有弹框文本字体统一增大一号

### Changed
- 修正 README 中错误的启动脚本名称（`启动CVE系统-SQLite.bat` → `start_cve_gui.bat`）
- 补齐 `.env.example` 模板（增加 QWEN/CLAUDE/EXA 等 AI Key 配置）
- 系统提示词增加防幻觉约束章节

### Cleanup
- 清理根目录 18 个无关文件（演讲稿、独白、JSON、JS）至 `archive/演讲稿与脚本/`
- 移除临时 dsa_DSA-*.json 和 FIXES_CHECKLIST.txt 等到 `archive/`

---

## [v5.3.0] - 2026-04-10

### Added
- Dell技术库标签页：新增数据导入导出面板（页面下半部分，PanedWindow 可拖拽分割）
  - 数据源选择：支持全部 8 个数据源（IT新闻简报、NVD CVE、Dell安全公告、CVE-Dell关联、AI解决方案、Dell技术库、学习对话记录、闪卡知识库）
  - 导出格式：Markdown / TXT / HTML 三种格式
  - 指定编号导出：输入 CVE ID、DSA ID、文章编号等可单条精准导出
  - 导出选中项：支持从 TreeView 多选记录直接导出
  - 数量限制：全部 / 最近50/100/200/500条
  - 预览功能：导出前可预览格式化内容
  - 导入功能：支持 Dell技术库 Markdown/TXT 格式导入（含多行内容解析）
- 所有数据源导出完整内容（不截断）：
  - NVD CVE：完整多语言描述、V3.1+V2评分、参考链接、受影响配置
  - Dell安全公告：解析 data JSON 导出 description/impact/remediation 等完整字段
  - Dell技术库：新增 content 完整内容字段
  - AI解决方案：新增提示词、状态字段
  - 学习对话：新增来源内容 + 完整对话记录
  - 闪卡知识库：新增选项、复习次数、正确次数
- 导出格式改为分条详情布局（Markdown 用 ## 分节，HTML 用卡片式，TXT 用分隔线），适合长文本展示

---

## [v5.2.0] - 2026-04-08

### Added
- 统计分析标签页：新增 3 张月度增长趋势图（CVE / Dell 公告 / CVE-Dell 关联，最近 13 个月）
- 统计分析标签页：新增数据汇聚匹配关系图（椭圆式，CVE + Dell → 关联匹配）
- 智能学习标签页：新增关键字搜索功能（支持全部 6 种数据源，回车搜索，搜索时上限 500 条）
- 匹配系数显示：CVE 匹配系数 / Dell 公告匹配系数（替代百分比匹配率）

### Fixed
- 修复 CVE-Dell 关联页面双击无法打开详情的问题（从数据库加载数据，兼容 dsa_id/dell_security_advisory 两种键名）
- 修复智能学习搜索 CVE 数据时引用不存在的 description 列导致 0 结果的问题
- 修复 Dell 月度统计和关联月度统计使用错误字段名 date_posted（改为 published_date）的问题

### Changed
- 统计分析布局调整：严重等级饼图 + 汇聚图上移至第二行，月度趋势图下移至第三行
- 统计分析三列布局使用 uniform 约束确保等宽对齐
- 智能学习左侧面板宽度缩窄 1/3（300px → 200px），内部控件同步调整
- 图表尺寸统一缩小（适配全屏显示）

### Removed
- 删除 Dell 安全公告中影响等级为 N/A 的 355 条条目

---

## [v5.1.0] - 2026-03-30

### Added
- 新增「📖 Dell技术库」标签页（位于解决方案和统计分析之间）
  - 单条 Dell kbdoc URL 抓取：Exa API 优先，requests 回退
  - 自动提取文章编号（如 000261124）作为主键
  - 解析正文内容和解决方案段落
  - TreeView 展示：文章编号、标题、解决方案预览、采集时间
  - 搜索功能：内存优先，数据库 LIKE 回退
  - 删除选中：支持 Ctrl/Shift 多选
  - AI 解决方案：调用 Qwen API 分析技术文档，结果存入解决方案标签页
  - 双击查看完整文章详情
- 新增数据库表 `dell_kb_articles`（article_id, title, content, solution, url, collected_date）
- 智能学习数据源新增 "Dell技术库" 选项
- 解决方案导出支持 HTML 格式（美观卡片布局 + 统计面板）
- 解决方案导出支持选中条目导出（全部/选中/取消三选对话框）

### Fixed
- 修复 `log()` 方法在控件未创建时崩溃的问题（添加 `hasattr` 安全检查）
- 修复 Dell 技术库 AI 解决方案/双击详情因 TreeView 前导零丢失导致文章查找失败的问题
- 修复 `dell_kb_ai_solution_click` 中变量名 `article_id` 未定义的 NameError

### Changed
- 解决方案标签页「CVE 编号」列名改为「方案编号」

---

## [v5.0.0] - 2026-03-14

### Changed
- 项目重命名为"智能知识管理平台"（原 CVE 监控系统）
- 统一更新所有文件中的项目名称（GUI、main.py、启动脚本、配置文档）
- 项目定位调整：以知识学习为核心，CVE/Dell 数据作为学习内容之一

### Removed
- 根目录清理：71 个报告 .md 移入 archive/old_reports/
- 根目录清理：41 个测试/诊断/备份 .py 移入 archive/old_tests/
- 根目录从 99+ 个文件精简至 17 个核心文件

### Added
- 新版 README.md（中文，反映新项目定位）
- GitHub upload skill（.claude/skills/github-upload.md）

---

## [v4.4.0] - 2025-11-05

### Changed
- SQLite 作为主存储引擎，双写一致性架构
- Redis 降级为可选缓存层

---

## [v4.3.0] - 2025-11-04

### Added
- 智能学习标签页支持 Web URL 作为内容来源
- 学习对话保存到数据库

### Fixed
- 多项 Bug 修复

---

## [v4.2.0] - 2025-11-03

### Added
- NVD/Dell 标签页删除和搜索功能

### Changed
- Docker 完全移除

---

## [Fixed] - 2025-10-30

### Fixed
- API endpoints configurable in web interfaces
- Enhanced file path handling in run.py
