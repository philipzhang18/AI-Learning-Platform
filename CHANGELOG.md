# Changelog

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
- 统计分析标签页：新增图表缩放控制（右下角浮动按钮，70%-160%）
- 统计分析标签页：卡片默认增大 10%，缩放时同步调整
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
