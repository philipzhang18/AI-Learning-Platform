# Changelog

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
