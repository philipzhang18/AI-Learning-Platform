# Changelog

## [v5.0.0] - 2026-03-14

### Changed
- 项目重命名为"智能知识学习平台"（原 CVE 监控系统）
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
- 所有路径从 D 盘迁移至 E 盘

---

## [Fixed] - 2025-10-30

### Fixed
- API endpoints configurable in web interfaces
- Enhanced file path handling in run.py
