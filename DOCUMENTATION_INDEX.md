# 智能知识管理平台 - 文档中心

**版本**: v5.1
**最后更新**: 2026-04-01

---

## 文档导航

### 快速开始

| 文档 | 说明 | 适用人群 |
|------|------|----------|
| [README.md](README.md) | 项目完整介绍和使用说明 | 所有用户 |
| [CONFIG.md](CONFIG.md) | 详细配置指南（环境变量、性能调优） | 需要自定义配置的用户 |
| [CLAUDE.md](CLAUDE.md) | Claude 开发环境配置 | 开发者 |

### 架构文档

| 文档 | 说明 |
|------|------|
| [README_WSL_ARCHITECTURE.md](README_WSL_ARCHITECTURE.md) | WSL 架构详细文档（SQLite + Redis） |
| [CHANGELOG.md](CHANGELOG.md) | 版本变更记录（v4.2 - v5.1） |

### 技术报告（docs/ 目录）

| 报告 | 主题 | 版本 |
|------|------|------|
| [docs/system_optimization_v3.6_report.md](docs/system_optimization_v3.6_report.md) | Redis 主存储 + SQLite 异步备份优化 | v3.6 |
| [docs/data_collection_optimization_report.md](docs/data_collection_optimization_report.md) | 数据采集性能优化（4-8x） | v3.6 |
| [docs/gui_performance_optimization_report.md](docs/gui_performance_optimization_report.md) | GUI 性能优化（16-46x） | v3.6 |
| [docs/system_upgrade_v3.3_report.md](docs/system_upgrade_v3.3_report.md) | Redis 数据库集成升级 | v3.3 |
| [docs/REDIS_GUIDE.md](docs/REDIS_GUIDE.md) | Redis 集成完整指南 | v3.3 |
| [docs/REDIS_MIGRATION_REPORT.md](docs/REDIS_MIGRATION_REPORT.md) | SQLite → Redis 数据迁移报告 | v3.3 |

---

## 按需求查找

| 需求 | 文档 |
|------|------|
| 快速开始使用系统 | [README.md](README.md) |
| 配置 API Key（NVD/Claude/Qwen/Exa） | [CONFIG.md](CONFIG.md) |
| 配置 Redis（WSL） | [README_WSL_ARCHITECTURE.md](README_WSL_ARCHITECTURE.md) |
| 了解项目架构 | [README_WSL_ARCHITECTURE.md](README_WSL_ARCHITECTURE.md) |
| 查看版本变更 | [CHANGELOG.md](CHANGELOG.md) |
| 配置开发环境 | [CLAUDE.md](CLAUDE.md) |

---

## 版本历史

| 版本 | 日期 | 主要变更 |
|------|------|----------|
| v5.1.0 | 2026-03-30 | Dell 技术库标签页，解决方案 HTML 导出 |
| v5.0.0 | 2026-03-14 | 重命名为"智能知识管理平台"，项目清理 |
| v4.4.0 | 2025-11-05 | SQLite 主存储 + 双写一致性架构 |
| v4.3.0 | 2025-11-04 | 智能学习 Web URL 来源 |
| v4.2.0 | 2025-11-03 | Docker 移除，路径迁移至 E 盘 |

---

**维护者**: Claude AI + Philip Zhang
**GitHub**: https://github.com/philipzhang18/AI-Learning-Platform
