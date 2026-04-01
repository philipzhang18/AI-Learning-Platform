# 智能知识管理平台 - WSL 架构文档

## 架构概览

**版本**: v5.1  
**架构**: SQLite（主存储）+ WSL Redis（可选缓存）  
**更新日期**: 2026-04-01

### 核心特性

- **SQLite 数据库**: 主数据存储，WAL 模式优化
- **WSL Redis**: 可选高性能缓存层，无需 Docker
- **混合模式**: Redis 失败自动降级到纯 SQLite 模式
- **AI 集成**: Claude API + Qwen API + Ollama（可选）

---

## 系统架构图

```
┌─────────────────────────────────────────────────────────────┐
│                   智能知识管理平台 GUI                        │
│              (cve_integrated_gui.py - 9 标签页)              │
└────────────────────┬────────────────────────────────────────┘
                     │
        ┌────────────┴────────────┐
        │                         │
   ┌────▼────┐              ┌────▼────┐
   │ SQLite  │              │ WSL     │
   │ 数据库  │◄─────备份────┤ Redis   │
   │(主存储) │              │(缓存层) │
   └─────────┘              └─────────┘
                                 │
                            失败自动降级
                                 │
                                 ▼
                          [纯 SQLite 模式]

AI 层：
┌──────────────────────────────────────────────────┐
│  Claude API  +  Qwen API  +  Ollama（可选）       │
│  └─ 用于智能学习、漏洞分析、新闻解读              │
└──────────────────────────────────────────────────┘
```

---

## 快速开始

### 前提条件

1. **Python 3.8+** 和虚拟环境
2. **Windows 10/11**（推荐）
3. **可选**: WSL2 + Redis（高性能缓存）

### 启动方式

#### Windows 用户

```bat
:: 方式一：SQLite 轻量模式（推荐）
双击运行：启动CVE系统-SQLite.bat

:: 方式二：混合模式（SQLite + WSL Redis）
双击运行：启动CVE系统-混合模式.bat
```

#### 命令行

```bash
# 激活虚拟环境
source /E/AI/cursor/starone/.venv/Scripts/activate

# 启动主程序
python cve_integrated_gui.py
```

---

## 详细配置

### 1. WSL Redis 配置（可选）

#### 安装与启动

```bash
# 在 WSL 中安装
wsl
sudo apt-get update
sudo apt-get install redis-server

# 启动 Redis
sudo service redis-server start

# 验证
redis-cli ping  # 应返回 PONG
```

#### 推荐配置

```bash
# 编辑配置文件
sudo nano /etc/redis/redis.conf

# 推荐配置
bind 0.0.0.0              # 允许外部访问
protected-mode no         # 禁用保护模式（内网环境）
requirepass your_password  # 设置密码（推荐）
maxmemory 2gb             # 最大内存
maxmemory-policy allkeys-lru  # 淘汰策略
```

#### 环境变量

编辑 `.env` 文件：

```env
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0
```

### 2. SQLite 优化（已自动应用）

| 配置项 | 值 | 说明 |
|-------|-----|------|
| journal_mode | WAL | 写前日志，提升并发 |
| cache_size | 10000 | ~40MB 缓存 |
| synchronous | NORMAL | 平衡性能和安全 |
| temp_store | MEMORY | 临时数据在内存 |
| mmap_size | 30GB | 内存映射 I/O |

**数据库文件位置**: `cve_data/cve_database.db`

**数据库表**:
- `cves` — NVD CVE 漏洞数据
- `dell_advisories` — Dell 安全公告
- `dell_kb_articles` — Dell 技术库文章
- `ai_solutions` — AI 生成的解决方案
- `news_briefs` — IT 新闻简报
- `podcast_scripts` — 播客脚本
- `learn_sessions` — 智能学习会话
- `collection_history` — 数据采集历史

---

## 运行模式

### 模式 1: 纯 SQLite（推荐新用户）

- **优点**: 无依赖，开箱即用
- **适用**: 日常使用
- **启动**: `启动CVE系统-SQLite.bat`

### 模式 2: SQLite + WSL Redis

- **优点**: 高性能缓存，自动降级
- **适用**: 大数据量场景
- **启动**: `启动CVE系统-混合模式.bat`

---

## 故障排查

### Redis 连接失败

```bash
# 检查 Redis 状态
wsl redis-cli ping

# 启动 Redis
wsl sudo service redis-server start

# 查看日志
wsl sudo tail -f /var/log/redis/redis-server.log
```

系统会自动降级到纯 SQLite 模式，无需手动干预。

### SQLite 数据库锁定

```bash
# 检查 WAL 文件
ls -lh cve_data/cve_database.db*

# 清理 WAL 文件（谨慎）
sqlite3 cve_data/cve_database.db "PRAGMA wal_checkpoint(TRUNCATE);"
```

---

## 性能基准

### SQLite + Redis 模式

| 操作 | 性能 | 说明 |
|-----|------|------|
| 首次加载 | ~2-3s | 从 SQLite 加载 |
| 缓存命中 | ~50-100ms | 从 Redis 读取 |
| 写入 | ~1000/s | 批量插入 |
| 搜索 | ~10ms | 索引查询 |

---

## 文件结构

```
CVE/
├── cve_integrated_gui.py          # 主程序（GUI 入口，9 标签页）
├── collect_cves.py                # NVD CVE 数据采集器
├── dell_security_scraper.py       # Dell 安全公告爬虫
├── redis_manager.py               # Redis 缓存管理器
├── llm_config.py                  # LLM API 配置
├── qwen_assistant.py              # Qwen AI 助手（CLI）
├── ollama_llm_service.py          # Ollama 本地模型 + 向量搜索（SQLite）
│
├── .env.example                   # 环境配置模板
├── requirements.txt               # Python 依赖
├── README.md                      # 项目介绍
├── CONFIG.md                      # 配置指南
├── CHANGELOG.md                   # 版本记录
│
├── 启动CVE系统-SQLite.bat          # Windows 启动（SQLite）
├── 启动CVE系统-混合模式.bat        # Windows 启动（SQLite + Redis）
│
├── cve_data/                      # 数据目录
│   ├── cve_database.db            # SQLite 数据库
│   └── *.csv                      # CSV 备份
│
└── docs/                          # 技术文档/历史报告
```

---

## 常用命令

### WSL Redis

```bash
# 启动/停止/重启
wsl sudo service redis-server start
wsl sudo service redis-server stop
wsl sudo service redis-server restart

# 查看状态
wsl redis-cli info server

# 清空缓存
wsl redis-cli FLUSHALL
```

### 数据库维护

```bash
# SQLite 优化
sqlite3 cve_data/cve_database.db "VACUUM;"

# 查看数据库大小
du -h cve_data/cve_database.db*
```

---

**最后更新**: 2026-04-01  
**架构版本**: v5.1 - SQLite + WSL Redis  
**维护者**: Claude AI + Philip Zhang
