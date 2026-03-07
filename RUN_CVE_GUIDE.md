# CVE 漏洞监控系统 - 运行指南

**架构**: SQLite（主存储）+ WSL Redis（可选缓存）
**GUI 版本**: v3.7

---

## 快速启动

### 方法 1: 双击启动（推荐）

双击运行 `start_cve_with_wsl_redis.bat`，自动：
- 启动 WSL Redis
- 验证连接
- 启动 GUI

### 方法 2: 手动启动

```bash
# 1. 启动 WSL Redis（可选）
wsl sudo service redis-server start

# 2. 激活虚拟环境
source /E/AI/cursor/starone/.venv/Scripts/activate

# 3. 进入项目目录
cd /E/AI/Claude/CVE

# 4. 启动 GUI
python cve_integrated_gui.py
```

### 方法 3: Windows PowerShell

```powershell
cd E:\AI\Claude\CVE
E:\AI\cursor\starone\.venv\Scripts\python.exe cve_integrated_gui.py
```

---

## 系统架构

```
┌─────────────────────────────────────┐
│   GUI (Tkinter)                      │  ← 用户界面
│   cve_integrated_gui.py             │
└─────────────────────────────────────┘
            ↓ ↑
┌─────────────────────────────────────┐
│   数据存储层                         │
│   - SQLite: cve_data/cve_database.db │  ← 主存储
│   - Redis: localhost:6379 (WSL)      │  ← 可选缓存
└─────────────────────────────────────┘
```

---

## 功能说明

### NVD CVE 数据标签页

- 查看/采集 NVD CVE 漏洞数据
- 搜索和过滤（支持全库搜索）
- 删除选中记录（支持多选）
- 双击查看详情

**数据来源**: NVD API → SQLite

### Dell 安全公告标签页

- 查看/采集 Dell 安全公告
- 单条 URL 抓取入库（Exa API + 直接请求）
- 加载 CSV 数据
- 搜索和过滤（支持全库搜索）
- 删除选中记录（支持多选）

**数据来源**: Dell Security Advisory → SQLite

---

## 数据管理

### 查看数据统计

```bash
source /E/AI/cursor/starone/.venv/Scripts/activate
cd /E/AI/Claude/CVE
python -c "
import sqlite3
conn = sqlite3.connect('cve_data/cve_database.db')
cursor = conn.cursor()
cursor.execute('SELECT COUNT(*) FROM cves')
print(f'CVE 总数: {cursor.fetchone()[0]}')
cursor.execute('SELECT COUNT(*) FROM dell_advisories')
print(f'Dell 公告总数: {cursor.fetchone()[0]}')
conn.close()
"
```

### 数据备份

```bash
# SQLite 备份
cp cve_data/cve_database.db backups/backup_$(date +%Y%m%d).db
```

---

## 故障排查

### 问题 1: GUI 无法启动

```bash
# 检查虚拟环境
source /E/AI/cursor/starone/.venv/Scripts/activate
python --version

# 直接运行 GUI
cd /E/AI/Claude/CVE
python cve_integrated_gui.py
```

### 问题 2: Redis 连接失败

Redis 为可选组件，程序会自动降级到 SQLite 模式，功能完全正常。

如需启用 Redis（WSL）：

```bash
wsl sudo service redis-server start
wsl redis-cli PING   # 应返回 PONG
```

### 问题 3: 数据加载慢

- 使用搜索框缩小数据范围（支持数据库全量搜索）
- 启用 WSL Redis 可加速热点数据查询

---

## 环境变量配置（.env）

```bash
# NVD API Key（推荐，提升采集速度 10 倍）
NVD_API_KEY=your_nvd_api_key

# Exa API Key（用于 Dell 公告 URL 抓取）
EXA_API_KEY=your_exa_api_key

# Redis（WSL 本地）
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# SQLite 路径
SQLITE_DB_PATH=cve_data/cve_database.db
```

---

**启动脚本**: `start_cve_with_wsl_redis.bat`
**数据库文件**: `cve_data/cve_database.db`
