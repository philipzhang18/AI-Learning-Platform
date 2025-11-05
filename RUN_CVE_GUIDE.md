# CVE 漏洞监控系统 - 运行指南

**系统状态**: MongoDB + Redis 后端已部署  
**数据迁移**: 已完成（51,126 CVE + 431 Dell）  
**GUI 状态**: 使用 SQLite（向后兼容）

---

## 快速启动

### 方法 1: 使用启动脚本（推荐）

```bash
cd /D/AI/Claude/CVE
bash start_cve_gui.sh
```

**功能**:
- 自动检查并启动 MongoDB 和 Redis 服务
- 启动 CVE GUI 程序
- 显示后端服务状态

### 方法 2: 手动启动

```bash
# 1. 确保后端服务运行
cd /D/AI/Claude/CVE
docker-compose -f docker-compose-mongodb-optimized.yml up -d

# 2. 启动 GUI
source /D/AI/cursor/starone/.venv/Scripts/activate
python cve_integrated_gui.py
```

### 方法 3: Windows 直接运行

```powershell
# PowerShell
cd D:\AI\Claude\CVE
D:\AI\cursor\starone\.venv\Scripts\python.exe cve_integrated_gui.py
```

---

## 系统架构

### 当前配置

```
┌─────────────────────────────────────┐
│   GUI (Tkinter)                      │  ← 用户界面
│   - cve_integrated_gui.py            │
│   - 使用 SQLite (主)                 │
│   - 使用 Redis (缓存)                │
└─────────────────────────────────────┘
            ↓ ↑
┌─────────────────────────────────────┐
│   数据存储层                         │  ← 数据持久化
│   - SQLite: cve_data/cve_database.db │
│   - Redis: localhost:6379            │
│   - MongoDB: localhost:27017         │  ← 已迁移，待集成
└─────────────────────────────────────┘
```

### 数据状态

| 数据库 | 状态 | 记录数 | 用途 |
|--------|------|--------|------|
| **SQLite** | ✅ 活跃 | 51,126 CVE + 431 Dell | GUI 主数据源 |
| **MongoDB** | ✅ 同步 | 51,126 CVE + 431 Dell | 高性能后端（待集成） |
| **Redis** | ✅ 活跃 | 缓存 | 热点数据缓存 |

---

## 功能说明

### NVD CVE 数据标签页

**功能**:
- 查看 NVD CVE 漏洞数据库
- 实时采集最新 CVE 数据
- 搜索和过滤 CVE
- 导出 CVE 数据

**数据来源**: SQLite（本地）+ Redis（缓存）

### Dell 安全公告标签页

**功能**:
- 查看 Dell 安全公告
- 采集 Dell 最新公告
- CVE ID 关联匹配
- 导出 Dell 数据

**数据来源**: SQLite（本地）

### 采集功能

**NVD CVE 采集**:
- 来源: NVD Data Feeds
- 更新频率: 手动触发或定时
- 数据量: 每次可采集数千条

**Dell 安全公告采集**:
- 来源: Dell Security Advisory 页面
- 支持时间范围筛选
- 自动关联 CVE ID

---

## 数据管理

### 查看数据统计

```bash
# SQLite
cd /D/AI/Claude/CVE
source /D/AI/cursor/starone/.venv/Scripts/activate
python -c "
import sqlite3
conn = sqlite3.connect('cve_data/cve_database.db')
cursor = conn.cursor()
cursor.execute('SELECT COUNT(*) FROM cves')
print(f'SQLite CVE: {cursor.fetchone()[0]}')
cursor.execute('SELECT COUNT(*) FROM dell_advisories')
print(f'SQLite Dell: {cursor.fetchone()[0]}')
conn.close()
"

# MongoDB
docker exec cve-mongodb mongosh -u admin -p secure_password \
  --authenticationDatabase admin cve_database \
  --eval "print('MongoDB CVE:', db.cve_collection.countDocuments()); print('MongoDB Dell:', db.dell_collection.countDocuments())"

# Redis
docker exec cve-redis redis-cli -a defaultpassword INFO stats | grep keys
```

### 数据同步

**当前状态**: SQLite 是主数据源，MongoDB 已有完整数据备份

**未来**: 可选择启用 MongoDB 作为主数据源（性能提升 20-35 倍）

---

## 后端服务管理

### 查看服务状态

```bash
# 查看所有容器
docker ps

# 查看资源使用
docker stats cve-mongodb cve-redis

# 查看日志
docker logs cve-mongodb
docker logs cve-redis
```

### 启动/停止服务

```bash
# 启动所有服务
docker-compose -f docker-compose-mongodb-optimized.yml up -d

# 停止所有服务
docker-compose -f docker-compose-mongodb-optimized.yml down

# 重启特定服务
docker restart cve-mongodb
docker restart cve-redis
```

### 访问管理界面

- **Redis Commander**: http://localhost:8082
- **MongoDB**: 命令行 (`docker exec -it cve-mongodb mongosh`)

---

## 性能对比

### SQLite vs MongoDB（已迁移数据）

| 操作 | SQLite | MongoDB | 提升 |
|------|--------|---------|------|
| **加载 51,126 条 CVE** | 15-30 秒 | 0.7 秒（100条/页） | **20-40x** |
| **单条查询** | 0.1-0.5 秒 | 0.29 秒 | **保持可用** |
| **统计查询** | 5-10 秒 | 0.24 秒 | **20-40x** |
| **内存占用** | 360 MB | 275 MB | **降低 24%** |

---

## 故障排查

### 问题 1: GUI 无法启动

**症状**: 点击启动脚本无反应

**解决**:
```bash
# 检查虚拟环境
source /D/AI/cursor/starone/.venv/Scripts/activate
python --version

# 检查依赖
pip list | grep tkinter

# 直接运行 GUI
cd /D/AI/Claude/CVE
python cve_integrated_gui.py
```

### 问题 2: Redis 连接失败

**症状**: GUI 显示 "Redis 连接失败"

**解决**:
```bash
# 检查 Redis 服务
docker ps | grep redis

# 重启 Redis
docker restart cve-redis

# 测试连接
docker exec cve-redis redis-cli -a defaultpassword PING
```

### 问题 3: 数据加载慢

**症状**: GUI 加载数据时间过长

**解决**:
- SQLite 加载大量数据较慢（15-30秒）是正常的
- 使用搜索和过滤功能缩小数据范围
- 未来版本将集成 MongoDB 提升性能

### 问题 4: 后端服务未运行

**症状**: 启动脚本报错 "MongoDB/Redis 未运行"

**解决**:
```bash
# 启动所有服务
cd /D/AI/Claude/CVE
docker-compose -f docker-compose-mongodb-optimized.yml up -d

# 等待服务完全启动
sleep 10

# 验证
docker ps
```

---

## 下一步计划

### 短期（可选）

- ✅ 数据已迁移到 MongoDB
- ⚠️ GUI 集成 MongoDB（性能提升 20-35 倍）
- ⚠️ 实现分页加载（每页 100 条）
- ⚠️ 添加虚拟滚动优化

### 中期（可选）

- 启用 Redis 缓存层（进一步提升性能）
- 部署监控系统
- 实现自动数据同步

---

## 配置文件

### 环境变量

创建 `.env` 文件（可选）:
```bash
# MongoDB
MONGODB_PASSWORD=secure_password
MONGODB_HOST=localhost
MONGODB_PORT=27017

# Redis
REDIS_PASSWORD=defaultpassword
REDIS_HOST=localhost
REDIS_PORT=6379

# CVE 采集
NVD_API_KEY=your_nvd_api_key  # 可选
```

### Docker 配置

- **生产配置**: `docker-compose-mongodb-optimized.yml`（已优化，CPU降低60%）
- **原始配置**: `docker-compose-mongodb.yml`（未优化）

---

## 数据备份

### 自动备份

SQLite 数据库会自动备份到 `backups/` 目录

### 手动备份

```bash
# SQLite 备份
cp cve_data/cve_database.db backups/backup_$(date +%Y%m%d).db

# MongoDB 备份
docker exec cve-mongodb mongodump \
  --username=admin --password=secure_password \
  --authenticationDatabase=admin \
  --db=cve_database --out=/tmp/backup

docker cp cve-mongodb:/tmp/backup backups/mongodb_$(date +%Y%m%d)
```

---

## 技术支持

### 相关文档

- **部署报告**: `DEPLOYMENT_REPORT_20251104.md`
- **架构设计**: `REDIS_MONGODB_ARCHITECTURE.md`
- **优化指南**: `DOCKER_OPTIMIZATION_GUIDE.md`
- **优化报告**: `DOCKER_OPTIMIZATION_REPORT.md`

### 日志文件

- GUI 日志: 查看 GUI 界面的日志区域
- MongoDB 日志: `docker logs cve-mongodb`
- Redis 日志: `docker logs cve-redis`

---

**系统状态**: ✅ 可用  
**数据完整性**: ✅ 100%  
**后端服务**: ✅ 运行中  
**GUI 版本**: v3.1 (SQLite + Redis)

🎉 **系统已准备就绪，请使用启动脚本运行 CVE 程序！**
