# Redis + MongoDB 架构实施指南

**版本**: v1.0
**日期**: 2025-11-04
**预计实施时间**: 4-6小时
**难度**: 中等

---

## 📋 目录

1. [前置准备](#前置准备)
2. [阶段1: 基础设施部署](#阶段1-基础设施部署)
3. [阶段2: 依赖安装](#阶段2-依赖安装)
4. [阶段3: 数据迁移](#阶段3-数据迁移)
5. [阶段4: 测试验证](#阶段4-测试验证)
6. [阶段5: GUI集成](#阶段5-gui集成)
7. [故障排查](#故障排查)
8. [性能优化](#性能优化)

---

## 前置准备

### 1. 系统要求

**最低配置**:
- CPU: 4核
- 内存: 8GB
- 硬盘: 20GB可用空间
- 操作系统: Windows 10/11, Linux, macOS

**推荐配置**:
- CPU: 8核+
- 内存: 16GB+
- 硬盘: 50GB+ SSD
- 操作系统: Windows 11, Ubuntu 22.04

### 2. 软件要求

**必需**:
- ✅ Docker Desktop 4.25+ (已安装)
- ✅ Python 3.8+ (已安装: 3.12.10)
- ✅ Git Bash / WSL (已安装)

**可选**:
- MongoDB Compass (MongoDB GUI工具)
- Redis Insight (Redis GUI工具)

### 3. 备份现有数据

**重要**: 在开始迁移前，务必备份SQLite数据库！

```bash
# 进入项目目录
cd /D/AI/Claude/CVE

# 创建备份目录
mkdir -p backups

# 备份SQLite数据库
cp cve_data/cve_database.db backups/cve_database_backup_$(date +%Y%m%d_%H%M%S).db

# 验证备份
ls -lh backups/
```

### 4. 检查磁盘空间

```bash
# Windows
dir cve_data

# Linux/Mac
du -sh cve_data/*
df -h .

# 确保至少有10GB可用空间
```

---

## 阶段1: 基础设施部署

### 步骤1.1: 启动MongoDB和Redis服务

```bash
# 进入项目目录
cd /D/AI/Claude/CVE

# 使用docker-compose启动服务
docker-compose -f docker-compose-mongodb.yml up -d

# 查看启动日志
docker-compose -f docker-compose-mongodb.yml logs -f

# 等待服务完全启动（约30-60秒）
# 看到以下日志表示成功:
#   ✓ MongoDB初始化完成!
#   ✓ Redis连接成功
```

**预期输出**:
```
✓ Container cve-mongodb        Started
✓ Container cve-redis           Started
✓ Container cve-mongo-express   Started
✓ Container cve-redis-commander Started
```

### 步骤1.2: 验证服务状态

```bash
# 检查容器状态
docker ps

# 应该看到4个容器在运行:
# - cve-mongodb
# - cve-redis
# - cve-mongo-express
# - cve-redis-commander
```

### 步骤1.3: 测试连接

**测试MongoDB**:
```bash
# 方法1: 使用docker exec
docker exec -it cve-mongodb mongosh -u admin -p secure_password --authenticationDatabase admin

# 在mongosh中执行:
> use cve_database
> show collections
> db.cve_collection.countDocuments()
> exit

# 方法2: 访问Web管理界面
# 浏览器打开: http://localhost:8081
# 用户名: admin
# 密码: admin (或在.env中配置的MONGO_EXPRESS_PASSWORD)
```

**测试Redis**:
```bash
# 方法1: 使用docker exec
docker exec -it cve-redis redis-cli -a defaultpassword

# 在redis-cli中执行:
127.0.0.1:6379> PING
PONG
127.0.0.1:6379> INFO stats
127.0.0.1:6379> exit

# 方法2: 访问Web管理界面
# 浏览器打开: http://localhost:8082
```

---

## 阶段2: 依赖安装

### 步骤2.1: 安装Python依赖包

```bash
# 激活虚拟环境
source /D/AI/cursor/starone/.venv/Scripts/activate

# 安装MongoDB驱动
pip install motor pymongo

# 安装异步Redis驱动
pip install aioredis

# 更新requirements.txt
pip freeze | grep -E "motor|pymongo|aioredis" >> requirements.txt

# 验证安装
python -c "import motor; import pymongo; import aioredis; print('✓ 所有依赖已安装')"
```

**预期输出**:
```
✓ 所有依赖已安装
```

### 步骤2.2: 验证代码文件

```bash
# 检查新创建的文件
ls -lh mongodb_manager.py unified_data_manager.py migrate_to_mongodb.py

# 应该看到:
# -rw-r--r-- 1 user user  24K mongodb_manager.py
# -rw-r--r-- 1 user user  32K unified_data_manager.py
# -rw-r--r-- 1 user user  18K migrate_to_mongodb.py
```

---

## 阶段3: 数据迁移

### 步骤3.1: 检查SQLite数据

```bash
# 查看SQLite数据库大小和记录数
python -c "
import sqlite3
conn = sqlite3.connect('cve_data/cve_database.db')
cursor = conn.cursor()

cursor.execute('SELECT COUNT(*) FROM cves')
cve_count = cursor.fetchone()[0]

cursor.execute('SELECT COUNT(*) FROM dell_advisories')
dell_count = cursor.fetchone()[0]

print(f'SQLite数据统计:')
print(f'  CVE记录: {cve_count}条')
print(f'  Dell记录: {dell_count}条')

conn.close()
"
```

### 步骤3.2: 执行数据迁移

**首次迁移（推荐）**:
```bash
# 完整迁移（不清空MongoDB）
python migrate_to_mongodb.py \
    --sqlite-db cve_data/cve_database.db \
    --mongo-host localhost \
    --mongo-port 27017 \
    --mongo-username admin \
    --mongo-password secure_password \
    --batch-size 1000

# 预计耗时:
#   51,101条CVE: 约2-3分钟
#   431条Dell: 约5-10秒
#   总计: 约3-4分钟
```

**清空重新迁移**:
```bash
# 如果需要重新迁移，使用--clean参数
python migrate_to_mongodb.py --clean \
    --mongo-password secure_password \
    --batch-size 1000
```

**只验证数据**:
```bash
# 验证数据完整性，不执行迁移
python migrate_to_mongodb.py --verify-only \
    --mongo-password secure_password
```

### 步骤3.3: 监控迁移进度

**迁移日志示例**:
```
╔══════════════════════════════════════════════════════════╗
║               数据迁移: SQLite → MongoDB                 ║
╚══════════════════════════════════════════════════════════╝

✓ SQLite连接成功: cve_data/cve_database.db
✓ MongoDB连接成功: localhost:27017

============================================================
开始迁移CVE数据...
============================================================
SQLite中CVE总数: 51101

进度: 1000/51101 (2.0%) - 成功=1000, 失败=0
进度: 2000/51101 (3.9%) - 成功=1000, 失败=0
进度: 3000/51101 (5.9%) - 成功=1000, 失败=0
...
进度: 51101/51101 (100.0%) - 成功=101, 失败=0

============================================================
✓ CVE迁移完成:
  总数: 51101
  成功: 51101
  失败: 0
============================================================

============================================================
开始迁移Dell安全公告数据...
============================================================
SQLite中Dell公告总数: 431

进度: 431/431 (100.0%) - 成功=431, 失败=0

============================================================
✓ Dell迁移完成:
  总数: 431
  成功: 431
  失败: 0
============================================================

============================================================
开始验证数据完整性...
============================================================
CVE数量对比:
  SQLite: 51101
  MongoDB: 51101
Dell公告数量对比:
  SQLite: 431
  MongoDB: 431
随机抽查数据...
CVE抽查: 10/10 通过
Dell抽查: 10/10 通过
============================================================
✓ 数据完整性验证通过!
============================================================

============================================================
✓ 迁移完成!
============================================================
总耗时: 185.32秒
CVE: 51101/51101 (失败=0)
Dell: 431/431 (失败=0)
============================================================
```

---

## 阶段4: 测试验证

### 步骤4.1: 测试MongoDB管理器

```bash
# 测试mongodb_manager.py
python -c "
import asyncio
from mongodb_manager import MongoDBManager

async def test():
    manager = MongoDBManager(
        host='localhost',
        password='secure_password'
    )

    connected = await manager.connect()
    if not connected:
        print('✗ 连接失败')
        return

    # 测试查询
    count = await manager.get_cves_count()
    print(f'✓ MongoDB连接成功')
    print(f'✓ CVE总数: {count}')

    dell_count = await manager.get_dell_count()
    print(f'✓ Dell总数: {dell_count}')

    await manager.close()

asyncio.run(test())
"
```

### 步骤4.2: 测试统一数据管理器

```bash
# 测试unified_data_manager.py
python unified_data_manager.py

# 预期输出:
# ✓ MongoDB连接成功: localhost:27017
# ✓ Redis连接成功: localhost:6379
# ✓ 连接成功
# 存储CVE: 新增
# 查询CVE: CVE-2024-TEST-001
# 分页查询: 10条, 总计51102条
# 统计信息: CVE=51102, Dell=431
# ✓ 测试完成
```

### 步骤4.3: 性能测试

```bash
# 创建性能测试脚本
cat > test_performance.py << 'EOF'
import asyncio
import time
from unified_data_manager import UnifiedDataManager

async def test_performance():
    manager = UnifiedDataManager(
        mongo_password="secure_password",
        redis_password="defaultpassword"
    )

    await manager.connect()

    # 测试1: 分页查询（首次 - 无缓存）
    start = time.time()
    cves, total = await manager.get_cves(page=1, limit=100)
    duration1 = time.time() - start
    print(f"分页查询(无缓存): {duration1:.3f}秒, 返回{len(cves)}条")

    # 测试2: 分页查询（第二次 - 有缓存）
    start = time.time()
    cves, total = await manager.get_cves(page=1, limit=100)
    duration2 = time.time() - start
    print(f"分页查询(有缓存): {duration2:.3f}秒, 返回{len(cves)}条")
    print(f"性能提升: {duration1/duration2:.1f}倍")

    # 测试3: 单条查询
    if cves:
        start = time.time()
        cve = await manager.get_cve(cves[0]['cve_id'])
        duration3 = time.time() - start
        print(f"单条查询: {duration3:.3f}秒")

    # 测试4: 统计查询
    start = time.time()
    stats = await manager.get_statistics()
    duration4 = time.time() - start
    print(f"统计查询: {duration4:.3f}秒")
    print(f"统计结果: CVE={stats['cve_total']}, Dell={stats['dell_total']}")

    await manager.close()

asyncio.run(test_performance())
EOF

python test_performance.py
```

**预期性能**:
```
分页查询(无缓存): 0.050秒, 返回100条
分页查询(有缓存): 0.005秒, 返回100条
性能提升: 10.0倍
单条查询: 0.002秒
统计查询: 0.020秒
统计结果: CVE=51101, Dell=431
```

---

## 阶段5: GUI集成

### 步骤5.1: 更新requirements.txt

```bash
# 确保所有依赖都在requirements.txt中
cat >> requirements.txt << 'EOF'

# MongoDB和Redis支持
motor>=3.3.0
pymongo>=4.5.0
aioredis>=2.0.1
EOF

# 重新安装依赖
pip install -r requirements.txt
```

### 步骤5.2: 创建GUI适配器（未来工作）

**注意**: 当前的`cve_integrated_gui.py`仍使用SQLite。要完全切换到MongoDB，需要修改GUI代码。这是下一步的工作。

**临时方案**: 双模式运行
- SQLite: 用于GUI显示（向后兼容）
- MongoDB: 用于数据存储和高性能查询

**长期方案**: 重写GUI使用统一数据管理器
- 预计工作量: 1-2天
- 需要修改的文件: `cve_integrated_gui.py`

---

## 故障排查

### 问题1: MongoDB连接失败

**症状**:
```
✗ MongoDB连接失败: ServerSelectionTimeoutError
```

**解决方案**:
```bash
# 1. 检查MongoDB容器状态
docker ps | grep mongodb

# 2. 查看MongoDB日志
docker logs cve-mongodb

# 3. 检查端口占用
netstat -an | grep 27017

# 4. 重启MongoDB
docker restart cve-mongodb

# 5. 检查防火墙设置（Windows）
netsh advfirewall firewall show rule name=all | grep 27017
```

### 问题2: Redis连接失败

**症状**:
```
⚠ Redis连接失败: ConnectionError
```

**解决方案**:
```bash
# 1. 检查Redis容器
docker ps | grep redis

# 2. 测试Redis连接
docker exec -it cve-redis redis-cli -a defaultpassword PING

# 3. 检查Redis密码
docker exec -it cve-redis redis-cli -a defaultpassword CONFIG GET requirepass

# 4. 重启Redis
docker restart cve-redis
```

### 问题3: 数据迁移中断

**症状**:
```
批量存储CVE失败: BulkWriteError
```

**解决方案**:
```bash
# 1. 查看详细错误
python migrate_to_mongodb.py --mongo-password secure_password 2>&1 | tee migration.log

# 2. 检查MongoDB磁盘空间
docker exec -it cve-mongodb df -h

# 3. 检查MongoDB内存
docker stats cve-mongodb

# 4. 降低batch_size
python migrate_to_mongodb.py --batch-size 500 --mongo-password secure_password

# 5. 清空重试
python migrate_to_mongodb.py --clean --mongo-password secure_password
```

### 问题4: 数据验证失败

**症状**:
```
⚠ CVE数量不一致! 差异: 50
```

**解决方案**:
```bash
# 1. 检查MongoDB数据
docker exec -it cve-mongodb mongosh -u admin -p secure_password --authenticationDatabase admin << 'EOF'
use cve_database
db.cve_collection.countDocuments()
db.dell_collection.countDocuments()
EOF

# 2. 检查SQLite数据
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

# 3. 重新迁移缺失数据
python migrate_to_mongodb.py --mongo-password secure_password
```

---

## 性能优化

### 优化1: 调整MongoDB内存

**编辑docker-compose-mongodb.yml**:
```yaml
mongodb:
  deploy:
    resources:
      limits:
        memory: 4G  # 增加到4GB
```

```bash
# 重启服务
docker-compose -f docker-compose-mongodb.yml up -d
```

### 优化2: 调整Redis内存

**编辑docker-compose-mongodb.yml**:
```yaml
redis:
  command: >
    redis-server
    --maxmemory 4gb  # 增加到4GB
```

```bash
# 重启Redis
docker-compose -f docker-compose-mongodb.yml restart redis
```

### 优化3: 启用Redis持久化

```bash
# 检查Redis持久化状态
docker exec -it cve-redis redis-cli -a defaultpassword INFO persistence

# 应该看到:
# aof_enabled:1
# rdb_last_save_time:...
```

### 优化4: MongoDB索引优化

```bash
# 连接MongoDB
docker exec -it cve-mongodb mongosh -u admin -p secure_password --authenticationDatabase admin

# 分析查询性能
use cve_database
db.cve_collection.find({"cvss_severity": "HIGH"}).explain("executionStats")

# 检查索引使用情况
db.cve_collection.aggregate([
  {$indexStats: {}}
])

# 添加自定义索引（如果需要）
db.cve_collection.createIndex({"published_date": -1, "cvss_score": -1})
```

---

## 后续步骤

### 1. GUI改造（下一阶段）

**目标**: 让GUI直接使用MongoDB和Redis

**步骤**:
1. 修改`cve_integrated_gui.py`导入`UnifiedDataManager`
2. 替换所有SQLite调用为MongoDB调用
3. 实现真正的分页加载（每页100条）
4. 添加虚拟滚动优化
5. 测试和优化

**预计工作量**: 1-2天

### 2. 性能监控

**安装监控工具**:
```bash
# MongoDB监控
docker run -d \
  --name mongodb-exporter \
  -p 9216:9216 \
  --network cve_network \
  percona/mongodb_exporter:0.40 \
  --mongodb.uri=mongodb://admin:secure_password@mongodb:27017

# Redis监控
docker run -d \
  --name redis-exporter \
  -p 9121:9121 \
  --network cve_network \
  oliver006/redis_exporter \
  --redis.addr=redis://redis:6379 \
  --redis.password=defaultpassword
```

### 3. 数据备份策略

**MongoDB备份**:
```bash
# 创建备份脚本
cat > backup_mongodb.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="./backups/mongodb"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# 备份MongoDB
docker exec cve-mongodb mongodump \
  --username=admin \
  --password=secure_password \
  --authenticationDatabase=admin \
  --db=cve_database \
  --out=/tmp/backup

docker cp cve-mongodb:/tmp/backup $BACKUP_DIR/mongodb_$TIMESTAMP

echo "✓ MongoDB备份完成: $BACKUP_DIR/mongodb_$TIMESTAMP"
EOF

chmod +x backup_mongodb.sh
```

**Redis备份**:
```bash
# Redis自动备份（已配置RDB和AOF）
# 手动触发备份
docker exec cve-redis redis-cli -a defaultpassword BGSAVE
```

---

## 📊 实施检查清单

### 基础设施 ✅
- [ ] Docker服务已启动
- [ ] MongoDB容器运行正常
- [ ] Redis容器运行正常
- [ ] 管理界面可访问（8081/8082）
- [ ] 网络连通性正常

### 依赖安装 ✅
- [ ] motor已安装
- [ ] pymongo已安装
- [ ] aioredis已安装
- [ ] requirements.txt已更新
- [ ] 虚拟环境正确

### 数据迁移 ✅
- [ ] SQLite数据已备份
- [ ] 迁移脚本执行成功
- [ ] CVE数据迁移完成（51,101条）
- [ ] Dell数据迁移完成（431条）
- [ ] 数据完整性验证通过

### 测试验证 ✅
- [ ] MongoDB管理器测试通过
- [ ] 统一数据管理器测试通过
- [ ] 性能测试达标
- [ ] 缓存功能正常
- [ ] 查询功能正常

### 文档完整 ✅
- [ ] 架构设计文档
- [ ] 问题分析报告
- [ ] 实施指南（本文档）
- [ ] API文档
- [ ] 故障排查指南

---

## 🎯 预期结果

### 性能提升

| 指标 | 迁移前(SQLite) | 迁移后(MongoDB+Redis) | 提升倍数 |
|------|---------------|---------------------|---------|
| 分页查询(100条) | 2-5秒 | 0.01-0.05秒 | **150倍** |
| 单条查询 | 0.1-0.5秒 | 0.002-0.005秒 | **100倍** |
| 批量插入(1000条) | 15秒 | 0.5秒 | **30倍** |
| 统计查询 | 5-10秒 | 0.02-0.1秒 | **100倍** |
| 内存占用 | 360 MB | 20-50 MB | **降低93%** |
| 并发支持 | 不支持 | 10000+ QPS | **支持** |

### 功能改进

- ✅ NVD和Dell数据可同时显示
- ✅ 切换标签页不丢失数据
- ✅ 支持真正的分页加载
- ✅ 查询响应速度大幅提升
- ✅ 支持全文搜索
- ✅ 支持高并发访问

---

## 📞 获取帮助

### 文档资源
- **架构设计**: `REDIS_MONGODB_ARCHITECTURE.md`
- **问题分析**: `DATA_DISPLAY_CONFLICT_ANALYSIS.md`
- **API文档**: 代码内的docstring

### 日志查看
```bash
# MongoDB日志
docker logs cve-mongodb -f

# Redis日志
docker logs cve-redis -f

# 迁移日志
cat migration.log
```

### 技术支持
- GitHub Issues: 项目仓库
- 项目文档: `DOCUMENTATION_INDEX.md`

---

**实施指南版本**: v1.0
**最后更新**: 2025-11-04
**状态**: 准备就绪，可以开始实施
**预计完成时间**: 4-6小时
