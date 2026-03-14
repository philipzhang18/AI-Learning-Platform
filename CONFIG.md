# 智能知识学习平台 - 配置指南

**版本**: v3.6
**更新日期**: 2025-11-02

---

## 📋 配置概述

本文档提供系统的详细配置说明，包括环境变量、数据库配置、性能调优等。

## 🔧 基础配置

### 1. Python 环境

**推荐版本**: Python 3.12+

```bash
# 查看 Python 版本
python --version

# 创建虚拟环境（推荐）
python -m venv venv

# 激活虚拟环境
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt
```

### 2. Redis 配置

#### 方式一：使用 Docker（推荐）

```yaml
# docker-compose.yml
services:
  redis:
    image: redis:7-alpine
    container_name: cve_redis
    ports:
      - "6379:6379"
    command: redis-server --requirepass defaultpassword
    volumes:
      - redis_data:/data
    restart: unless-stopped

volumes:
  redis_data:
```

**启动命令**:
```bash
docker-compose up -d redis
```

**验证连接**:
```bash
docker-compose exec redis redis-cli -a defaultpassword ping
# 输出: PONG
```

#### 方式二：本地安装 Redis

**Windows**:
```bash
# 使用 WSL2 安装
wsl --install
sudo apt-get update
sudo apt-get install redis-server

# 启动 Redis
sudo service redis-server start
```

**Linux/Mac**:
```bash
# Ubuntu/Debian
sudo apt-get install redis-server

# macOS
brew install redis

# 启动服务
sudo systemctl start redis
```

**配置密码**:
```bash
# 编辑 redis.conf
requirepass your_password_here

# 重启服务
sudo systemctl restart redis
```

### 3. 环境变量配置

创建 `.env` 文件（可选）:

```bash
# NVD API 配置
NVD_API_KEY=your_nvd_api_key_here

# Redis 配置
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=defaultpassword

# 数据目录
DATA_DIR=cve_data
```

**在代码中使用**:
```python
import os
from dotenv import load_dotenv

load_dotenv()  # 加载 .env 文件

nvd_api_key = os.getenv('NVD_API_KEY')
redis_password = os.getenv('REDIS_PASSWORD', 'defaultpassword')
```

---

## ⚙️ 高级配置

### NVD API Key 配置

**获取 API Key**:
1. 访问 https://nvd.nist.gov/developers/request-an-api-key
2. 填写申请表单（免费）
3. 在邮箱中接收 API Key

**配置方法**:

**Windows PowerShell**:
```powershell
$env:NVD_API_KEY="your-api-key-here"
```

**Windows CMD**:
```cmd
set NVD_API_KEY=your-api-key-here
```

**Linux/Mac**:
```bash
export NVD_API_KEY="your-api-key-here"

# 永久配置（添加到 ~/.bashrc 或 ~/.zshrc）
echo 'export NVD_API_KEY="your-api-key-here"' >> ~/.bashrc
source ~/.bashrc
```

**性能对比**:
- 无 API Key: 6秒/请求（限速 5 req/30s）
- 有 API Key: 0.6秒/请求（限速 50 req/30s）
- **提升**: **10 倍**

### Redis 性能优化

#### 内存配置

编辑 `docker-compose.yml`:
```yaml
services:
  redis:
    command: >
      redis-server
      --requirepass defaultpassword
      --maxmemory 2gb
      --maxmemory-policy allkeys-lru
```

**参数说明**:
- `maxmemory 2gb`: 最大内存限制为 2GB
- `maxmemory-policy allkeys-lru`: 内存满时使用 LRU 算法淘汰数据

#### 持久化配置

**RDB 持久化**（默认）:
```yaml
command: >
  redis-server
  --save 900 1
  --save 300 10
  --save 60 10000
```

**AOF 持久化**（更安全但较慢）:
```yaml
command: >
  redis-server
  --appendonly yes
  --appendfsync everysec
```

### 数据库备份策略

#### 自动备份

**SQLite 备份**:
```bash
# 每日备份脚本
#!/bin/bash
DATE=$(date +%Y%m%d)
cp cve_data/cve_database.db cve_data/backups/cve_database_$DATE.db

# 保留最近 30 天的备份
find cve_data/backups/ -name "*.db" -mtime +30 -delete
```

**Redis 备份**:
```bash
# 手动触发 RDB 快照
docker-compose exec redis redis-cli -a defaultpassword BGSAVE

# 复制快照文件
docker cp cve_redis:/data/dump.rdb ./backups/redis_$(date +%Y%m%d).rdb
```

#### 数据恢复

**从 SQLite 恢复到 Redis**:
```bash
python migrate_to_redis.py
```

**从 Redis 快照恢复**:
```bash
# 停止 Redis
docker-compose stop redis

# 替换快照文件
docker cp ./backups/redis_20251101.rdb cve_redis:/data/dump.rdb

# 启动 Redis
docker-compose start redis
```

---

## 🚀 性能调优

### 系统资源配置

**推荐配置**:
| 数据量 | CPU | 内存 | 磁盘 |
|--------|-----|------|------|
| < 10,000 CVE | 2 核 | 2GB | 5GB |
| 10,000 - 50,000 | 4 核 | 4GB | 10GB |
| > 50,000 | 8 核 | 8GB | 20GB |

### 数据采集优化

#### 并发控制

修改 `collect_cves.py`:
```python
# 调整并发数
CONCURRENT_REQUESTS = 5  # 默认 5，可调整到 10-20（需要 API Key）

# 调整超时时间
TIMEOUT = 30  # 秒
```

#### 批量大小

修改 `cve_integrated_gui.py`:
```python
# 时间范围分块大小
chunk_size = timedelta(days=120)  # 默认 120 天，可调整到 30-180 天
```

### GUI 性能优化

#### 显示限制

修改 `cve_integrated_gui.py`:
```python
# 关联数据显示限制
max_display = 1000  # 默认 1000，可调整到 500-2000

# 统计卡片更新频率
update_interval = 100  # 毫秒，默认 100
```

#### 队列大小

```python
# 数据队列大小
self.data_queue = queue.Queue(maxsize=10000)  # 默认无限制
```

---

## 📊 监控和日志

### Redis 监控

**查看内存使用**:
```bash
docker-compose exec redis redis-cli -a defaultpassword INFO memory
```

**查看数据统计**:
```bash
docker-compose exec redis redis-cli -a defaultpassword INFO stats
```

**监控实时命令**:
```bash
docker-compose exec redis redis-cli -a defaultpassword MONITOR
```

### 日志配置

**应用日志**:
- 位置: GUI 应用的"操作日志"标签页
- 级别: INFO（默认）

**Redis 日志**:
```bash
# 查看 Redis 日志
docker-compose logs redis -f

# 配置日志级别
command: redis-server --loglevel warning
```

---

## 🔐 安全配置

### Redis 安全

**1. 修改默认密码**:
```yaml
services:
  redis:
    command: redis-server --requirepass your_strong_password_here
```

**2. 禁用危险命令**:
```yaml
command: >
  redis-server
  --requirepass your_password
  --rename-command FLUSHDB ""
  --rename-command FLUSHALL ""
  --rename-command CONFIG ""
```

**3. 绑定到本地**（仅本机访问）:
```yaml
command: redis-server --bind 127.0.0.1 --requirepass your_password
```

### 网络安全

**防火墙配置**:
```bash
# 仅允许本地访问 Redis
sudo ufw deny 6379
sudo ufw allow from 127.0.0.1 to any port 6379
```

---

## 🛠️ 故障排查配置

### 启用调试模式

修改 `cve_integrated_gui.py`:
```python
# 启用详细日志
DEBUG = True

if DEBUG:
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        filename='cve_monitor_debug.log'
    )
```

### Redis 调试

```bash
# 查看慢查询
docker-compose exec redis redis-cli -a defaultpassword SLOWLOG GET 10

# 查看客户端连接
docker-compose exec redis redis-cli -a defaultpassword CLIENT LIST
```

---

## 📝 配置检查清单

启动前检查以下配置：

- [ ] Python 3.12+ 已安装
- [ ] 虚拟环境已激活（推荐）
- [ ] Redis 服务已启动
- [ ] Redis 密码已配置
- [ ] NVD API Key 已设置（可选但推荐）
- [ ] 数据目录 `cve_data/` 已创建
- [ ] 依赖包已安装 (`pip install -r requirements.txt`)
- [ ] 防火墙规则已配置（生产环境）

---

## 🔗 相关文档

- [README.md](README.md) - 项目概述和快速开始
- [REDIS_GUIDE.md](REDIS_GUIDE.md) - Redis 集成详细指南
- [system_optimization_v3.6_report.md](docs/system_optimization_v3.6_report.md) - v3.6 优化报告

---

**维护者**: Claude AI + Philip Zhang
**最后更新**: 2025-11-02
**配置版本**: v3.6
