# Docker Desktop GPU 故障排查指南

## 当前问题分析

### 问题 1: Docker Desktop 内部错误
**症状**: `500 Internal Server Error for API route`

**原因**: Docker Desktop 服务异常或正在重启

### 问题 2: Docker Hub 网络连接失败
**症状**: `failed to fetch oauth token: dial tcp ... connectex: A connection attempt failed`

**原因**: 无法连接到 Docker Hub(可能是网络问题或需要镜像加速器)

## 解决方案

### 步骤 1: 重启 Docker Desktop

**重要**: 必须先解决 Docker Desktop 异常问题

#### Windows 上重启 Docker Desktop

```powershell
# 方法 1: 通过任务栏图标
# 1. 右键点击任务栏的 Docker 图标
# 2. 选择 "Quit Docker Desktop"
# 3. 等待几秒后,重新启动 Docker Desktop

# 方法 2: 通过 PowerShell (管理员权限)
# 停止 Docker Desktop
taskkill /F /IM "Docker Desktop.exe"

# 等待 5 秒
Start-Sleep -Seconds 5

# 启动 Docker Desktop
Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"
```

#### 验证 Docker Desktop 已恢复

等待 Docker Desktop 完全启动(托盘图标变为绿色),然后在 Git Bash 中测试:

```bash
# 测试 Docker 命令
docker --version

# 测试 Docker 连接
docker ps

# 测试 GPU 支持
docker run --rm --gpus all nvidia/cuda:13.0.1-runtime-ubuntu22.04 nvidia-smi
```

如果上述命令正常工作,说明 Docker Desktop 已恢复正常。

### 步骤 2: 配置 Docker 镜像加速器(解决网络问题)

由于 Docker Hub 连接问题,需要配置国内镜像加速器。

#### 配置方法

1. **打开 Docker Desktop 设置**
   - 右键点击任务栏的 Docker 图标
   - 选择 "Settings" 或"设置"

2. **进入 Docker Engine 配置**
   - 左侧菜单选择 "Docker Engine"

3. **添加镜像加速器配置**

在配置 JSON 中添加以下内容:

```json
{
  "builder": {
    "gc": {
      "defaultKeepStorage": "20GB",
      "enabled": true
    }
  },
  "experimental": false,
  "registry-mirrors": [
    "https://docker.m.daocloud.io",
    "https://dockerhub.azk8s.cn",
    "https://docker.mirrors.sjtug.sjtu.edu.cn",
    "https://mirror.ccs.tencentyun.com"
  ]
}
```

**注意**: 如果已有其他配置,只需添加 `"registry-mirrors"` 部分,不要删除现有配置。

4. **保存并重启 Docker Desktop**
   - 点击 "Apply & restart" 按钮
   - 等待 Docker Desktop 重启完成

#### 验证镜像加速器生效

```bash
# 查看 Docker 配置信息
docker info | grep -A 5 "Registry Mirrors"

# 应该能看到配置的镜像加速器地址
```

### 步骤 3: 重新启动 GPU 服务栈

配置完成后,重新启动服务:

```bash
# 进入项目目录
cd /D/AI/Claude/CVE

# 清理之前失败的容器(如果有)
docker-compose -f docker-compose-gpu.yml down

# 重新启动服务
docker-compose -f docker-compose-gpu.yml up -d

# 查看启动日志
docker-compose -f docker-compose-gpu.yml logs -f
```

### 步骤 4: 监控服务启动

在另一个终端窗口中监控:

```bash
# 实时查看容器状态
watch -n 2 'docker ps'

# 或者每 5 秒检查一次
docker-compose -f docker-compose-gpu.yml ps
```

等待所有服务显示为 `Up` 或 `healthy` 状态。

### 步骤 5: 验证服务健康

服务启动后,逐个验证:

```bash
# 1. Redis
docker exec cve-redis redis-cli -a defaultpassword PING
# 期望输出: PONG

# 2. MongoDB
docker exec cve-mongodb mongosh --eval "db.adminCommand('ping')"
# 期望输出: { ok: 1 }

# 3. PostgreSQL
docker exec cve-postgres-vector psql -U admin -d cve_vectors -c "SELECT version();"
# 期望输出: PostgreSQL 版本信息

# 4. Ollama (GPU)
docker exec cve-ollama nvidia-smi
# 期望输出: NVIDIA GPU 信息

# 5. Ollama API
curl http://localhost:11434/api/tags
# 期望输出: {"models":[...]}
```

### 步骤 6: 下载 LLM 模型

所有服务健康后,下载模型:

```bash
# 嵌入模型 (约 137MB)
docker exec -it cve-ollama ollama pull nomic-embed-text

# 分析模型 (约 2GB)
docker exec -it cve-ollama ollama pull qwen2.5:3b

# 查看已安装模型
docker exec -it cve-ollama ollama list
```

## 替代方案:仅启动核心服务

如果下载镜像仍然有问题,可以先启动已有的服务:

### 方案 A: 仅启动 Redis(已存在)

```bash
# 启动 Redis
docker run -d \
  --name cve-redis \
  -p 6379:6379 \
  redis:7-alpine \
  redis-server --requirepass defaultpassword

# 测试 Redis
docker exec cve-redis redis-cli -a defaultpassword PING
```

### 方案 B: 使用本地已有的镜像

```bash
# 查看已下载的镜像
docker images

# 如果有以下镜像,可以手动启动:
# - redis:7-alpine
# - mongo:6.0
# - ankane/pgvector
# - ollama/ollama
```

### 方案 C: 手动拉取关键镜像

```bash
# 只拉取 GPU 相关的关键镜像
docker pull ollama/ollama:latest

# 启动 Ollama
docker run -d \
  --name cve-ollama \
  --gpus all \
  -p 11434:11434 \
  -v ollama-data:/root/.ollama \
  ollama/ollama:latest

# 验证 GPU
docker exec cve-ollama nvidia-smi
```

## 常见问题

### Q1: Docker Desktop 一直无法启动

**解决方案**:
```powershell
# 1. 完全关闭 Docker Desktop
taskkill /F /IM "Docker Desktop.exe"
taskkill /F /IM "com.docker.service"

# 2. 清理 Docker 缓存(慎用,会删除所有数据)
# 路径: %LOCALAPPDATA%\Docker

# 3. 重新安装 Docker Desktop
```

### Q2: nvidia-smi 在容器中不可用

**解决方案**:
```bash
# 确保 Docker 配置中包含 GPU 支持
# Docker Desktop Settings -> Resources -> WSL Integration
# 启用 WSL 2 集成

# 确保 NVIDIA Container Toolkit 已安装(在 WSL 2 中)
distribution=$(. /etc/os-release;echo $ID$VERSION_ID)
curl -s -L https://nvidia.github.io/nvidia-docker/gpgkey | sudo apt-key add -
curl -s -L https://nvidia.github.io/nvidia-docker/$distribution/nvidia-docker.list | \
    sudo tee /etc/apt/sources.list.d/nvidia-docker.list

sudo apt-get update
sudo apt-get install -y nvidia-container-toolkit
sudo systemctl restart docker
```

### Q3: 镜像下载速度仍然很慢

**解决方案**:
```bash
# 尝试更多镜像源
# 在 Docker Desktop Settings -> Docker Engine 中添加:

{
  "registry-mirrors": [
    "https://docker.m.daocloud.io",
    "https://dockerproxy.com",
    "https://hub-mirror.c.163.com",
    "https://mirror.ccs.tencentyun.com",
    "https://registry.docker-cn.com"
  ]
}
```

### Q4: 端口已被占用

**症状**: `Bind for 0.0.0.0:6379 failed: port is already allocated`

**解决方案**:
```bash
# 查找占用端口的进程
netstat -ano | findstr :6379

# 结束进程(PowerShell 管理员)
taskkill /PID [进程ID] /F

# 或修改 docker-compose-gpu.yml 中的端口映射
```

## 快速诊断命令

运行以下命令进行全面诊断:

```bash
echo "=== Docker 版本 ==="
docker --version
docker-compose --version

echo -e "\n=== Docker 状态 ==="
docker info

echo -e "\n=== GPU 驱动 ==="
nvidia-smi

echo -e "\n=== Docker GPU 支持 ==="
docker run --rm --gpus all nvidia/cuda:13.0.1-runtime-ubuntu22.04 nvidia-smi

echo -e "\n=== 运行中的容器 ==="
docker ps

echo -e "\n=== 所有容器 ==="
docker ps -a

echo -e "\n=== 已下载的镜像 ==="
docker images

echo -e "\n=== Docker 网络 ==="
docker network ls

echo -e "\n=== Docker 存储卷 ==="
docker volume ls
```

## 下一步

完成上述故障排查后:

1. ✅ 确认 Docker Desktop 正常运行
2. ✅ 配置镜像加速器生效
3. ✅ 成功启动所有服务
4. ✅ 下载 LLM 模型
5. ✅ 验证 GPU 加速功能

然后可以参考 `GPU_DOCKER_SETUP.md` 开始使用系统。

---

**最后更新**: 2025-11-03
**适用于**: Docker Desktop on Windows with WSL 2
**GPU**: NVIDIA GeForce 940MX (4GB)
