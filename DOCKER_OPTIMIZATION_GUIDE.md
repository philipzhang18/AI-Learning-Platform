# Docker Desktop CPU 占用优化指南

**系统信息**:
- GPU: NVIDIA GeForce 940MX
- Docker CPUs: 4 核心
- Docker Memory: 15.53GB
- 优化目标: 降低 Docker Desktop backend CPU 占用

---

## 问题分析

Docker Desktop backend 高 CPU 占用的常见原因：
1. **分配资源过多** - 分配了过多的 CPU 核心
2. **WSL 2 内存泄漏** - WSL 2 后端内存管理问题
3. **容器资源限制不当** - 容器没有设置资源限制
4. **文件监控过度** - 文件共享和监控导致 CPU 占用
5. **后台进程过多** - 不必要的容器在后台运行

---

## 优化方案

### 方案 1: 调整 Docker Desktop 资源分配（立即见效）

**当前配置**: 4 CPUs, 15.53GB Memory
**推荐配置**: 2 CPUs, 8GB Memory（对于你的 MongoDB + Redis 足够）

**操作步骤**:

1. 打开 Docker Desktop
2. 点击 **Settings** (设置图标)
3. 进入 **Resources** → **Advanced**
4. 调整以下参数：
   ```
   CPUs: 2 (从 4 降到 2)
   Memory: 8 GB (从 15.53GB 降到 8GB)
   Swap: 2 GB
   Disk image size: 根据需要
   ```
5. 点击 **Apply & Restart**

**预期效果**: CPU 占用降低 40-50%

---

### 方案 2: 优化 WSL 2 后端（Windows 专用）

创建 `.wslconfig` 文件限制 WSL 2 资源占用：

**位置**: `C:\Users\<你的用户名>\.wslconfig`

**配置内容**:
```ini
[wsl2]
# 限制 WSL 2 最大内存
memory=8GB

# 限制 WSL 2 CPU 核心数
processors=2

# 限制交换空间
swap=2GB

# 关闭 WSL 2 页面文件
pageReporting=false

# 关闭嵌套虚拟化（如果不需要）
nestedVirtualization=false

# 限制虚拟硬盘大小
# vmIdleTimeout=60000
```

**应用方法**:
```powershell
# 在 PowerShell 中执行
wsl --shutdown
# 然后重启 Docker Desktop
```

---

### 方案 3: 为容器设置资源限制

修改你的 `docker-compose-mongodb.yml`，为每个容器设置明确的资源限制：

```yaml
version: '3.8'

services:
  mongodb:
    image: mongo:7.0
    container_name: cve-mongodb
    restart: unless-stopped
    ports:
      - "27017:27017"
    environment:
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: ${MONGODB_PASSWORD:-secure_password}
      MONGO_INITDB_DATABASE: cve_database
    volumes:
      - mongodb_data:/data/db
      - mongodb_config:/data/configdb
      - ./init-mongodb.js:/docker-entrypoint-initdb.d/init.js:ro
    command: mongod --auth
    networks:
      - cve_network
    deploy:
      resources:
        limits:
          cpus: '1.0'          # 降低到 1 核
          memory: 1.5G         # 降低到 1.5GB
        reservations:
          cpus: '0.5'
          memory: 512M

  redis:
    image: redis:7-alpine
    container_name: cve-redis
    restart: unless-stopped
    ports:
      - "6379:6379"
    command: >
      redis-server
      --requirepass ${REDIS_PASSWORD:-defaultpassword}
      --maxmemory 1gb          # 降低到 1GB
      --maxmemory-policy allkeys-lru
      --save 900 1
      --save 300 10
      --save 60 10000
      --appendonly yes
      --appendfsync everysec
      --lazyfree-lazy-eviction yes
      --lazyfree-lazy-expire yes
    volumes:
      - redis_data:/data
    networks:
      - cve_network
    deploy:
      resources:
        limits:
          cpus: '0.5'          # 降低到 0.5 核
          memory: 1G           # 降低到 1GB
        reservations:
          cpus: '0.25'
          memory: 256M

  redis-commander:
    image: rediscommander/redis-commander:latest
    container_name: cve-redis-commander
    restart: unless-stopped
    ports:
      - "8082:8081"
    environment:
      REDIS_HOSTS: local:redis:6379:0:${REDIS_PASSWORD:-defaultpassword}
    depends_on:
      redis:
        condition: service_healthy
    networks:
      - cve_network
    deploy:
      resources:
        limits:
          cpus: '0.25'         # 降低到 0.25 核
          memory: 128M         # 降低到 128MB

volumes:
  mongodb_data:
    driver: local
  mongodb_config:
    driver: local
  redis_data:
    driver: local

networks:
  cve_network:
    driver: bridge
```

**应用方法**:
```bash
# 重启服务以应用新配置
docker-compose -f docker-compose-mongodb.yml down
docker-compose -f docker-compose-mongodb.yml up -d
```

---

### 方案 4: 启用 GPU 支持（可选，适用于 AI/ML 工作负载）

虽然 Docker Desktop backend 本身无法在 GPU 上运行，但你可以为容器启用 GPU 支持。

**前提条件**:
1. 安装 **NVIDIA Container Toolkit**
2. 安装最新的 NVIDIA 驱动

**安装步骤** (WSL 2):

```bash
# 1. 在 WSL 2 中安装 NVIDIA Container Toolkit
distribution=$(. /etc/os-release;echo $ID$VERSION_ID)
curl -s -L https://nvidia.github.io/nvidia-docker/gpgkey | sudo apt-key add -
curl -s -L https://nvidia.github.io/nvidia-docker/$distribution/nvidia-docker.list | sudo tee /etc/apt/sources.list.d/nvidia-docker.list

sudo apt-get update
sudo apt-get install -y nvidia-docker2
sudo systemctl restart docker

# 2. 验证 GPU 支持
docker run --rm --gpus all nvidia/cuda:11.0-base nvidia-smi
```

**GPU 容器示例** (如果需要 GPU 加速的 CVE 分析):
```yaml
services:
  gpu-cve-analyzer:
    image: nvidia/cuda:11.8.0-runtime-ubuntu22.04
    container_name: gpu-cve-analyzer
    runtime: nvidia
    environment:
      - NVIDIA_VISIBLE_DEVICES=all
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]
```

**注意**: GeForce 940MX 是入门级 GPU，对于通用计算性能有限，主要适用于：
- 轻量级机器学习推理
- 图像处理加速
- 不建议用于大规模深度学习训练

---

### 方案 5: 优化 Docker Desktop 设置

**5.1 禁用不必要的功能**:

在 Docker Desktop Settings 中：
- **General** → 关闭 "Start Docker Desktop when you log in"（如果不需要开机自启）
- **General** → 关闭 "Use the WSL 2 based engine"（如果不需要 WSL 2，但通常需要）
- **Resources** → **File Sharing** → 只共享必要的目录
- **Kubernetes** → 禁用 Kubernetes（如果不使用）

**5.2 清理 Docker 资源**:

```bash
# 清理未使用的镜像
docker image prune -a

# 清理未使用的容器
docker container prune

# 清理未使用的卷
docker volume prune

# 清理所有未使用的资源
docker system prune -a --volumes
```

**5.3 限制日志大小**:

在 `C:\Users\<用户名>\.docker\daemon.json` 中添加：

```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
```

重启 Docker Desktop 应用配置。

---

### 方案 6: 使用 Docker Compose 配置文件优化

创建 `.env` 文件统一管理配置：

```bash
# .env 文件
MONGODB_PASSWORD=secure_password
REDIS_PASSWORD=defaultpassword

# 资源限制
MONGODB_CPU_LIMIT=1.0
MONGODB_MEMORY_LIMIT=1.5G
REDIS_CPU_LIMIT=0.5
REDIS_MEMORY_LIMIT=1G
```

---

## 监控和验证

### 1. 监控 Docker 资源占用

```bash
# 实时监控容器资源使用
docker stats

# 查看特定容器资源
docker stats cve-mongodb cve-redis
```

### 2. 监控 WSL 2 内存

```powershell
# PowerShell 中查看 WSL 内存
Get-Process -Name vmmem

# 或使用任务管理器查看 "Vmmem" 进程
```

### 3. 设置告警

创建监控脚本 `monitor_docker.ps1`:

```powershell
# 监控 Docker Desktop CPU 占用
while ($true) {
    $dockerProcess = Get-Process -Name "Docker Desktop" -ErrorAction SilentlyContinue
    if ($dockerProcess) {
        $cpu = $dockerProcess.CPU
        Write-Host "Docker Desktop CPU: $cpu"

        if ($cpu -gt 60) {
            Write-Warning "Docker Desktop CPU 使用过高: $cpu%"
        }
    }
    Start-Sleep -Seconds 5
}
```

---

## 优化效果预期

| 项目 | 优化前 | 优化后 | 改善 |
|------|--------|--------|------|
| **Docker Desktop CPU** | 高占用 (>50%) | 低占用 (<20%) | **降低 60%** |
| **WSL 2 内存占用** | 8-15GB | 4-8GB | **降低 50%** |
| **容器响应时间** | 无变化 | 无变化 | 保持稳定 |
| **系统整体性能** | 卡顿 | 流畅 | **显著改善** |

---

## 实施顺序

建议按以下顺序实施优化：

1. **立即执行** (5分钟):
   - 方案 1: 调整 Docker Desktop 资源分配（CPUs: 2, Memory: 8GB）
   - 重启 Docker Desktop

2. **短期优化** (15分钟):
   - 方案 2: 创建 `.wslconfig` 文件
   - 方案 5.2: 清理 Docker 资源
   - 方案 5.3: 限制日志大小

3. **中期优化** (30分钟):
   - 方案 3: 更新 docker-compose-mongodb.yml 并重启服务
   - 方案 5.1: 优化 Docker Desktop 设置

4. **长期优化** (可选):
   - 方案 4: 启用 GPU 支持（如果需要 GPU 加速）
   - 设置资源监控

---

## 故障排查

### 问题 1: 调整资源后服务无法启动

**解决方案**:
```bash
# 1. 检查容器日志
docker logs cve-mongodb
docker logs cve-redis

# 2. 如果内存不足，逐步增加限制
# 修改 docker-compose 中的 memory limit

# 3. 验证服务健康
docker ps
```

### 问题 2: WSL 2 仍然占用大量 CPU

**解决方案**:
```powershell
# 完全重启 WSL 2
wsl --shutdown

# 检查 WSL 2 版本
wsl --list --verbose

# 如果问题持续，考虑切换到 Hyper-V 后端
```

### 问题 3: GPU 支持无法启用

**解决方案**:
- 确保 NVIDIA 驱动最新
- 确保 Docker Desktop 版本 >= 19.03
- GeForce 940MX 可能不支持所有 CUDA 功能

---

## 总结

**核心优化建议**:

1. ✅ **降低 Docker Desktop 分配的 CPU 和内存**（从 4核/15.53GB 降到 2核/8GB）
2. ✅ **创建 `.wslconfig` 限制 WSL 2 资源**
3. ✅ **为容器设置明确的资源限制**
4. ✅ **清理不必要的 Docker 资源**
5. ⚠️ **GPU 支持可选**（940MX 性能有限）

**预期效果**: Docker Desktop backend CPU 占用降��� **40-60%**

---

**优化完成后，请运行以下命令验证**:
```bash
# 查看容器资源使用
docker stats

# 验证服务正常运行
docker ps
```

如有任何问题，请参考故障排查部分或提供详细日志。
