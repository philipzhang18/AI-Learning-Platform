# Docker Desktop CPU 利用率优化指南

## 问题诊断

### 当前症状
- Docker Desktop backend 进程占用 CPU 高
- GPU 加速未充分利用
- 系统响应变慢

### 根本原因
1. **WSL2 内存/CPU 配置不当**: 默认配置可能占用过多系统资源
2. **GPU 未正确启用**: 导致计算回退到 CPU
3. **Docker 容器资源限制缺失**: 容器可以无限制使用 CPU

---

## 解决方案

### 步骤 1: 配置 WSL2 资源限制

创建或编辑 `%USERPROFILE%\.wslconfig` 文件：

```ini
[wsl2]
# 限制 WSL2 最大内存使用（根据你的系统调整）
memory=4GB

# 限制 WSL2 最大 CPU 核心数（建议留一半给主系统）
processors=4

# 限制 swap 大小
swap=2GB

# 关闭页面报告（减少 I/O）
pageReporting=false

# 启用本地主机转发
localhostForwarding=true
```

**修改后需要重启 WSL2**：
```powershell
# PowerShell 管理员模式执行
wsl --shutdown
```

等待 10 秒后，WSL2 会在下次 Docker 操作时自动启动。

---

### 步骤 2: 优化 Docker Desktop 资源配置

1. **打开 Docker Desktop Settings**
   - 右键点击任务栏 Docker 图标
   - 选择 "Settings"

2. **调整 Resources 设置**（Settings -> Resources）
   - **CPUs**: 设置为系统核心数的 50-75%（例如 8 核系统设置 4-6）
   - **Memory**: 设置为系统内存的 25-40%（例如 16GB 设置 4-6GB）
   - **Swap**: 1-2GB
   - **Disk image size**: 根据需求设置（建议 60GB）

3. **启用 GPU 支持**（Settings -> Resources -> WSL Integration）
   - 确保勾选了你的 WSL2 发行版（例如 Ubuntu）
   - 启用 "Enable GPU acceleration"

4. **点击 "Apply & Restart"**

---

### 步骤 3: 为容器添加资源限制

编辑 `docker-compose-gpu.yml`，为每个服务添加资源限制：

```yaml
services:
  # MongoDB - 限制资源使用
  mongodb:
    image: mongo:6.0
    # ... 其他配置 ...
    deploy:
      resources:
        limits:
          cpus: '1.0'        # 最多使用 1 个 CPU 核心
          memory: 2G         # 最多使用 2GB 内存
        reservations:
          cpus: '0.25'       # 保证最少 0.25 核心
          memory: 512M       # 保证最少 512MB 内存

  # Redis - 轻量级配置
  redis:
    image: redis:7-alpine
    # ... 其他配置 ...
    deploy:
      resources:
        limits:
          cpus: '0.5'        # Redis 通常不需要太多 CPU
          memory: 2G
        reservations:
          cpus: '0.1'
          memory: 256M

  # PostgreSQL - 中等资源
  postgres-vector:
    image: ankane/pgvector:latest
    # ... 其他配置 ...
    deploy:
      resources:
        limits:
          cpus: '1.5'
          memory: 3G
        reservations:
          cpus: '0.5'
          memory: 512M

  # Ollama - GPU 加速，限制 CPU 使用
  ollama:
    image: ollama/ollama:latest
    # ... 其他配置 ...
    deploy:
      resources:
        limits:
          cpus: '2.0'        # LLM 推理主要用 GPU，限制 CPU
          memory: 4G
        reservations:
          cpus: '0.5'
          memory: 1G
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]

  # 后端服务
  backend:
    # ... 其他配置 ...
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 2G
        reservations:
          cpus: '0.25'
          memory: 512M
```

---

### 步骤 4: 验证 GPU 加速是否生效

#### 4.1 检查 GPU 在容器中是否可用

```bash
# 确保 Ollama 容器正在运行
docker ps | grep ollama

# 检查 GPU
docker exec cve-ollama nvidia-smi

# 应该看到类似输出：
# +-----------------------------------------------------------------------------+
# | NVIDIA-SMI 581.57       Driver Version: 581.57       CUDA Version: 13.0     |
# |-------------------------------+----------------------+----------------------+
# | GPU  Name        Persistence-M| Bus-Id        Disp.A | Volatile Uncorr. ECC |
# | Fan  Temp  Perf  Pwr:Usage/Cap|         Memory-Usage | GPU-Util  Compute M. |
# |===============================+======================+======================|
# |   0  GeForce 940MX      Off  | 00000000:01:00.0 Off |                  N/A |
# | N/A   45C    P0    N/A /  N/A |    300MiB /  4096MiB |      0%      Default |
# +-------------------------------+----------------------+----------------------+
```

#### 4.2 测试 LLM 推理时的 GPU 使用

```bash
# 启动实时 GPU 监控（新终端）
watch -n 1 'docker exec cve-ollama nvidia-smi'

# 在另一个终端执行推理测试
curl http://localhost:11434/api/generate -d '{
  "model": "qwen2.5:3b",
  "prompt": "Explain CVE vulnerabilities in detail",
  "stream": false
}'

# 观察 GPU 监控窗口：
# - GPU-Util 应该飙升到 60-90%
# - Memory-Usage 应该增加到 2-3GB
# - 如果 GPU-Util 始终为 0%，说明 GPU 未启用
```

#### 4.3 CPU vs GPU 性能对比

```bash
# 激活虚拟环境
source /D/AI/cursor/starone/.venv/Scripts/activate
cd /D/AI/Claude/CVE

# 运行性能测试
python performance_test.py

# 期望结果:
# ✅ GPU 模式: 20-30 向量/秒
# ❌ CPU 模式: 2-5 向量/秒
# 加速比: 5-10x
```

---

### 步骤 5: 监控和调优

#### 5.1 实时监控 Docker 容器资源使用

```bash
# 方法 1: Docker stats 命令
docker stats

# 输出示例:
# CONTAINER ID   NAME                CPU %     MEM USAGE / LIMIT     MEM %     NET I/O
# abc123         cve-ollama          45.23%    2.5GiB / 4GiB        62.5%     1.2kB / 890B
# def456         cve-mongodb         5.12%     1.2GiB / 2GiB        60.0%     5kB / 3kB
# ghi789         cve-redis           0.50%     256MiB / 2GiB        12.5%     2kB / 1kB

# 方法 2: 只监控特定容器
docker stats cve-ollama cve-mongodb cve-redis
```

#### 5.2 查看 Docker Desktop 整体资源使用

```powershell
# PowerShell 查看 WSL2 进程资源使用
Get-Process -Name "vmmem" | Select-Object CPU, WorkingSet64

# 或使用任务管理器查看 "Vmmem" 进程
```

#### 5.3 持续优化建议

**如果 CPU 使用率仍然高**:
1. 进一步减少 WSL2 内存/CPU 配置
2. 减少同时运行的容器数量
3. 确保 GPU 加速正常工作（检查 nvidia-smi）

**如果 GPU 利用率低**:
1. 检查模型是否正确加载到 GPU
2. 调整 Ollama 环境变量:
   ```yaml
   ollama:
     environment:
       - CUDA_VISIBLE_DEVICES=0
       - OLLAMA_NUM_GPU=1
       - OLLAMA_GPU_LAYERS=99  # 将所有层加载到 GPU
   ```

**如果内存不足**:
1. 使用量化模型（q4_0）减少 75% 显存
2. 设置 Ollama 自动卸载不用的模型:
   ```yaml
   - OLLAMA_KEEP_ALIVE=5m  # 5 分钟后卸载模型
   ```

---

## 优化效果预期

### 优化前
- Docker Desktop CPU: 40-60%
- WSL2 内存: 6-8GB
- GPU 利用率: 0-10%
- 推理速度: 2-5 向量/秒

### 优化后
- Docker Desktop CPU: 10-25%
- WSL2 内存: 3-4GB
- GPU 利用率: 60-90%（推理时）
- 推理速度: 20-30 向量/秒

---

## 故障排查

### 问题: WSL2 配置未生效

**症状**: 修改 `.wslconfig` 后，Docker 仍占用大量资源

**解决**:
```powershell
# 1. 确保 .wslconfig 路径正确
echo %USERPROFILE%\.wslconfig
# 应该显示: C:\Users\你的用户名\.wslconfig

# 2. 完全关闭 WSL2
wsl --shutdown

# 3. 等待 10 秒，重新启动 Docker Desktop

# 4. 验证配置
wsl -l -v
docker info | grep "Total Memory"
```

### 问题: GPU 在容器中不可用

**症状**: `docker exec cve-ollama nvidia-smi` 报错

**解决**:
```bash
# 1. 检查主机 GPU
nvidia-smi

# 2. 检查 Docker GPU 支持
docker run --rm --gpus all nvidia/cuda:13.0.1-runtime-ubuntu22.04 nvidia-smi

# 3. 如果上面失败，重新安装 NVIDIA Container Toolkit
# (在 WSL2 Ubuntu 中执行)
distribution=$(. /etc/os-release;echo $ID$VERSION_ID)
curl -s -L https://nvidia.github.io/nvidia-docker/gpgkey | sudo apt-key add -
curl -s -L https://nvidia.github.io/nvidia-docker/$distribution/nvidia-docker.list | \
    sudo tee /etc/apt/sources.list.d/nvidia-docker.list

sudo apt-get update
sudo apt-get install -y nvidia-container-toolkit
sudo systemctl restart docker

# 4. 重启 Docker Desktop
```

### 问题: 容器频繁被 OOM Killed

**症状**: 容器自动退出，日志显示 "Out of memory"

**解决**:
```yaml
# 增加对应服务的内存限制
services:
  service-name:
    deploy:
      resources:
        limits:
          memory: 4G  # 增加到 4GB
```

---

## 参考文档

- **GPU 快速启动**: `GPU_QUICKSTART.md`
- **Docker 故障排查**: `DOCKER_TROUBLESHOOTING.md`
- **完整 GPU 设置**: `GPU_DOCKER_SETUP.md`
- **性能测试**: `performance_test.py`

---

**最后更新**: 2025-11-04
**适用于**: Docker Desktop on Windows with WSL 2
**GPU**: NVIDIA GeForce 940MX (4GB)
