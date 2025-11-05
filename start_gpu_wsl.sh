#!/bin/bash
# CVE 系统 - GPU 加速服务启动脚本（WSL 版）
# 架构：SQLite + WSL Redis + GPU 向量搜索

echo "========================================"
echo "CVE 系统 - GPU 加速服务启动"
echo "========================================"
echo ""

# 切换到项目目录
cd /mnt/d/AI/Claude/CVE || exit 1

# 检查 GPU 是否可用
echo "[检查] 检测 NVIDIA GPU..."
if command -v nvidia-smi &> /dev/null; then
    GPU_INFO=$(nvidia-smi --query-gpu=name,memory.total --format=csv,noheader | head -n 1)
    echo "[✓] GPU 已检测到: $GPU_INFO"
else
    echo "[!] 警告: 未检测到 NVIDIA GPU"
    echo "    GPU 加速功能可能无法使用"
    echo ""
    read -p "是否继续？(y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "已取消启动"
        exit 1
    fi
fi

# 检查 Docker
echo ""
echo "[检查] 检测 Docker..."
if ! command -v docker &> /dev/null; then
    echo "[✗] 错误: Docker 未安装"
    echo "请先安装 Docker Desktop for Windows"
    exit 1
fi
echo "[✓] Docker 已就绪"

# 检查 Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo "[✗] 错误: Docker Compose 未安装"
    exit 1
fi
echo "[✓] Docker Compose 已就绪"

# 停止可能存在的旧服务
echo ""
echo "[清理] 停止现有 GPU 服务..."
docker-compose -f docker-compose-gpu-lite.yml down 2>/dev/null

# 启动 GPU 服务栈
echo ""
echo "========================================"
echo "启动 GPU 服务栈（轻量版）..."
echo "========================================"
echo ""
echo "服务列表:"
echo "  1. Ollama          - GPU 加速 LLM 服务"
echo "  2. PostgreSQL      - 向量数据库 (pgvector)"
echo "  3. Open WebUI      - LLM 管理界面"
echo "  4. pgAdmin         - 数据库管理界面"
echo ""
echo "注意："
echo "  - Redis 使用 WSL 本地服务"
echo "  - SQLite 数据库文件位于 cve_data/"
echo ""

docker-compose -f docker-compose-gpu-lite.yml up -d

# 等待服务启动
echo ""
echo "[等待] 服务初始化中..."
sleep 5

# 检查服务状态
echo ""
echo "========================================"
echo "服务状态检查"
echo "========================================"
docker-compose -f docker-compose-gpu-lite.yml ps

# 健康检查
echo ""
echo "========================================"
echo "服务健康检查"
echo "========================================"

# 检查 PostgreSQL
echo -n "[PostgreSQL] "
if docker exec cve-postgres-vector pg_isready -U admin 2>/dev/null | grep -q "accepting connections"; then
    echo "✓ 运行正常"
else
    echo "✗ 连接失败"
fi

# 检查 Ollama
echo -n "[Ollama] "
if curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
    echo "✓ 运行正常"
    
    # 显示已安装的模型
    MODELS=$(curl -s http://localhost:11434/api/tags | grep -o '"name":"[^"]*"' | cut -d'"' -f4)
    if [ -z "$MODELS" ]; then
        echo ""
        echo "  [!] 未检测到已安装的模型"
        echo "  提示: 需要下载模型才能使用 GPU 加速功能"
        echo ""
        echo "  下载推荐模型："
        echo "    docker exec -it cve-ollama ollama pull nomic-embed-text  # 向量生成（~137MB）"
        echo "    docker exec -it cve-ollama ollama pull qwen2.5:3b        # CVE 分析（~2GB）"
    else
        echo ""
        echo "  已安装模型:"
        echo "$MODELS" | sed 's/^/    - /'
    fi
else
    echo "✗ 连接失败"
fi

echo ""
echo "========================================"
echo "GPU 服务启动完成"
echo "========================================"
echo ""
echo "访问地址:"
echo "  - Ollama Web UI:      http://localhost:8080"
echo "  - PostgreSQL 管理:    http://localhost:5050 (admin@admin.com / admin)"
echo ""
echo "WSL Redis 连接:"
echo "  - 地址: localhost:6379"
echo "  - 检查: wsl redis-cli ping"
echo ""
echo "常用命令:"
echo "  查看日志:  docker-compose -f docker-compose-gpu-lite.yml logs -f"
echo "  停止服务:  docker-compose -f docker-compose-gpu-lite.yml down"
echo "  重启服务:  docker-compose -f docker-compose-gpu-lite.yml restart"
echo ""
echo "测试 GPU 功能:"
echo "  bash check_wsl_environment.sh"
echo ""
echo "========================================"
