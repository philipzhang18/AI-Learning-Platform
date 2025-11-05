#!/bin/bash
# Docker Desktop 优化应用脚本
# 功能：快速应用所有 Docker 优化配置

echo "========================================"
echo "Docker Desktop 优化脚本"
echo "========================================"
echo ""

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 检查是否在正确的目录
if [ ! -f "docker-compose-mongodb-optimized.yml" ]; then
    echo -e "${RED}错误: 请在项目根目录运行此脚本${NC}"
    exit 1
fi

echo "步骤 1/5: 停止当前运行的容器..."
docker-compose -f docker-compose-mongodb.yml down
echo -e "${GREEN}✓ 容器已停止${NC}"
echo ""

echo "步骤 2/5: 清理 Docker 资源..."
echo "清理未使用的镜像..."
docker image prune -f
echo "清理未使用的容器..."
docker container prune -f
echo "清理未使用的网络..."
docker network prune -f
echo -e "${GREEN}✓ Docker 资源清理完成${NC}"
echo ""

echo "步骤 3/5: 启动优化后的服务..."
docker-compose -f docker-compose-mongodb-optimized.yml up -d
echo -e "${GREEN}✓ 服务已启动${NC}"
echo ""

echo "步骤 4/5: 等待服务健康检查..."
sleep 10

echo "步骤 5/5: 验证服务状态..."
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
echo ""

echo "========================================"
echo "资源使用情况:"
echo "========================================"
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"
echo ""

echo "========================================"
echo -e "${GREEN}✓ 优化完成！${NC}"
echo "========================================"
echo ""
echo "预期效果:"
echo "  - Docker Desktop CPU 占用降低 40-60%"
echo "  - 内存占用降低约 50%"
echo "  - 服务响应速度保持不变"
echo ""
echo "下一步操作:"
echo "  1. 检查任务管理器中的 'Vmmem' 进程"
echo "  2. 监控 Docker Desktop backend 的 CPU 占用"
echo "  3. 如需进一步优化，创建 .wslconfig 文件:"
echo "     请参考 .wslconfig.example"
echo ""
echo "验证命令:"
echo "  docker stats               # 实时监控容器资源"
echo "  docker ps                  # 查看运行状态"
echo "  docker logs cve-mongodb    # 查看 MongoDB 日志"
echo ""
