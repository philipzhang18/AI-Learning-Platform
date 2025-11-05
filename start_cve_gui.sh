#!/bin/bash
# CVE 程序启动脚本

echo "========================================"
echo "CVE 漏洞监控系统 - 启动脚本"
echo "========================================"
echo ""

# 检查 MongoDB 和 Redis 服务
echo "检查后端服务状态..."
MONGODB_RUNNING=$(docker ps -q -f name=cve-mongodb)
REDIS_RUNNING=$(docker ps -q -f name=cve-redis)

if [ -z "$MONGODB_RUNNING" ]; then
    echo "⚠ MongoDB 未运行，正在��动..."
    cd /D/AI/Claude/CVE
    docker-compose -f docker-compose-mongodb-optimized.yml up -d mongodb
    sleep 5
fi

if [ -z "$REDIS_RUNNING" ]; then
    echo "⚠ Redis 未运行，正在启动..."
    cd /D/AI/Claude/CVE
    docker-compose -f docker-compose-mongodb-optimized.yml up -d redis
    sleep 3
fi

# 验证服务状态
echo ""
echo "后端服务状态:"
docker ps --format "table {{.Names}}\t{{.Status}}" | grep -E "cve-mongodb|cve-redis"
echo ""

echo "========================================"
echo "正在启动 CVE 漏洞监控系统..."
echo "========================================"
echo ""

# 进入项目目录并启动 GUI
cd /D/AI/Claude/CVE
export PYTHONPATH=/D/AI/Claude/CVE:$PYTHONPATH
/D/AI/cursor/starone/.venv/Scripts/python.exe cve_integrated_gui.py
