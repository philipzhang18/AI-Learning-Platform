#!/bin/bash
# CVE 漏洞监控系统启动脚本 - SQLite + WSL Redis 混合模式

echo "========================================"
echo "CVE 漏洞监控系统 - 混合模式启动"
echo "架构: SQLite存储 + WSL Redis缓存"
echo "========================================"
echo ""

cd /D/AI/Claude/CVE

# 检查并启动WSL Redis服务
echo "[信息] 检查WSL Redis服务..."
WSL_REDIS_STATUS=$(wsl bash -c "sudo service redis-server status 2>/dev/null | grep -o 'running' || echo 'stopped'")

if [ "$WSL_REDIS_STATUS" != "running" ]; then
    echo "[⚠] Redis未运行，正在启动WSL Redis服务..."
    wsl bash -c "sudo service redis-server start"
    sleep 2
else
    echo "[✓] WSL Redis 服务已运行"
fi

# 验证Redis连接
echo "[信息] 验证Redis连接..."
REDIS_PING=$(wsl bash -c "redis-cli ping 2>/dev/null || echo 'FAILED'")

if [ "$REDIS_PING" = "PONG" ]; then
    echo "[✓] Redis 连接成功"
else
    echo "[✗] Redis 连接失败，将回退到纯SQLite模式"
fi

# 获取WSL IP地址（用于从Windows连接WSL服务）
WSL_IP=$(wsl bash -c "ip addr show eth0 | grep 'inet ' | awk '{print \$2}' | cut -d/ -f1")
echo "[信息] WSL IP地址: $WSL_IP"

# 检查数据库
echo ""
echo "[信息] 检查SQLite数据库状态..."
if [ -f "cve_data/cve_database.db" ]; then
    DB_SIZE=$(du -h cve_data/cve_database.db | cut -f1)
    echo "[✓] SQLite 数据库已就绪 (大小: $DB_SIZE)"
else
    echo "[!] SQLite 数据库不存在，将自动创建"
fi

echo ""
echo "========================================"
echo "正在启动 CVE GUI 程序..."
echo "========================================"
echo ""

# 设置环境变量（使用WSL Redis + SQLite模式）
export REDIS_HOST="$WSL_IP"
export REDIS_PORT="6379"
export REDIS_PASSWORD=""
export USE_REDIS=1
export USE_SQLITE_FALLBACK=1
export PYTHONPATH=/D/AI/Claude/CVE:$PYTHONPATH

# 启动GUI
/D/AI/cursor/starone/.venv/Scripts/python.exe cve_integrated_gui.py

echo ""
echo "========================================"
echo "CVE 程序已退出"
echo "========================================"
