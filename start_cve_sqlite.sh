#!/bin/bash
# CVE 漏洞监控系统启动脚本 - SQLite 轻量版

echo "========================================"
echo "CVE 漏洞监控系统 - 轻量版启动"
echo "架构: SQLite 本地存储"
echo "========================================"
echo ""

# 获取脚本所在目录（支持相对路径和符号链接）
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[信息] 工作目录: $SCRIPT_DIR"

# 检查数据库
echo "[信息] 检查数据库状态..."
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

# 设置环境变量（使用纯SQLite模式）
export REDIS_HOST=""
export REDIS_PORT=""
export USE_SQLITE_ONLY=1
export PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH"

# 查找Python解释器
PYTHON_CMD=""

# 1. 优先使用虚拟环境（Git Bash路径格式）
if [ -f "/d/AI/cursor/starone/.venv/Scripts/python.exe" ]; then
    PYTHON_CMD="/d/AI/cursor/starone/.venv/Scripts/python.exe"
# 2. 尝试系统Python
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
elif command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
else
    echo "[错误] 未找到Python解释器"
    echo "请确保Python已安装，或激活虚拟环境"
    exit 1
fi

echo "[信息] 使用Python: $PYTHON_CMD"

# 启动GUI
"$PYTHON_CMD" cve_integrated_gui.py

echo ""
echo "========================================"
echo "CVE 程序已退出"
echo "========================================"
