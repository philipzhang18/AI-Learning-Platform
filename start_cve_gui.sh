#!/bin/bash

# CVE 漏洞监控系统 - 快速启动脚本

echo "=================================="
echo " CVE 漏洞监控系统 - 启动中..."
echo "=================================="
echo ""

# 激活虚拟环境
echo "[1/2] 激活虚拟环境..."
source /D/AI/cursor/starone/.venv/Scripts/activate

if [ $? -ne 0 ]; then
    echo "错误：无法激活虚拟环境"
    echo "请检查虚拟环境路径是否正确"
    exit 1
fi

echo "✓ 虚拟环境已激活"
echo ""

# 检查依赖
echo "[2/2] 检查依赖包..."
python -c "import tkinter, aiohttp, feedparser" 2>/dev/null

if [ $? -ne 0 ]; then
    echo "警告：某些依赖包可能缺失"
    echo "正在安装依赖..."
    pip install -r requirements.txt
fi

echo "✓ 依赖包检查完成"
echo ""

# 启动程序
echo "=================================="
echo " 正在启动 GUI 程序..."
echo "=================================="
echo ""

python cve_integrated_gui.py

# 退出后的消息
echo ""
echo "=================================="
echo " 程序已退出"
echo "=================================="
