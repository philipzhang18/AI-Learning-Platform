@echo off
chcp 65001 >nul
echo ========================================
echo 智能知识学习平台 - 轻量版启动
echo 架构: SQLite 本地存储
echo ========================================
echo.

cd /D E:\AI\Claude\CVE

echo [信息] 检查数据库状态...
if exist cve_data\cve_database.db (
    echo [✓] SQLite 数据库已就绪
) else (
    echo [!] SQLite 数据库不存在，将自动创建
)

echo.
echo ========================================
echo 正在启动智能知识学习平台...
echo ========================================
echo.

:: 设置环境变量（禁用Redis，使用纯SQLite模式）
set REDIS_HOST=
set REDIS_PORT=
set USE_SQLITE_ONLY=1

:: 启动GUI
E:\AI\cursor\starone\.venv\Scripts\python.exe cve_integrated_gui.py

echo.
echo ========================================
echo 智能知识学习平台已退出
echo ========================================
pause
