@echo off
chcp 65001 >nul
echo ========================================
echo CVE 漏洞监控系统 - WSL Redis 启动程序
echo ========================================
echo.

cd /D E:\AI\Claude\CVE

echo 正在 WSL 中启动 Redis...
wsl sudo service redis-server start
timeout /t 2 /nobreak >nul

echo 验证 Redis 连接...
wsl redis-cli PING
if errorlevel 1 (
    echo [错误] Redis 连接失败
    pause
    exit /b 1
)

echo Redis 已启动
echo.

echo ========================================
echo 正在启动 CVE GUI 程序...
echo ========================================
echo.

E:\AI\cursor\starone\.venv\Scripts\python.exe cve_integrated_gui.py

echo.
echo ========================================
echo CVE 程序已退出
echo ========================================
pause
