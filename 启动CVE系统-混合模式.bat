@echo off
chcp 65001 >nul
title CVE漏洞监控系统 - SQLite+WSL Redis混合模式

echo ========================================
echo CVE 漏洞监控系统 - 混合模式启动
echo 架构: SQLite存储 + WSL Redis缓存
echo ========================================
echo.

cd /d D:\AI\Claude\CVE

echo [信息] 检查WSL Redis服务...
wsl bash -c "sudo service redis-server status 2>nul | findstr running >nul"
if %errorlevel% neq 0 (
    echo [警告] Redis未运行，正在启动WSL Redis服务...
    wsl bash -c "sudo service redis-server start"
    timeout /t 2 /nobreak >nul
) else (
    echo [√] WSL Redis 服务已运行
)

echo.
echo [信息] 验证Redis连接...
wsl bash -c "redis-cli ping 2>nul" | findstr PONG >nul
if %errorlevel% equ 0 (
    echo [√] Redis 连接成功
) else (
    echo [×] Redis 连接失败，将回退到纯SQLite模式
)

echo.
echo [信息] 检查SQLite数据库状态...
if exist "cve_data\cve_database.db" (
    echo [√] SQLite 数据库已就绪
) else (
    echo [!] SQLite 数据库不存在，将自动创建
)

echo.
echo ========================================
echo 正在启动 CVE GUI 程序...
echo ========================================
echo.

REM 获取WSL IP地址
for /f "tokens=*" %%i in ('wsl bash -c "ip addr show eth0 | grep ''inet '' | awk ''{print $2}'' | cut -d/ -f1"') do set WSL_IP=%%i
echo [信息] WSL IP地址: %WSL_IP%

REM 设置环境变量
set REDIS_HOST=%WSL_IP%
set REDIS_PORT=6379
set REDIS_PASSWORD=
set USE_REDIS=1
set USE_SQLITE_FALLBACK=1
set PYTHONPATH=D:\AI\Claude\CVE

REM 启动GUI
D:\AI\cursor\starone\.venv\Scripts\python.exe cve_integrated_gui.py

echo.
echo ========================================
echo CVE 程序已退出
echo ========================================
pause
