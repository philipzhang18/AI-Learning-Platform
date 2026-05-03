@echo off
chcp 65001 >nul
echo ========================================
echo 智能知识管理平台 - WSL Redis 启动程序
echo ========================================
echo.

cd /D E:\AI\Claude\CVE

REM 从 .env 读取 REDIS_PASSWORD 作为 sudo 密码
set "SUDO_PASS="
for /f "tokens=1,* delims==" %%a in ('findstr /b "REDIS_PASSWORD=" .env') do (
    if not "%%b"=="" set "SUDO_PASS=%%b"
)

echo 正在 WSL 中启动 Redis...
if defined SUDO_PASS (
    echo %SUDO_PASS%| wsl sudo -S service redis-server start 2>nul
) else (
    echo [警告] .env 中未设置 REDIS_PASSWORD，需手动输入密码
    wsl sudo service redis-server start
)
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

set USE_REDIS=true

echo ========================================
echo 正在启动智能知识管理平台...
echo ========================================
echo.

E:\AI\cursor\starone\.venv\Scripts\python.exe cve_integrated_gui.py

echo.
echo ========================================
echo 智能知识管理平台已退出
echo ========================================
pause
