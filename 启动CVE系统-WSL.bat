@echo off
chcp 65001 >nul
echo ========================================
echo CVE 漏洞监控系统
echo 架构：SQLite + WSL Redis
echo ========================================
echo.

:: 检查 WSL 是否运行
echo [1/4] 检查 WSL 环境...
wsl --list --running | findstr /i "Ubuntu" >nul 2>&1
if errorlevel 1 (
    echo [!] WSL 未运行，正在启动...
    wsl --distribution Ubuntu --exec echo "WSL 已启动"
)
echo [✓] WSL 运行正常
echo.

:: 检查 Redis 是否运行
echo [2/4] 检查 Redis 服务...
wsl redis-cli ping >nul 2>&1
if errorlevel 1 (
    echo [!] Redis 未运行，正在启动...
    wsl sudo service redis-server start
    timeout /t 2 /nobreak >nul
    
    :: 再次检查
    wsl redis-cli ping >nul 2>&1
    if errorlevel 1 (
        echo [✗] Redis 启动失败
        echo.
        echo 手动启动方式：
        echo   wsl sudo service redis-server start
        echo.
        pause
        exit /b 1
    )
)
echo [✓] Redis 运行正常
echo.

:: 激活虚拟环境并启动 GUI
echo [3/4] 启动 CVE 监控系统...
cd /D D:\AI\Claude\CVE

:: 检查虚拟环境
if not exist "D:\AI\cursor\starone\.venv\Scripts\python.exe" (
    echo [✗] 虚拟环境未找到
    echo 路径: D:\AI\cursor\starone\.venv
    echo.
    pause
    exit /b 1
)

echo [✓] 虚拟环境已找到
echo.

echo [4/4] 启动 GUI 应用...
echo ========================================
echo.

:: 启动 Python GUI（使用 Git Bash）
"C:\Program Files\Git\bin\bash.exe" -c "source /D/AI/cursor/starone/.venv/Scripts/activate && python cve_integrated_gui.py"

:: 如果上面的方式失败，尝试直接调用
if errorlevel 1 (
    echo.
    echo [!] Git Bash 启动失败，尝试直接启动...
    D:\AI\cursor\starone\.venv\Scripts\python.exe cve_integrated_gui.py
)

pause
