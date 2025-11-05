@echo off
chcp 65001 >nul
echo ========================================
echo CVE 漏洞监控系统 - 启动程序
echo ========================================
echo.

cd /D D:\AI\Claude\CVE

echo 检查后端服务...
docker ps | findstr "cve-mongodb" >nul
if errorlevel 1 (
    echo [警告] MongoDB 未运行，正在启动...
    docker-compose -f docker-compose-mongodb-optimized.yml up -d mongodb
    timeout /t 5 /nobreak >nul
)

docker ps | findstr "cve-redis" >nul
if errorlevel 1 (
    echo [警告] Redis 未运行，正在启动...
    docker-compose -f docker-compose-mongodb-optimized.yml up -d redis
    timeout /t 3 /nobreak >nul
)

echo.
echo 后端服务状态:
docker ps --format "table {{.Names}}\t{{.Status}}" | findstr "cve"
echo.

echo ========================================
echo 正在启动 CVE GUI 程序...
echo ========================================
echo.

D:\AI\cursor\starone\.venv\Scripts\python.exe cve_integrated_gui.py

echo.
echo ========================================
echo CVE 程序已退出
echo ========================================
pause
