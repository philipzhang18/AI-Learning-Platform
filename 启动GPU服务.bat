@echo off
REM CVE 系统 GPU 加速服务启动脚本 (Windows)
chcp 65001 >nul
cls

echo ========================================
echo CVE 系统 - GPU 加速服务启动
echo ========================================
echo.

cd /d D:\AI\Claude\CVE

REM 检查 Docker
echo [检查] 检测 Docker...
docker --version >nul 2>&1
if errorlevel 1 (
    echo [×] 错误: Docker 未安装或未运行
    echo 请先启动 Docker Desktop
    pause
    exit /b 1
)
echo [√] Docker 已就绪
echo.

REM 检查 GPU （可选）
echo [检查] 检测 NVIDIA GPU...
nvidia-smi --query-gpu=name,memory.total --format=csv,noheader >nul 2>&1
if errorlevel 1 (
    echo [!] 警告: 未检测到 NVIDIA GPU
    echo     GPU 加速功能可能无法使用
    echo.
    choice /C YN /M "是否继续"
    if errorlevel 2 exit /b 0
) else (
    for /f "delims=" %%i in ('nvidia-smi --query-gpu=name,memory.total --format=csv,noheader') do (
        echo [√] GPU 已检测到: %%i
    )
)

REM 停止旧服务
echo.
echo [清理] 停止现有服务...
docker-compose -f docker-compose-gpu.yml down 2>nul

REM 启动服务
echo.
echo ========================================
echo 启动 GPU 服务栈...
echo ========================================
echo.
echo 服务列表:
echo   1. MongoDB         - CVE 数据存储
echo   2. Redis           - 高速缓存
echo   3. PostgreSQL      - 向量数据库 (pgvector)
echo   4. Ollama          - GPU 加速 LLM 服务
echo.

docker-compose -f docker-compose-gpu.yml up -d

REM 等待服务启动
echo.
echo [等待] 服务初始化中...
timeout /t 5 /nobreak >nul

REM 检查服务状态
echo.
echo ========================================
echo 服务状态检查
echo ========================================
docker-compose -f docker-compose-gpu.yml ps

REM 健康检查
echo.
echo ========================================
echo 服务健康检查
echo ========================================

REM Redis
echo [Redis]
docker exec cve-redis redis-cli -a defaultpassword PING 2>nul | findstr "PONG" >nul
if errorlevel 1 (
    echo   × 连接失败
) else (
    echo   √ 运行正常
)

REM MongoDB
echo [MongoDB]
docker exec cve-mongodb mongosh --eval "db.adminCommand('ping')" --quiet 2>nul | findstr "ok" >nul
if errorlevel 1 (
    echo   × 连接失败
) else (
    echo   √ 运行正常
)

REM PostgreSQL
echo [PostgreSQL]
docker exec cve-postgres-vector pg_isready -U admin 2>nul | findstr "accepting connections" >nul
if errorlevel 1 (
    echo   × 连接失败
) else (
    echo   √ 运行正常
)

REM Ollama
echo [Ollama]
curl -s http://localhost:11434/api/tags >nul 2>&1
if errorlevel 1 (
    echo   × 连接失败
) else (
    echo   √ 运行正常

    REM 检查模型
    echo.
    echo   检查已安装的模型...
    curl -s http://localhost:11434/api/tags | findstr "\"name\":" >nul 2>&1
    if errorlevel 1 (
        echo   [!] 未检测到已安装的模型
        echo.
        echo   下载推荐模型：
        echo     docker exec -it cve-ollama ollama pull nomic-embed-text
        echo     docker exec -it cve-ollama ollama pull qwen2.5:3b
    ) else (
        echo   [√] 模型已安装
        docker exec cve-ollama ollama list 2>nul
    )
)

echo.
echo ========================================
echo GPU 服务启动完成
echo ========================================
echo.
echo 访问地址:
echo   - Ollama Web UI:      http://localhost:8080
echo   - Redis 管理界面:     http://localhost:8081
echo   - PostgreSQL 管理:    http://localhost:5050
echo.
echo 常用命令:
echo   查看日志:  docker-compose -f docker-compose-gpu.yml logs -f
echo   停止服务:  docker-compose -f docker-compose-gpu.yml down
echo   重启服务:  docker-compose -f docker-compose-gpu.yml restart
echo.
echo 详细文档:
echo   GPU_USAGE_GUIDE.md - 快速使用指南
echo   GPU_QUICKSTART.md - 快速入门
echo ========================================
echo.
pause
