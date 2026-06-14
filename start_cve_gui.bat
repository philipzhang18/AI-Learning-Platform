@echo off
chcp 65001 >nul
REM ============================================================
REM  智能知识管理平台 - 统一启动入口
REM  自动探测 WSL Redis: 可用则启用缓存模式, 否则降级为 SQLite 轻量模式
REM ============================================================
cd /D "%~dp0"

REM ---------- 1. 探测 Python 解释器 (本地 .venv -> KMP_PYTHON -> 系统 PATH) ----------
set "PYEXE="
if exist "%~dp0.venv\Scripts\python.exe" (
    set "PYEXE=%~dp0.venv\Scripts\python.exe"
) else if defined KMP_PYTHON (
    set "PYEXE=%KMP_PYTHON%"
) else (
    where python >nul 2>nul
    if not errorlevel 1 set "PYEXE=python"
)

if not defined PYEXE (
    echo [错误] 未找到 Python 解释器。
    echo   请在项目目录创建虚拟环境: python -m venv .venv
    echo   或设置环境变量 KMP_PYTHON 指向 python.exe
    pause
    exit /b 1
)

REM ---------- 2. 探测 WSL Redis (失败自动降级, 不交互卡住) ----------
set "USE_REDIS=false"
where wsl >nul 2>nul
if errorlevel 1 (
    echo [信息] 未检测到 WSL, 使用 SQLite 轻量模式
    goto launch
)

REM 2a. Redis 若已在运行, 直接启用
wsl redis-cli PING >nul 2>nul
if not errorlevel 1 (
    echo [信息] 检测到 Redis 已运行, 启用缓存模式
    set "USE_REDIS=true"
    goto launch
)

REM 2b. 未运行: 仅当 .env 提供 REDIS_PASSWORD 时尝试无人值守启动
set "SUDO_PASS="
if exist "%~dp0.env" (
    for /f "tokens=1,* delims==" %%a in ('findstr /b "REDIS_PASSWORD=" "%~dp0.env"') do (
        if not "%%b"=="" set "SUDO_PASS=%%b"
    )
)

if not defined SUDO_PASS (
    echo [信息] .env 未配置 REDIS_PASSWORD, 跳过 Redis 启动, 使用 SQLite 轻量模式
    goto launch
)

echo [信息] 正在 WSL 中启动 Redis...
echo %SUDO_PASS%| wsl sudo -S service redis-server start >nul 2>nul
wsl redis-cli PING >nul 2>nul
if errorlevel 1 (
    echo [信息] Redis 启动失败, 自动降级为 SQLite 轻量模式
    set "USE_REDIS=false"
) else (
    echo [信息] Redis 已就绪, 启用缓存模式
    set "USE_REDIS=true"
)

:launch
REM ---------- 3. 获取 Python 运行环境版本 (不显示绝对路径) ----------
set "PYVER="
for /f "tokens=2" %%v in ('"%PYEXE%" --version 2^>^&1') do set "PYVER=%%v"

echo.
echo ========================================
echo 智能知识管理平台
if "%USE_REDIS%"=="true" (echo 运行模式: SQLite + WSL Redis 缓存) else (echo 运行模式: SQLite 轻量模式)
if defined PYVER (echo Python 运行环境: %PYVER%) else (echo Python 运行环境: 未知)
echo ========================================
echo.

"%PYEXE%" cve_integrated_gui.py

echo.
echo ========================================
echo 智能知识管理平台已退出
echo ========================================
pause
