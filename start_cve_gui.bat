@echo off
chcp 65001 >nul
cls

echo ==================================
echo  智能知识学习平台 - 启动中...
echo ==================================
echo.

REM 激活虚拟环境
echo [1/2] 激活虚拟环境...
call E:\AI\cursor\starone\.venv\Scripts\activate.bat

if errorlevel 1 (
    echo 错误：无法激活虚拟环境
    echo 请检查虚拟环境路径是否正确
    pause
    exit /b 1
)

echo √ 虚拟环境已激活
echo.

REM 检查依赖
echo [2/2] 检查依赖包...
python -c "import tkinter, aiohttp, feedparser" 2>nul

if errorlevel 1 (
    echo 警告：某些依赖包可能缺失
    echo 正在安装依赖...
    pip install -r requirements.txt
)

echo √ 依赖包检查完成
echo.

REM 启动程序
echo ==================================
echo  正在启动 GUI 程序...
echo ==================================
echo.

python cve_integrated_gui.py

REM 退出后的消息
echo.
echo ==================================
echo  程序已退出
echo ==================================
pause
