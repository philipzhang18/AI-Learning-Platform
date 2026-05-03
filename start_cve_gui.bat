@echo off
chcp 65001 >nul
echo ========================================
echo 智能知识管理平台 - SQLite 轻量模式
echo ========================================
echo.

cd /D E:\AI\Claude\CVE

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
