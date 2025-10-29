"""
快速演示脚本 - 直接启动 V2.0 版本
"""
import subprocess
import sys
import webbrowser
import time

print("=" * 60)
print("CVE 漏洞监控系统 V2.0 - 快速演示")
print("=" * 60)

print("\n新功能特性:")
print("✅ 多字段关键字搜索")
print("✅ 智能解决方案推荐")
print("✅ 增强的统计分析")
print("✅ 实时过滤机制")

print("\n请选择演示版本:")
print("1. 桌面 GUI V2.0 (推荐)")
print("2. Web 界面 V2.0")
print("3. 同时启动两个版本")

choice = input("\n请输入选项 (1-3): ").strip()

if choice == "1" or choice == "3":
    print("\n正在启动桌面 GUI V2.0...")
    try:
        subprocess.Popen([sys.executable, "cve_gui_v2.py"])
        print("✅ 桌面 GUI V2.0 已启动")
        print("\n使用提示:")
        print("- 选择搜索类型和输入关键字进行搜索")
        print("- 查看自动生成的解决方案")
        print("- 双击行查看详细信息")
    except Exception as e:
        print(f"❌ 启动失败: {e}")

if choice == "2" or choice == "3":
    print("\n正在启动 Web 界面 V2.0...")

    # 启动简单的 HTTP 服务器
    import http.server
    import socketserver
    import threading

    PORT = 8080

    class Handler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            # 禁用日志输出
            pass

    def start_server():
        with socketserver.TCPServer(("", PORT), Handler) as httpd:
            httpd.serve_forever()

    # 在后台启动服务器
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()

    print(f"✅ Web 服务器已在端口 {PORT} 启动")

    # 等待服务器启动
    time.sleep(1)

    # 打开浏览器
    url = f"http://localhost:{PORT}/cve_web_interface_v2.html"
    webbrowser.open(url)
    print(f"✅ 已在浏览器中打开: {url}")

    print("\n使用提示:")
    print("- 使用搜索栏进行多条件筛选")
    print("- 查看彩色标签的解决方案")
    print("- 点击'查看详情'了解更多")
    print("- 按 Ctrl+F 快速聚焦搜索框")

    print("\n按 Ctrl+C 停止 Web 服务器")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n已停止 Web 服务器")

if choice not in ["1", "2", "3"]:
    print("无效选项，请重新运行程序")

print("\n" + "=" * 60)
print("演示已启动，请在界面中体验新功能！")
print("=" * 60)