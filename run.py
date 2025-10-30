"""
CVE 漏洞监控系统 - 启动器
选择要运行的界面版本
"""
import os
import sys
import subprocess
import webbrowser
from pathlib import Path

def check_dependencies():
    """检查必要的依赖"""
    try:
        import aiohttp
        return True
    except ImportError:
        print("Warning: Missing required dependency")
        print("Installing aiohttp...")
        subprocess.run([sys.executable, "-m", "pip", "install", "aiohttp"], check=True)
        print("Dependencies installed successfully")
        return True

def run_desktop_gui():
    """运行桌面 GUI 版本"""
    print("Starting Desktop GUI V2.0...")
    print("Choose version:")
    print("1. V1.0 - Basic version")
    print("2. V2.0 - Enhanced version (with search & solutions)")

    choice = input("Enter version (1 or 2): ").strip()

    if choice == "1":
        print("Starting V1.0...")
        try:
            subprocess.Popen([sys.executable, "cve_gui.py"])
            print("Desktop GUI V1.0 launched")
        except Exception as e:
            print(f"Failed to launch: {e}")
    else:
        print("Starting V2.0...")
        try:
            subprocess.Popen([sys.executable, "cve_gui_v2.py"])
            print("Desktop GUI V2.0 launched")
        except Exception as e:
            print(f"Failed to launch: {e}")

def run_web_interface():
    """运行 Web 界面版本"""
    print("Starting Web Interface...")
    print("Choose version:")
    print("1. V1.0 - Basic version")
    print("2. V2.0 - Enhanced version (with search & solutions)")

    choice = input("Enter version (1 or 2): ").strip()

    # 启动 HTTP 服务器
    import http.server
    import socketserver
    import threading

    PORT = 8080
    Handler = http.server.SimpleHTTPRequestHandler

    def start_server():
        with socketserver.TCPServer(("", PORT), Handler) as httpd:
            print(f"Web server started on port {PORT}")
            httpd.serve_forever()

    # 在后台线程启动服务器
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()

    # 打开浏览器
    if choice == "1":
        url = f"http://localhost:{PORT}/cve_web_interface.html"
    else:
        url = f"http://localhost:{PORT}/cve_web_interface_v2.html"

    print(f"Opening browser: {url}")
    webbrowser.open(url)

    print("\nPress Ctrl+C to stop the server")
    try:
        # 保持程序运行
        while True:
            pass
    except KeyboardInterrupt:
        print("\nWeb server stopped")

def run_api_server():
    """运行 API 服务器"""
    print("Starting API Server...")
    try:
        subprocess.run([sys.executable, "main.py"])
    except Exception as e:
        print(f"Failed to start: {e}")

def run_data_collector():
    """直接运行数据采集脚本"""
    print("Running data collector...")
    try:
        subprocess.run([sys.executable, "collect_cves.py"])
    except Exception as e:
        print(f"Failed to run: {e}")

def main():
    """主函数"""
    print("=" * 60)
    print("CVE Vulnerability Monitoring System - Launcher")
    print("=" * 60)

    # 检查依赖
    if not check_dependencies():
        return

    while True:
        print("\nSelect a version to run:")
        print("1. Desktop GUI (tkinter)")
        print("2. Web Interface (browser)")
        print("3. API Server (FastAPI)")
        print("4. Data Collector Script")
        print("5. Open Data Directory")
        print("0. Exit")
        print("-" * 40)

        choice = input("Enter option (0-5): ").strip()

        if choice == "1":
            run_desktop_gui()
            break
        elif choice == "2":
            run_web_interface()
            break
        elif choice == "3":
            run_api_server()
            break
        elif choice == "4":
            run_data_collector()
            break
        elif choice == "5":
            # 打开数据目录
            data_dir = Path("cve_data")
            data_dir.mkdir(exist_ok=True)

            try:
                if sys.platform == "win32":
                    os.startfile(data_dir.absolute())
                elif sys.platform == "darwin":
                    subprocess.run(["open", str(data_dir.absolute())], check=True)
                else:
                    subprocess.run(["xdg-open", str(data_dir.absolute())], check=True)

                print(f"Opened data directory: {data_dir.absolute()}")
            except Exception as e:
                print(f"Failed to open data directory: {e}")
                print(f"Data directory location: {data_dir.absolute()}")

            continue
        elif choice == "0":
            print("Goodbye!")
            break
        else:
            print("Invalid option, please try again")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram exited")