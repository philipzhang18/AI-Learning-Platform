"""
CVE GUI 截图工具
自动截取GUI界面的各个标签页
"""
import tkinter as tk
from PIL import ImageGrab, Image
import time
import os
from pathlib import Path

def capture_screenshots():
    """捕获GUI截图"""

    # 创建截图目录
    docs_dir = Path("docs/images")
    docs_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("CVE GUI 截图工具")
    print("=" * 60)
    print()

    # 等待用户准备
    print("请确保CVE GUI窗口可见并最大化")
    print("截图将在 5 秒后开始...")
    time.sleep(5)

    try:
        # 截取整个屏幕
        print("\n正在截取主界面...")
        screenshot = ImageGrab.grab()

        # 保存主界面截图
        main_screenshot_path = docs_dir / "main_interface.png"
        screenshot.save(main_screenshot_path, "PNG", optimize=True, quality=95)
        print(f"✓ 主界面截图已保存: {main_screenshot_path}")

        # 创建缩略图（用于README）
        thumbnail = screenshot.copy()
        thumbnail.thumbnail((1200, 800), Image.Resampling.LANCZOS)
        thumbnail_path = docs_dir / "screenshot.png"
        thumbnail.save(thumbnail_path, "PNG", optimize=True, quality=90)
        print(f"✓ 缩略图已保存: {thumbnail_path}")

        print("\n" + "=" * 60)
        print("截图完成！")
        print("=" * 60)
        print()
        print("截图文件：")
        print(f"  - 主界面: {main_screenshot_path}")
        print(f"  - 缩略图: {thumbnail_path}")
        print()
        print("建议手动截图以下标签页：")
        print("  1. 📊 NVD CVE 数据")
        print("  2. 🏢 Dell 安全公告")
        print("  3. 🔗 CVE-Dell 关联")
        print("  4. 📈 统计分析")
        print()
        print("使用 Windows 截图工具 (Win + Shift + S) 截取各标签页")

        return True

    except Exception as e:
        print(f"\n❌ 截图失败: {e}")
        print("\n备用方案：")
        print("1. 使用 Windows 截图工具: Win + Shift + S")
        print("2. 手动保存到: docs/images/screenshot.png")
        return False

if __name__ == "__main__":
    # 检查PIL是否安装
    try:
        from PIL import ImageGrab, Image
        capture_screenshots()
    except ImportError:
        print("=" * 60)
        print("需要安装 Pillow 库")
        print("=" * 60)
        print()
        print("请运行: pip install Pillow")
        print()
        print("或使用 Windows 截图工具手动截图:")
        print("  1. 按 Win + Shift + S")
        print("  2. 选择区域截图")
        print("  3. 保存到: docs/images/screenshot.png")
