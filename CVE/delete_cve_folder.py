#!/usr/bin/env python3
"""
删除远程仓库中的 CVE 文件夹
"""

import subprocess
import json
import time

def run_gh_command(cmd):
    """执行 gh 命令"""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            return json.loads(result.stdout) if result.stdout else None
        else:
            print(f"命令执行失败: {cmd}")
            print(f"错误: {result.stderr}")
            return None
    except Exception as e:
        print(f"执行命令时出错: {e}")
        return None

def delete_file(file_path, sha):
    """删除单个文件"""
    cmd = f'''gh api -X DELETE repos/philipzhang18/CVE-Security-Solution/contents/{file_path} \
        -f message="Remove CVE folder - delete {file_path}" \
        -f branch=master \
        -f sha="{sha}"'''

    result = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=30
    )

    return result.returncode == 0

def delete_directory_contents(path):
    """递归删除目录内容"""
    print(f"正在处理目录: {path}")

    # 获取目录内容
    cmd = f'gh api repos/philipzhang18/CVE-Security-Solution/contents/{path}'
    contents = run_gh_command(cmd)

    if not contents:
        print(f"无法获取目录内容: {path}")
        return

    # 先处理所有子目录
    directories = [item for item in contents if item['type'] == 'dir']
    for item in directories:
        delete_directory_contents(item['path'])

    # 再删除文件
    files = [item for item in contents if item['type'] == 'file']
    for item in files:
        file_path = item['path']
        sha = item['sha']
        print(f"删除文件: {file_path}")

        if delete_file(file_path, sha):
            print(f"  ✓ 已删除: {file_path}")
        else:
            print(f"  ✗ 删除失败: {file_path}")

        # API 限速保护
        time.sleep(0.5)

def main():
    """主函数"""
    print("=" * 60)
    print("开始删除 CVE 文件夹中的所有内容...")
    print("=" * 60)

    delete_directory_contents("CVE")

    print("=" * 60)
    print("完成！CVE 文件夹的内容已删除。")
    print("=" * 60)

if __name__ == "__main__":
    main()
