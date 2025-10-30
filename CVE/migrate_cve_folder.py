#!/usr/bin/env python3
"""
CVE 文件夹迁移脚本
通过 GitHub API 将 CVE 文件夹中的所有文件删除
"""

import subprocess
import json
import time
import sys

REPO = "philipzhang18/CVE-Security-Solution"
BRANCH = "master"

def run_command(cmd, capture_output=True):
    """执行命令"""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=capture_output,
            text=True,
            timeout=30,
            encoding='utf-8',
            errors='ignore'
        )
        if capture_output and result.returncode == 0 and result.stdout:
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return result.stdout
        return None
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        return None

def get_contents(path):
    """获取目录或文件内容"""
    cmd = f'gh api repos/{REPO}/contents/{path}'
    return run_command(cmd)

def delete_file(file_path, sha):
    """删除单个文件"""
    cmd = f'''gh api -X DELETE repos/{REPO}/contents/{file_path} ^
        -f message="Remove CVE folder - delete {file_path}" ^
        -f branch={BRANCH} ^
        -f sha="{sha}"'''

    result = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=30,
        encoding='utf-8',
        errors='ignore'
    )

    return result.returncode == 0

def collect_all_files(path, files_list):
    """递归收集所有文件"""
    contents = get_contents(path)

    if not contents or not isinstance(contents, list):
        return

    for item in contents:
        if item['type'] == 'file':
            files_list.append({
                'path': item['path'],
                'sha': item['sha'],
                'name': item['name']
            })
        elif item['type'] == 'dir':
            collect_all_files(item['path'], files_list)

def main():
    """主函数"""
    print("=" * 70)
    print("CVE 文件夹迁移脚本")
    print("=" * 70)
    print()

    # 第一步：收集所有文件
    print("[1/3] 正在收集 CVE 文件夹中的所有文件...")
    all_files = []
    collect_all_files("CVE", all_files)

    if not all_files:
        print("  ✓ CVE 文件夹已经为空或不存在")
        return

    print(f"  ✓ 找到 {len(all_files)} 个文件")
    print()

    # 第二步：删除所有文件
    print(f"[2/3] 正在删除 {len(all_files)} 个文件...")
    print("      这可能需要几分钟，请耐心等待...")
    print()

    success_count = 0
    failed_count = 0

    for i, file in enumerate(all_files, 1):
        file_path = file['path']
        sha = file['sha']

        print(f"  [{i}/{len(all_files)}] 删除: {file_path}")

        if delete_file(file_path, sha):
            success_count += 1
            print(f"      ✓ 成功")
        else:
            failed_count += 1
            print(f"      ✗ 失败")

        # API 限速保护
        time.sleep(0.8)

    print()
    print("[3/3] 删除完成")
    print(f"      成功: {success_count} 个文件")
    print(f"      失败: {failed_count} 个文件")
    print()

    # 验证
    print("正在验证...")
    remaining = get_contents("CVE")
    if not remaining or not isinstance(remaining, list) or len(remaining) == 0:
        print("  ✓ CVE 文件夹已清空")
    else:
        print(f"  ! 还剩 {len(remaining)} 个项目未删除")

    print()
    print("=" * 70)
    print("迁移完成！")
    print("=" * 70)
    print()
    print("下一步：")
    print("1. 访问 GitHub 仓库确认更改")
    print("2. 同步本地仓库：git fetch origin")
    print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        print("操作已取消")
        sys.exit(1)
    except Exception as e:
        print(f"发生错误: {e}", file=sys.stderr)
        sys.exit(1)
