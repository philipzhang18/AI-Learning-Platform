#!/bin/bash

# 获取 CVE 文件夹中所有文件和文件夹
echo "正在获取 CVE 文件夹中的所有内容..."

# 递归删除所有文件
function delete_contents() {
    local path=$1

    # 获取当前路径下的所有内容
    contents=$(gh api "repos/philipzhang18/CVE-Security-Solution/contents/$path" 2>/dev/null)

    if [ $? -ne 0 ]; then
        echo "无法访问路径: $path"
        return
    fi

    # 解析 JSON 并处理每个项目
    echo "$contents" | jq -r '.[] | "\(.type)|\(.path)|\(.sha)"' | while IFS='|' read -r type item_path sha; do
        if [ "$type" = "file" ]; then
            echo "删除文件: $item_path"
            gh api -X DELETE "repos/philipzhang18/CVE-Security-Solution/contents/$item_path" \
                -f message="Remove CVE folder - delete $item_path" \
                -f branch=master \
                -f sha="$sha" > /dev/null 2>&1

            if [ $? -eq 0 ]; then
                echo "  ✓ 已删除: $item_path"
            else
                echo "  ✗ 删除失败: $item_path"
            fi
            # API 限速保护
            sleep 1
        elif [ "$type" = "dir" ]; then
            echo "进入目录: $item_path"
            delete_contents "$item_path"
        fi
    done
}

# 开始删除
delete_contents "CVE"

echo "完成！CVE 文件夹的内容已删除。"
