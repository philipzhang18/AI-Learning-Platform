"""
诊断Dell数据加载问题
模拟GUI的Dell数据加载过程
"""
import sys
import os
import io
import json
import sqlite3

# 设置UTF-8输出
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

sys.path.insert(0, 'D:/AI/Claude/CVE')
os.chdir('D:/AI/Claude/CVE')

# 设置SQLite模式
os.environ['USE_SQLITE_ONLY'] = '1'
os.environ['REDIS_HOST'] = ''

print("=" * 70)
print("Dell数据加载诊断")
print("=" * 70)

# 方法1: 直接查询数据库
print("\n[方法1] 直接从数据库查询")
print("-" * 70)

db = sqlite3.connect('cve_data/cve_database.db')
cursor = db.cursor()
cursor.execute("SELECT data FROM dell_advisories ORDER BY published_date DESC")
records = cursor.fetchall()

dell_advisories_method1 = []
for record in records:
    try:
        if record[0]:
            data = json.loads(record[0])
            dell_advisories_method1.append(data)
    except json.JSONDecodeError as e:
        print(f"  JSON解析错误: {e}")
        continue

print(f"加载结果: {len(dell_advisories_method1)} 条记录")
print(f"前5条记录:")
for i, advisory in enumerate(dell_advisories_method1[:5], 1):
    dsa_id = advisory.get("dell_security_advisory", "N/A")
    title = advisory.get("title", "N/A")[:50]
    print(f"  {i}. {dsa_id} - {title}...")

db.close()

# 方法2: 使用GUI的load_dell_from_database方法
print("\n[方法2] 使用GUI类的加载方法")
print("-" * 70)

import tkinter as tk
from cve_integrated_gui import CVEIntegratedGUI

root = tk.Tk()
root.withdraw()

app = CVEIntegratedGUI(root)

# 调用加载方法前先清空
app.dell_advisories = []

# 手动执行加载逻辑（模拟load_dell_from_database）
cursor = app.conn.cursor()
cursor.execute("SELECT data FROM dell_advisories ORDER BY published_date DESC")
records = cursor.fetchall()

for record in records:
    try:
        if record[0]:
            data = json.loads(record[0])
            app.dell_advisories.append(data)
    except json.JSONDecodeError:
        continue

print(f"加载到app.dell_advisories: {len(app.dell_advisories)} 条记录")

# 检查树视图中的项目数
tree_items = app.dell_tree.get_children()
print(f"树视图中的项目数: {len(tree_items)}")

# 方法3: 检查实际的load_dell_from_database方法
print("\n[方法3] 调用实际的load_dell_from_database方法")
print("-" * 70)

# 清空并重新加载
for item in app.dell_tree.get_children():
    app.dell_tree.delete(item)
app.dell_advisories = []

# 调用实际方法
app.load_dell_from_database()

print(f"加载后app.dell_advisories: {len(app.dell_advisories)} 条记录")
tree_items = app.dell_tree.get_children()
print(f"加载后树视图项目数: {len(tree_items)}")

# 详细检查树视图内容
if len(tree_items) < 20:
    print(f"\n树视图中的所有项目:")
    for i, item in enumerate(tree_items, 1):
        values = app.dell_tree.item(item)['values']
        print(f"  {i}. {values[0]} - {values[1][:40]}...")

# 检查是否有过滤条件
print(f"\n搜索框内容: '{app.dell_search_var.get()}'")

# 方法4: 检查是否是过滤问题
print("\n[方法4] 测试过滤功能")
print("-" * 70)

# 清空搜索框并重新加载
app.dell_search_var.set("")
app.filter_dell_data()

tree_items_after_clear = app.dell_tree.get_children()
print(f"清空搜索框后树视图项目数: {len(tree_items_after_clear)}")

app.close_database_connection()
root.destroy()

print("\n" + "=" * 70)
print("诊断完成")
print("=" * 70)
