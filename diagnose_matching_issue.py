"""
CVE-Dell关联数显示为0的问题诊断脚本
"""
import sqlite3
import json

def diagnose_matching_issue():
    """诊断CVE-Dell关联匹配问题"""

    print("=" * 80)
    print("CVE-Dell 关联数显示问题诊断")
    print("=" * 80)
    print()

    conn = sqlite3.connect('cve_data/cve_database.db')
    cursor = conn.cursor()

    # 1. 数据库统计
    print("【1】数据库数据统计")
    print("-" * 40)

    cursor.execute('SELECT COUNT(*) FROM dell_advisories')
    dell_count = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM cves')
    cve_count = cursor.fetchone()[0]

    print(f"  Dell安全公告: {dell_count:,} 条")
    print(f"  CVE记录: {cve_count:,} 条")
    print()

    # 2. 提取Dell公告中的所有CVE IDs
    print("【2】Dell公告中的CVE IDs分析")
    print("-" * 40)

    cursor.execute('SELECT data FROM dell_advisories')
    records = cursor.fetchall()

    all_dell_cve_ids = set()
    for record in records:
        try:
            data = json.loads(record[0])
            cve_ids = data.get('cve_ids', [])
            all_dell_cve_ids.update(cve_ids)
        except:
            pass

    print(f"  Dell公告中的唯一CVE IDs: {len(all_dell_cve_ids):,} 个")
    print()

    # 3. 数据库关联匹配分析
    print("【3】数据库关联匹配分析（真实情况）")
    print("-" * 40)

    cursor.execute('SELECT cve_id FROM cves')
    all_cve_ids_in_db = set(row[0] for row in cursor.fetchall())

    matched_in_db = all_dell_cve_ids & all_cve_ids_in_db
    unmatched_in_db = all_dell_cve_ids - all_cve_ids_in_db

    print(f"  在CVE表中找到的: {len(matched_in_db):,} 个")
    print(f"  在CVE表中未找到的: {len(unmatched_in_db):,} 个")
    print(f"  匹配率: {len(matched_in_db)/len(all_dell_cve_ids)*100:.1f}%")
    print()

    # 4. 模拟GUI内存状态
    print("【4】模拟GUI内存状态（问题所在）")
    print("-" * 40)

    # 模拟初始化后的状态
    cve_data_memory = []  # GUI初始化时，cve_data为空
    dell_advisories_memory = []  # Dell数据会自动加载

    # 加载Dell数据到内存（模拟load_local_data）
    cursor.execute('SELECT data FROM dell_advisories')
    records = cursor.fetchall()
    for record in records:
        try:
            if record[0]:
                data = json.loads(record[0])
                dell_advisories_memory.append(data)
        except:
            pass

    print(f"  内存中的CVE数据: {len(cve_data_memory)} 条  ← 问题所在！")
    print(f"  内存中的Dell数据: {len(dell_advisories_memory)} 条")
    print()

    # 5. 模拟update_stats()的关联计算
    print("【5】模拟update_stats()关联计算（当前逻辑）")
    print("-" * 40)

    # 这是当前代码的逻辑（cve_integrated_gui.py:2803）
    cve_ids_set = {cve.get("cve_id", "") for cve in cve_data_memory}

    matched_cves = set()
    for advisory in dell_advisories_memory:
        advisory_cve_ids = advisory.get("cve_ids", [])
        for cve_id in advisory_cve_ids:
            if cve_id in cve_ids_set:
                matched_cves.add(cve_id)

    matched_count = len(matched_cves)

    print(f"  CVE ID集合大小: {len(cve_ids_set)} 个")
    print(f"  计算的关联数: {matched_count} 个  ← 这就是显示为0的原因！")
    print()

    # 6. 问题总结
    print("【6】问题总结")
    print("-" * 40)
    print("  🔴 问题根源:")
    print("     - update_stats()方法使用内存中的self.cve_data计算关联")
    print("     - 初始化时，self.cve_data为空列表（性能优化）")
    print("     - 导致关联计算结果为0")
    print()
    print("  📊 实际情况:")
    print(f"     - 数据库中实际有 {len(matched_in_db):,} 个匹配的CVE")
    print(f"     - 但界面显示为 0 个")
    print()
    print("  💡 解决方案:")
    print("     方案1: 修改update_stats()从数据库计算关联（推荐）")
    print("     方案2: 用户手动点击'从数据库加载'按钮加载CVE数据")
    print("     方案3: 初始化时自动加载部分CVE数据用于关联计算")
    print()

    # 7. 修复验证
    print("【7】修复后的预期结果")
    print("-" * 40)
    print(f"  期望的关联数显示: {len(matched_in_db):,} 个")
    print(f"  对应的Dell公告数: {dell_count:,} 条")
    print(f"  关联匹配率: {len(matched_in_db)/len(all_dell_cve_ids)*100:.1f}%")
    print()

    conn.close()

    print("=" * 80)
    print("诊断完成！")
    print("=" * 80)

if __name__ == "__main__":
    diagnose_matching_issue()
