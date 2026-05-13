"""
知识图谱性能基准测试

对比优化前后的性能提升：
1. 缓存加载速度 vs 构图速度
2. 快速查询 vs 原查询方法
3. 内存占用对比
"""
import time
import sys
import io
from pathlib import Path

# 修复 Windows 控制台编码问题
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# 添加项目根目录到 sys.path
ROOT = Path(__file__).parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from knowledge_graph import KnowledgeGraph


def benchmark_build_vs_cache():
    """测试构图速度 vs 缓存加载速度"""
    print("=" * 60)
    print("测试 1: 构图速度 vs 缓存加载速度")
    print("=" * 60)

    db_path = ROOT / "cve_data" / "cve_database.db"
    cache_path = ROOT / "cve_data" / "kg_benchmark_cache.pkl"

    # 删除旧缓存
    if cache_path.exists():
        cache_path.unlink()

    # 测试构图速度（限制 5000 条 CVE）
    print("\n[1/3] 构建知识图谱（limit_cve=5000）...")
    start = time.time()
    kg = KnowledgeGraph.from_sqlite(db_path)
    kg.build(limit_cve=5000, limit_dsa=500)
    build_time = time.time() - start
    print(f"✓ 构图完成，耗时: {build_time:.2f} 秒")

    stats = kg.stats()
    print(f"  - 节点总数: {stats['nodes_total']}")
    print(f"  - 边总数: {stats['edges_total']}")

    # 保存缓存
    print("\n[2/3] 保存缓存...")
    start = time.time()
    kg.save_cache(cache_path)
    save_time = time.time() - start
    print(f"✓ 缓存已保存，耗时: {save_time:.2f} 秒")
    print(f"  - 缓存文件大小: {cache_path.stat().st_size / 1024 / 1024:.2f} MB")

    # 测试缓存加载速度
    print("\n[3/3] 从缓存加载知识图谱...")
    start = time.time()
    kg2 = KnowledgeGraph.load_cache(cache_path)
    load_time = time.time() - start
    print(f"✓ 缓存加载完成，耗时: {load_time:.2f} 秒")

    # 对比结果
    print("\n" + "=" * 60)
    print("性能对比:")
    print("=" * 60)
    print(f"构图时间:     {build_time:.2f} 秒")
    print(f"缓存加载时间: {load_time:.2f} 秒")
    print(f"加速比:       {build_time / load_time:.1f}x")
    print(f"时间节省:     {(1 - load_time / build_time) * 100:.1f}%")

    return kg2


def benchmark_query_speed(kg):
    """测试快速查询 vs 原查询方法"""
    print("\n" + "=" * 60)
    print("测试 2: 快速查询 vs 原查询方法")
    print("=" * 60)

    # 获取测试样本
    cve_nodes = [n for n, attr in kg.G.nodes(data=True) if attr.get("type") == "cve"]
    if len(cve_nodes) < 100:
        print("⚠ CVE 节点数量不足，跳过查询性能测试")
        return

    test_cves = cve_nodes[:100]  # 测试前 100 个 CVE

    # 预热
    for cve in test_cves[:10]:
        kg.products_of_cve(cve)
        kg.products_of_cve_fast(cve)

    # 测试原方法（遍历图）
    print("\n[1/2] 测试原查询方法（遍历图）...")
    start = time.time()
    for cve in test_cves:
        kg.products_of_cve(cve)
    slow_time = time.time() - start
    print(f"✓ 完成 100 次查询，耗时: {slow_time:.4f} 秒")
    print(f"  - 平均每次查询: {slow_time / 100 * 1000:.2f} ms")

    # 测试快速方法（反向索引）
    print("\n[2/2] 测试快速查询方法（反向索引）...")
    start = time.time()
    for cve in test_cves:
        kg.products_of_cve_fast(cve)
    fast_time = time.time() - start
    print(f"✓ 完成 100 次查询，耗时: {fast_time:.4f} 秒")
    print(f"  - 平均每次查询: {fast_time / 100 * 1000:.2f} ms")

    # 对比结果
    print("\n" + "=" * 60)
    print("性能对比:")
    print("=" * 60)
    print(f"原方法耗时:   {slow_time:.4f} 秒 ({slow_time / 100 * 1000:.2f} ms/次)")
    print(f"快速方法耗时: {fast_time:.4f} 秒 ({fast_time / 100 * 1000:.2f} ms/次)")
    print(f"加速比:       {slow_time / fast_time:.1f}x")
    print(f"时间节省:     {(1 - fast_time / slow_time) * 100:.1f}%")


def benchmark_consistency(kg):
    """验证快速查询与原查询结果一致性"""
    print("\n" + "=" * 60)
    print("测试 3: 结果一致性验证")
    print("=" * 60)

    cve_nodes = [n for n, attr in kg.G.nodes(data=True) if attr.get("type") == "cve"]
    test_cves = cve_nodes[:50]  # 测试前 50 个 CVE

    print(f"\n验证 {len(test_cves)} 个 CVE 的查询结果一致性...")
    inconsistent = 0
    for cve in test_cves:
        products_slow = set(kg.products_of_cve(cve))
        products_fast = set(kg.products_of_cve_fast(cve))
        if products_slow != products_fast:
            inconsistent += 1
            print(f"⚠ 不一致: {cve}")
            print(f"  原方法: {products_slow}")
            print(f"  快速方法: {products_fast}")

    if inconsistent == 0:
        print(f"✓ 所有 {len(test_cves)} 个查询结果一致")
    else:
        print(f"✗ 发现 {inconsistent} 个不一致结果")


def main():
    print("\n" + "=" * 60)
    print("知识图谱性能基准测试")
    print("=" * 60)
    print()

    try:
        # 测试 1: 构图 vs 缓存加载
        kg = benchmark_build_vs_cache()

        # 测试 2: 查询速度
        benchmark_query_speed(kg)

        # 测试 3: 结果一致性
        benchmark_consistency(kg)

        print("\n" + "=" * 60)
        print("✓ 所有基准测试完成")
        print("=" * 60)

    except Exception as e:
        print(f"\n✗ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
