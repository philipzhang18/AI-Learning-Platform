"""
全面性能测试 - SQLite vs Redis
测试单次查询、随机查询、并发查询、写入性能
"""
import time
import sqlite3
import json
import random
from pathlib import Path
from redis_manager import RedisDataManager
from concurrent.futures import ThreadPoolExecutor, as_completed


def test_single_query_sqlite(db_path, cve_id):
    """测试SQLite单次查询"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    start_time = time.time()
    cursor.execute("SELECT data FROM cves WHERE cve_id = ?", (cve_id,))
    result = cursor.fetchone()

    if result and result[0]:
        data = json.loads(result[0])

    elapsed = time.time() - start_time
    conn.close()

    return elapsed


def test_single_query_redis(redis_manager, cve_id):
    """测试Redis单次查询"""
    start_time = time.time()
    data = redis_manager.get_cve(cve_id)
    elapsed = time.time() - start_time

    return elapsed


def test_random_queries(db_path, redis_manager, num_queries=1000):
    """测试随机查询性能"""
    print(f"\n[随机查询测试] {num_queries} 次查询")
    print("=" * 80)

    # 获取所有CVE ID
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT cve_id FROM cves LIMIT 10000")
    all_ids = [row[0] for row in cursor.fetchall()]
    conn.close()

    # 随机选择
    test_ids = random.sample(all_ids, min(num_queries, len(all_ids)))

    # SQLite 测试
    print(f"\n[SQLite] 随机查询 {len(test_ids)} 次...")
    start_time = time.time()

    for cve_id in test_ids:
        test_single_query_sqlite(db_path, cve_id)

    sqlite_time = time.time() - start_time
    sqlite_qps = len(test_ids) / sqlite_time

    print(f"  总耗时: {sqlite_time:.3f}s")
    print(f"  QPS: {sqlite_qps:.1f} 查询/秒")
    print(f"  平均延迟: {sqlite_time/len(test_ids)*1000:.2f}ms")

    # Redis 测试
    print(f"\n[Redis] 随机查询 {len(test_ids)} 次...")
    start_time = time.time()

    for cve_id in test_ids:
        test_single_query_redis(redis_manager, cve_id)

    redis_time = time.time() - start_time
    redis_qps = len(test_ids) / redis_time

    print(f"  总耗时: {redis_time:.3f}s")
    print(f"  QPS: {redis_qps:.1f} 查询/秒")
    print(f"  平均延迟: {redis_time/len(test_ids)*1000:.2f}ms")

    # 对比
    speedup = sqlite_time / redis_time
    print(f"\n[对比]")
    print(f"  Redis vs SQLite: {speedup:.2f}x {'FASTER' if speedup > 1 else 'SLOWER'}")
    print(f"  Redis QPS 提升: {(redis_qps - sqlite_qps) / sqlite_qps * 100:+.1f}%")

    return {
        'sqlite_time': sqlite_time,
        'redis_time': redis_time,
        'sqlite_qps': sqlite_qps,
        'redis_qps': redis_qps,
        'speedup': speedup
    }


def test_concurrent_queries(db_path, redis_manager, num_queries=1000, workers=10):
    """测试并发查询性能"""
    print(f"\n[并发查询测试] {num_queries} 次查询，{workers} 个并发线程")
    print("=" * 80)

    # 获取测试ID
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT cve_id FROM cves LIMIT 10000")
    all_ids = [row[0] for row in cursor.fetchall()]
    conn.close()

    test_ids = random.sample(all_ids, min(num_queries, len(all_ids)))

    # Redis 并发测试（Redis更适合并发）
    print(f"\n[Redis] 并发查询 {len(test_ids)} 次（{workers} 线程）...")
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(test_single_query_redis, redis_manager, cve_id) for cve_id in test_ids]
        for future in as_completed(futures):
            future.result()

    redis_concurrent_time = time.time() - start_time
    redis_concurrent_qps = len(test_ids) / redis_concurrent_time

    print(f"  总耗时: {redis_concurrent_time:.3f}s")
    print(f"  QPS: {redis_concurrent_qps:.1f} 查询/秒")
    print(f"  平均延迟: {redis_concurrent_time/len(test_ids)*1000:.2f}ms")

    return {
        'redis_concurrent_time': redis_concurrent_time,
        'redis_concurrent_qps': redis_concurrent_qps
    }


def test_write_performance(db_path, redis_manager, num_writes=100):
    """测试写入性能"""
    print(f"\n[写入性能测试] {num_writes} 次写入")
    print("=" * 80)

    # 准备测试数据
    test_data = []
    for i in range(num_writes):
        test_data.append({
            'cve_id': f'CVE-TEST-{i:04d}',
            'description': f'Test CVE description {i}',
            'published_date': '2025-01-01',
            'severity': 'HIGH',
            'cvss_score': 7.5
        })

    # SQLite 写入测试
    print(f"\n[SQLite] 写入 {num_writes} 条记录...")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    start_time = time.time()
    for data in test_data:
        cursor.execute("""
            INSERT OR REPLACE INTO cves (cve_id, data, published_date)
            VALUES (?, ?, ?)
        """, (data['cve_id'], json.dumps(data), data['published_date']))
    conn.commit()
    sqlite_write_time = time.time() - start_time

    # 清理测试数据
    for data in test_data:
        cursor.execute("DELETE FROM cves WHERE cve_id = ?", (data['cve_id'],))
    conn.commit()
    conn.close()

    sqlite_wps = num_writes / sqlite_write_time
    print(f"  总耗时: {sqlite_write_time:.3f}s")
    print(f"  WPS: {sqlite_wps:.1f} 写入/秒")

    # Redis 写入测试
    print(f"\n[Redis] 写入 {num_writes} 条记录...")
    start_time = time.time()

    for data in test_data:
        redis_manager.store_cve(data)

    redis_write_time = time.time() - start_time

    # 清理测试数据
    for data in test_data:
        redis_manager.delete_cve(data['cve_id'])

    redis_wps = num_writes / redis_write_time
    print(f"  总耗时: {redis_write_time:.3f}s")
    print(f"  WPS: {redis_wps:.1f} 写入/秒")

    # 对比
    speedup = sqlite_write_time / redis_write_time
    print(f"\n[对比]")
    print(f"  Redis vs SQLite: {speedup:.2f}x {'FASTER' if speedup > 1 else 'SLOWER'}")
    print(f"  Redis WPS 提升: {(redis_wps - sqlite_wps) / sqlite_wps * 100:+.1f}%")

    return {
        'sqlite_write_time': sqlite_write_time,
        'redis_write_time': redis_write_time,
        'sqlite_wps': sqlite_wps,
        'redis_wps': redis_wps,
        'speedup': speedup
    }


def main():
    """主测试函数"""
    print("=" * 80)
    print("Redis 性能优化全面测试")
    print("=" * 80)

    # 配置
    sqlite_db_path = "cve_data/cve_database.db"
    redis_manager = RedisDataManager(password='defaultpassword')

    # 检查连接
    if not Path(sqlite_db_path).exists():
        print(f"[ERROR] SQLite database not found: {sqlite_db_path}")
        return

    if not redis_manager.ping():
        print(f"[ERROR] Redis connection failed")
        return

    print(f"\n[OK] SQLite database: {sqlite_db_path}")
    print(f"[OK] Redis connected: {redis_manager.host}:{redis_manager.port}")

    # 获取统计信息
    stats = redis_manager.get_stats()
    print(f"\n[Redis 状态]")
    print(f"  CVE 数量: {stats['cve_count']}")
    print(f"  内存占用: {stats['redis_info'].get('used_memory_human')}")

    # 运行测试
    results = {}

    # 1. 单次查询测试
    print("\n" + "=" * 80)
    cve_id = "CVE-2024-0001"
    sqlite_latency = test_single_query_sqlite(sqlite_db_path, cve_id) * 1000
    redis_latency = test_single_query_redis(redis_manager, cve_id) * 1000

    print(f"[单次查询测试] 查询 {cve_id}")
    print(f"  SQLite: {sqlite_latency:.2f}ms")
    print(f"  Redis:  {redis_latency:.2f}ms")
    print(f"  Redis 快 {sqlite_latency/redis_latency:.2f}x")

    # 2. 随机查询测试
    print("\n" + "=" * 80)
    results['random'] = test_random_queries(sqlite_db_path, redis_manager, num_queries=1000)

    # 3. 并发查询测试
    print("\n" + "=" * 80)
    results['concurrent'] = test_concurrent_queries(sqlite_db_path, redis_manager, num_queries=1000, workers=10)

    # 4. 写入性能测试
    print("\n" + "=" * 80)
    results['write'] = test_write_performance(sqlite_db_path, redis_manager, num_writes=100)

    # 最终总结
    print("\n" + "=" * 80)
    print("性能测试总结")
    print("=" * 80)

    print(f"\n[随机查询]")
    print(f"  Redis QPS: {results['random']['redis_qps']:.1f}")
    print(f"  SQLite QPS: {results['random']['sqlite_qps']:.1f}")
    print(f"  Redis 性能: {results['random']['speedup']:.2f}x")

    print(f"\n[并发查询] ({10} 线程)")
    print(f"  Redis QPS: {results['concurrent']['redis_concurrent_qps']:.1f}")
    print(f"  相比单线程提升: {results['concurrent']['redis_concurrent_qps'] / results['random']['redis_qps']:.2f}x")

    print(f"\n[写入性能]")
    print(f"  Redis WPS: {results['write']['redis_wps']:.1f}")
    print(f"  SQLite WPS: {results['write']['sqlite_wps']:.1f}")
    print(f"  Redis 性能: {results['write']['speedup']:.2f}x")

    print(f"\n[结论]")
    print(f"  ✓ Redis 适合：高并发读写、单次查询、实时数据访问")
    print(f"  ✓ SQLite 适合：批量读取、复杂SQL查询、单机应用")
    print(f"  ✓ 推荐：混合架构 (Redis缓存 + SQLite持久化)")

    redis_manager.close()


if __name__ == "__main__":
    main()
