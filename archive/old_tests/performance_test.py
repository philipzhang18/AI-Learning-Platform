"""
Performance Test: SQLite vs Redis
Compare data loading performance
"""
import time
import sqlite3
import json
from pathlib import Path
from redis_manager import RedisDataManager


def test_sqlite_performance(db_path, num_records=1000):
    """Test SQLite loading performance"""
    print(f"\n[SQLite Performance Test]")
    print(f"Loading {num_records} records...")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    start_time = time.time()

    cursor.execute(f"SELECT cve_id, data FROM cves LIMIT {num_records}")
    records = cursor.fetchall()

    cve_data = []
    for record in records:
        if record[1]:
            try:
                data = json.loads(record[1])
                cve_data.append(data)
            except:
                pass

    end_time = time.time()
    elapsed = end_time - start_time

    conn.close()

    print(f"  Records loaded: {len(cve_data)}")
    print(f"  Time: {elapsed:.3f} seconds")
    print(f"  Speed: {len(cve_data)/elapsed:.1f} records/sec")

    return elapsed, len(cve_data)


def test_redis_performance(redis_manager, num_records=1000):
    """Test Redis loading performance (using optimized bulk load)"""
    print(f"\n[Redis Performance Test]")
    print(f"Loading {num_records} records...")

    start_time = time.time()

    # Use optimized bulk load method (Pipeline)
    cve_data = redis_manager.get_all_cves(limit=num_records)

    end_time = time.time()
    elapsed = end_time - start_time

    print(f"  Records loaded: {len(cve_data)}")
    print(f"  Time: {elapsed:.3f} seconds")
    print(f"  Speed: {len(cve_data)/elapsed:.1f} records/sec")

    return elapsed, len(cve_data)


def test_bulk_load_redis(redis_manager):
    """Test Redis bulk loading (all records)"""
    print(f"\n[Redis Bulk Load Test]")

    start_time = time.time()
    all_cves = redis_manager.get_all_cves()
    end_time = time.time()
    elapsed = end_time - start_time

    print(f"  Records loaded: {len(all_cves)}")
    print(f"  Time: {elapsed:.3f} seconds")
    print(f"  Speed: {len(all_cves)/elapsed:.1f} records/sec")

    return elapsed, len(all_cves)


def main():
    """Main performance test"""
    print("=" * 80)
    print("SQLite vs Redis Performance Comparison")
    print("=" * 80)

    # Configuration
    sqlite_db_path = "cve_data/cve_database.db"
    redis_manager = RedisDataManager(password='defaultpassword')

    # Check connections
    if not Path(sqlite_db_path).exists():
        print(f"[ERROR] SQLite database not found: {sqlite_db_path}")
        return

    if not redis_manager.ping():
        print(f"[ERROR] Redis connection failed")
        return

    print(f"\n[OK] SQLite database: {sqlite_db_path}")
    print(f"[OK] Redis connected: {redis_manager.host}:{redis_manager.port}")

    # Get statistics
    stats = redis_manager.get_stats()
    print(f"\nRedis Stats:")
    print(f"  CVE count: {stats['cve_count']}")
    print(f"  Memory used: {stats['redis_info'].get('used_memory_human')}")

    # Run performance tests
    test_sizes = [100, 1000, 5000]

    results = {}
    for size in test_sizes:
        print(f"\n{'=' * 80}")
        print(f"Test Size: {size} records")
        print(f"{'=' * 80}")

        sqlite_time, sqlite_count = test_sqlite_performance(sqlite_db_path, size)
        redis_time, redis_count = test_redis_performance(redis_manager, size)

        speedup = sqlite_time / redis_time if redis_time > 0 else 0

        results[size] = {
            'sqlite_time': sqlite_time,
            'redis_time': redis_time,
            'speedup': speedup
        }

        print(f"\n[Summary for {size} records]")
        print(f"  SQLite: {sqlite_time:.3f}s")
        print(f"  Redis:  {redis_time:.3f}s")
        print(f"  Speedup: {speedup:.2f}x {'FASTER' if speedup > 1 else 'SLOWER'}")

    # Test bulk load
    print(f"\n{'=' * 80}")
    print(f"Bulk Load Test (All Records)")
    print(f"{'=' * 80}")
    test_bulk_load_redis(redis_manager)

    # Final summary
    print(f"\n{'=' * 80}")
    print(f"Performance Summary")
    print(f"{'=' * 80}")
    for size, result in results.items():
        print(f"{size:>5} records: Redis is {result['speedup']:.2f}x {'faster' if result['speedup'] > 1 else 'slower'} than SQLite")

    redis_manager.close()


if __name__ == "__main__":
    main()
