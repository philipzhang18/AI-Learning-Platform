"""
测试缓存工具模块
"""
import pytest
import time
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from gui.utils.cache_utils import LRUCache, TTLCache, ttl_cache


class TestLRUCache:
    """测试 LRU 缓存"""

    def test_basic_put_get(self):
        cache = LRUCache(maxsize=10)
        cache.put("key1", "value1")
        assert cache.get("key1") == "value1"

    def test_default_value(self):
        cache = LRUCache(maxsize=10)
        assert cache.get("missing", "default") == "default"
        assert cache.get("missing") is None

    def test_lru_eviction(self):
        """LRU 淘汰策略"""
        cache = LRUCache(maxsize=3)
        cache.put("a", 1)
        cache.put("b", 2)
        cache.put("c", 3)

        # 访问 a，使其变为最近使用
        cache.get("a")

        # 添加新项，应淘汰 b（最少使用）
        cache.put("d", 4)

        assert cache.get("a") == 1
        assert cache.get("b") is None  # 已淘汰
        assert cache.get("c") == 3
        assert cache.get("d") == 4

    def test_remove(self):
        cache = LRUCache(maxsize=10)
        cache.put("key1", "value1")
        assert cache.remove("key1") is True
        assert cache.get("key1") is None
        assert cache.remove("missing") is False

    def test_clear(self):
        cache = LRUCache(maxsize=10)
        cache.put("a", 1)
        cache.put("b", 2)
        cache.clear()
        assert cache.get("a") is None
        assert cache.get("b") is None

    def test_stats(self):
        cache = LRUCache(maxsize=10)
        cache.put("key1", "value1")
        cache.get("key1")  # hit
        cache.get("key1")  # hit
        cache.get("missing")  # miss

        stats = cache.stats()
        assert stats["hits"] == 2
        assert stats["misses"] == 1
        assert stats["size"] == 1


class TestTTLCache:
    """测试 TTL 缓存"""

    def test_basic_operation(self):
        cache = TTLCache(maxsize=10, ttl=10.0)
        cache.put("key1", "value1")
        assert cache.get("key1") == "value1"

    def test_expiration(self):
        """超时自动失效"""
        cache = TTLCache(maxsize=10, ttl=0.1)
        cache.put("key1", "value1")
        assert cache.get("key1") == "value1"

        time.sleep(0.15)
        assert cache.get("key1") is None

    def test_custom_ttl(self):
        """自定义 TTL"""
        cache = TTLCache(maxsize=10, ttl=10.0)
        cache.put("key1", "value1", ttl=0.1)

        time.sleep(0.15)
        assert cache.get("key1") is None

    def test_cleanup_expired(self):
        """清理过期项"""
        cache = TTLCache(maxsize=10, ttl=0.1)
        cache.put("a", 1)
        cache.put("b", 2)

        time.sleep(0.15)
        cache.put("c", 3, ttl=10.0)  # 不过期

        expired = cache.cleanup_expired()
        # cleanup 后只保留 c
        assert cache.get("a") is None
        assert cache.get("b") is None
        assert cache.get("c") == 3


class TestTtlCacheDecorator:
    """测试 TTL 缓存装饰器"""

    def test_basic_caching(self):
        call_count = 0

        @ttl_cache(ttl=10.0)
        def expensive_func(x):
            nonlocal call_count
            call_count += 1
            return x * 2

        # 第一次调用
        assert expensive_func(5) == 10
        assert call_count == 1

        # 第二次调用使用缓存
        assert expensive_func(5) == 10
        assert call_count == 1

        # 不同参数
        assert expensive_func(10) == 20
        assert call_count == 2

    def test_cache_expiration(self):
        call_count = 0

        @ttl_cache(ttl=0.1)
        def expensive_func(x):
            nonlocal call_count
            call_count += 1
            return x

        expensive_func(1)
        expensive_func(1)
        assert call_count == 1

        time.sleep(0.15)
        expensive_func(1)
        assert call_count == 2

    def test_cache_clear(self):
        call_count = 0

        @ttl_cache(ttl=10.0)
        def expensive_func(x):
            nonlocal call_count
            call_count += 1
            return x

        expensive_func(1)
        expensive_func(1)
        assert call_count == 1

        expensive_func.cache_clear()
        expensive_func(1)
        assert call_count == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
