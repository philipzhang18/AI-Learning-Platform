import json

from dell_security_scraper import DellSecurityScraper
from redis_manager import RedisDataManager


class FakeRedisClient:
    def __init__(self, values=None):
        self.values = values or {}

    def get(self, key):
        return self.values.get(key)

    def smembers(self, key):
        return set()

    def scard(self, key):
        return 0

    def zrange(self, key, start, end, withscores=False):
        return []

    def info(self):
        return {}


class TestDellSeverityExtraction:
    def test_extract_impact_from_explicit_label(self):
        scraper = DellSecurityScraper()
        content = "Impact: Critical\nSummary\nSomething happened"
        assert scraper._extract_impact(content) == "Critical"

    def test_extract_impact_from_summary_keyword(self):
        scraper = DellSecurityScraper()
        content = "Summary\nThis is a High severity update for multiple vulnerabilities."
        assert scraper._extract_impact(content) == "High"

    def test_extract_impact_from_cvss_score(self):
        scraper = DellSecurityScraper()
        content = "CVSS Base Score: 8.8"
        assert scraper._extract_impact(content) == "High"

    def test_extract_impact_from_html_attribute(self):
        scraper = DellSecurityScraper()
        html = '<div data-severity="Medium">alert</div>'
        assert scraper._extract_impact("", html) == "Medium"


class TestRedisCacheStats:
    def create_manager(self, values=None):
        manager = RedisDataManager.__new__(RedisDataManager)
        manager.CVE_PREFIX = "cve:"
        manager.DELL_PREFIX = "dell:"
        manager.CVE_SET = "cve:all_ids"
        manager.DELL_SET = "dell:all_ids"
        manager.COLLECTION_HISTORY = "collection:history"
        manager.cache_hits = 0
        manager.cache_misses = 0
        manager.redis_client = FakeRedisClient(values)
        return manager

    def test_get_cve_records_hit_and_miss(self):
        payload = {"cve_id": "CVE-2026-0001"}
        manager = self.create_manager({"cve:CVE-2026-0001": json.dumps(payload)})

        assert manager.get_cve("CVE-2026-0001") == payload
        assert manager.get_cve("CVE-2026-9999") is None

        stats = manager.get_cache_stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["total_requests"] == 2
        assert stats["hit_rate_float"] == 0.5

    def test_get_dell_advisory_records_hit(self):
        payload = {"dell_security_advisory": "DSA-2026-001"}
        manager = self.create_manager({"dell:DSA-2026-001": json.dumps(payload)})

        assert manager.get_dell_advisory("DSA-2026-001") == payload

        stats = manager.get_cache_stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 0
        assert stats["hit_rate"] == "100.00%"

    def test_reset_cache_stats(self):
        manager = self.create_manager()
        manager.cache_hits = 3
        manager.cache_misses = 2

        manager.reset_cache_stats()

        stats = manager.get_cache_stats()
        assert stats["hits"] == 0
        assert stats["misses"] == 0
        assert stats["hit_rate"] == "0.00%"
