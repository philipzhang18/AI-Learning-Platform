"""
测试 cve_utils 模块
"""
import pytest
import sys
from pathlib import Path

# 添加项目根目录到 sys.path
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from cve_utils import clean_cve_ids


class TestCleanCveIds:
    """测试 clean_cve_ids 函数"""

    def test_single_cve_id(self):
        """单个 CVE ID"""
        assert clean_cve_ids("CVE-2024-1234") == ["CVE-2024-1234"]

    def test_lowercase_to_uppercase(self):
        """小写转大写"""
        assert clean_cve_ids("cve-2024-1234") == ["CVE-2024-1234"]

    def test_mixed_case(self):
        """混合大小写"""
        assert clean_cve_ids("Cve-2024-1234") == ["CVE-2024-1234"]

    def test_multiple_cves(self):
        """多个 CVE ID"""
        text = "CVE-2024-1234 and CVE-2024-5678"
        result = clean_cve_ids(text)
        assert "CVE-2024-1234" in result
        assert "CVE-2024-5678" in result
        assert len(result) == 2

    def test_duplicates_removed(self):
        """重复项去重"""
        text = "CVE-2024-1234 CVE-2024-1234 cve-2024-1234"
        assert clean_cve_ids(text) == ["CVE-2024-1234"]

    def test_sorted_output(self):
        """输出按字典序排序"""
        text = "CVE-2024-9999 CVE-2024-1111 CVE-2024-5555"
        result = clean_cve_ids(text)
        assert result == sorted(result)

    def test_empty_input(self):
        """空输入"""
        assert clean_cve_ids("") == []
        assert clean_cve_ids(None) == []

    def test_no_cve_in_text(self):
        """文本中无 CVE ID"""
        assert clean_cve_ids("This is just plain text") == []

    def test_long_cve_id(self):
        """长 CVE ID（7 位数字）"""
        text = "CVE-2024-1234567"
        assert clean_cve_ids(text) == ["CVE-2024-1234567"]

    def test_list_input(self):
        """列表输入"""
        cve_list = ["CVE-2024-1234", "cve-2024-5678", "CVE-2024-1234"]
        result = clean_cve_ids(cve_list)
        assert "CVE-2024-1234" in result
        assert "CVE-2024-5678" in result
        assert len(result) == 2

    def test_set_input(self):
        """集合输入"""
        cve_set = {"CVE-2024-1234", "CVE-2024-5678"}
        result = clean_cve_ids(cve_set)
        assert len(result) == 2

    def test_invalid_format(self):
        """无效格式（不会被识别）"""
        assert clean_cve_ids("CVE-24-1234") == []  # 年份只有2位
        assert clean_cve_ids("CVE-2024-12") == []  # 数字不足4位

    def test_with_punctuation(self):
        """混杂标点"""
        text = "Found CVE-2024-1234, CVE-2024-5678; and CVE-2024-9999."
        result = clean_cve_ids(text)
        assert len(result) == 3

    def test_in_url(self):
        """嵌入 URL 中"""
        text = "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
        assert clean_cve_ids(text) == ["CVE-2024-1234"]


class TestCleanCveIdsEdgeCases:
    """边界情况测试"""

    def test_unicode_text(self):
        """Unicode 文本"""
        text = "漏洞 CVE-2024-1234 是一个高危漏洞"
        assert clean_cve_ids(text) == ["CVE-2024-1234"]

    def test_very_long_text(self):
        """长文本性能"""
        text = "Some text " * 1000 + "CVE-2024-1234"
        result = clean_cve_ids(text)
        assert "CVE-2024-1234" in result

    def test_many_cves(self):
        """大量 CVE ID"""
        cves = " ".join(f"CVE-2024-{i:04d}" for i in range(100))
        result = clean_cve_ids(cves)
        assert len(result) == 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
