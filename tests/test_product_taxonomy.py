"""
risk/product_taxonomy.py 单元测试

覆盖三个真实问题场景：
1. "an IAM" 抽取噪声 → 清洗回退到 ECS
2. "Dell Color Management Software" → 客户端外设产品线
3. "Dell PowerScale OneFS" → PowerScale/Isilon 产品线
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from risk.product_taxonomy import (
    is_noise_product,
    resolve_product_line,
    clean_product_name,
)


class TestNoiseDetection:
    """抽取噪声判定"""

    def test_an_iam_is_noise(self):
        assert is_noise_product("an IAM") is True

    def test_article_prefix_is_noise(self):
        assert is_noise_product("a vulnerability") is True
        assert is_noise_product("an vulnerability") is True

    def test_empty_is_noise(self):
        assert is_noise_product("") is True

    def test_real_product_not_noise(self):
        assert is_noise_product("Dell Color Management Software") is False
        assert is_noise_product("Dell PowerScale OneFS") is False
        assert is_noise_product("PowerEdge R740") is False


class TestProductLineResolution:
    """产品 → 产品线归属"""

    def test_color_management_to_client(self):
        line = resolve_product_line("Dell Color Management Software")
        assert line is not None
        assert "客户端" in line

    def test_onefs_to_powerscale(self):
        line = resolve_product_line("Dell PowerScale OneFS")
        assert line is not None
        assert "PowerScale" in line or "Isilon" in line

    def test_isilon_insightiq_to_powerscale(self):
        line = resolve_product_line("Dell Isilon InsightIQ")
        assert line is not None
        assert "PowerScale" in line or "Isilon" in line

    def test_ecs_resolves(self):
        line = resolve_product_line("Dell ECS")
        assert line is not None
        assert "ECS" in line

    def test_unknown_returns_none(self):
        assert resolve_product_line("Completely Unknown Widget XYZ") is None


class TestProductNameCleaning:
    """噪声清洗 + 标题回退"""

    def test_an_iam_recovers_to_ecs(self):
        cleaned = clean_product_name(
            "an IAM", "Dell ECS Security Update for an IAM Vulnerability"
        )
        assert cleaned == "Dell ECS"

    def test_an_iam_then_resolves_to_ecs_line(self):
        cleaned = clean_product_name(
            "an IAM", "Dell ECS Security Update for an IAM Vulnerability"
        )
        line = resolve_product_line(cleaned)
        assert line is not None
        assert "ECS" in line

    def test_noise_without_title_dropped(self):
        # 无标题上下文，噪声无法恢复 → None
        assert clean_product_name("an IAM", "") is None

    def test_legit_product_unchanged(self):
        name = "Dell Color Management Software"
        assert clean_product_name(name, "any title") == name


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
