"""
测试用户偏好模块
"""
import pytest
import sys
import json
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from user_preferences import UserPreferences


class TestUserPreferences:
    """测试用户偏好"""

    def test_create_with_defaults(self, tmp_path):
        """创建并使用默认值"""
        config = tmp_path / "prefs.json"
        prefs = UserPreferences(config_path=config, auto_save=False)

        assert prefs.get("language") == "zh_CN"
        assert prefs.get("theme") == "light"
        assert prefs.get("window.size") == "1400x900"

    def test_default_value(self, tmp_path):
        """默认值返回"""
        config = tmp_path / "prefs.json"
        prefs = UserPreferences(config_path=config, auto_save=False)

        assert prefs.get("nonexistent", "default_val") == "default_val"
        assert prefs.get("nonexistent.nested.key") is None

    def test_set_and_get(self, tmp_path):
        """设置和获取"""
        config = tmp_path / "prefs.json"
        prefs = UserPreferences(config_path=config, auto_save=False)

        prefs.set("theme", "dark")
        assert prefs.get("theme") == "dark"

    def test_nested_keys(self, tmp_path):
        """嵌套键"""
        config = tmp_path / "prefs.json"
        prefs = UserPreferences(config_path=config, auto_save=False)

        prefs.set("window.size", "1600x1000")
        assert prefs.get("window.size") == "1600x1000"

        prefs.set("custom.deep.key", "value")
        assert prefs.get("custom.deep.key") == "value"

    def test_save_and_reload(self, tmp_path):
        """保存后重新加载"""
        config = tmp_path / "prefs.json"

        prefs1 = UserPreferences(config_path=config, auto_save=False)
        prefs1.set("theme", "dark")
        prefs1.set("window.size", "1800x1200")
        prefs1.save()

        # 重新加载
        prefs2 = UserPreferences(config_path=config, auto_save=False)
        assert prefs2.get("theme") == "dark"
        assert prefs2.get("window.size") == "1800x1200"

    def test_auto_save(self, tmp_path):
        """自动保存"""
        config = tmp_path / "prefs.json"

        prefs1 = UserPreferences(config_path=config, auto_save=True)
        prefs1.set("theme", "dark")

        # 文件应已写入
        assert config.exists()
        content = json.loads(config.read_text(encoding='utf-8'))
        assert content["theme"] == "dark"

    def test_update_batch(self, tmp_path):
        """批量更新"""
        config = tmp_path / "prefs.json"
        prefs = UserPreferences(config_path=config, auto_save=False)

        prefs.update({
            "theme": "dark",
            "language": "en_US",
            "window.size": "1600x1000",
        })

        assert prefs.get("theme") == "dark"
        assert prefs.get("language") == "en_US"
        assert prefs.get("window.size") == "1600x1000"

    def test_reset(self, tmp_path):
        """重置为默认值"""
        config = tmp_path / "prefs.json"
        prefs = UserPreferences(config_path=config, auto_save=False)

        prefs.set("theme", "dark")
        assert prefs.get("theme") == "dark"

        prefs.reset()
        assert prefs.get("theme") == "light"

    def test_export_import(self, tmp_path):
        """导入导出"""
        config = tmp_path / "prefs.json"
        export = tmp_path / "exported.json"

        prefs1 = UserPreferences(config_path=config, auto_save=False)
        prefs1.set("theme", "dark")
        prefs1.set("custom.key", "value")
        prefs1.export_to_file(export)

        # 新建实例并导入
        prefs2 = UserPreferences(
            config_path=tmp_path / "other.json",
            auto_save=False
        )
        assert prefs2.get("theme") == "light"

        prefs2.import_from_file(export)
        assert prefs2.get("theme") == "dark"
        assert prefs2.get("custom.key") == "value"

    def test_corrupted_config(self, tmp_path):
        """配置文件损坏时使用默认值"""
        config = tmp_path / "prefs.json"
        config.write_text("not valid json {{{")

        prefs = UserPreferences(config_path=config, auto_save=False)
        # 使用默认值
        assert prefs.get("theme") == "light"

    def test_deep_merge(self, tmp_path):
        """深度合并配置"""
        config = tmp_path / "prefs.json"

        # 写入部分自定义配置
        config.write_text(json.dumps({
            "theme": "dark",
            "window": {
                "size": "1600x1000"
                # 缺少 position 和 maximized
            }
        }))

        prefs = UserPreferences(config_path=config, auto_save=False)

        # 自定义值
        assert prefs.get("theme") == "dark"
        assert prefs.get("window.size") == "1600x1000"
        # 默认值（从默认配置合并）
        assert prefs.get("window.position") == "+100+100"
        assert prefs.get("window.maximized") is False
        assert prefs.get("language") == "zh_CN"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
