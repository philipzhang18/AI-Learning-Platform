"""
用户偏好管理
持久化用户配置（窗口大小、列宽、主题、语言等）

使用示例:
    from user_preferences import UserPreferences

    prefs = UserPreferences()

    # 读取
    window_size = prefs.get("window.size", "1400x900")
    columns = prefs.get("nvd_tab.column_widths", {})

    # 写入（自动保存）
    prefs.set("window.size", "1600x1000")
    prefs.set("theme", "dark")

    # 批量更新
    prefs.update({
        "window.size": "1800x1200",
        "language": "en_US",
    })
"""
import json
import threading
from pathlib import Path
from typing import Any, Dict, Optional


class UserPreferences:
    """用户偏好管理器

    特性:
    - 自动保存到 JSON 文件
    - 支持嵌套键（dot notation）
    - 线程安全
    - 默认值支持
    """

    def __init__(
        self,
        config_path: Optional[Path] = None,
        defaults: Optional[Dict[str, Any]] = None,
        auto_save: bool = True,
    ):
        """
        Args:
            config_path: 配置文件路径，默认 .user_preferences.json
            defaults: 默认配置
            auto_save: 是否自动保存
        """
        if config_path is None:
            config_path = Path.home() / ".cve_app_preferences.json"

        self.config_path = Path(config_path)
        self.auto_save = auto_save
        self.lock = threading.Lock()

        # 加载默认配置
        self._defaults = defaults or self._get_defaults()

        # 加载配置
        self._prefs = self._load()

    def _get_defaults(self) -> Dict[str, Any]:
        """获取默认配置"""
        return {
            "window": {
                "size": "1400x900",
                "position": "+100+100",
                "maximized": False,
            },
            "theme": "light",
            "language": "zh_CN",
            "tabs": {
                "default": "nvd",
                "remember_last": True,
                "last_tab": "nvd",
            },
            "tree_columns": {
                "nvd_tab": {},
                "dell_tab": {},
                "matched_tab": {},
            },
            "data": {
                "auto_backup": True,
                "backup_interval_hours": 24,
                "max_backups": 30,
                "page_size": 100,
            },
            "ai": {
                "default_model": "qwen",
                "qwen_model": "qwen-plus",
                "stream_output": True,
                "show_thinking": False,
            },
            "notifications": {
                "show_progress": True,
                "sound_enabled": False,
            },
        }

    def _load(self) -> Dict[str, Any]:
        """加载配置文件"""
        if not self.config_path.exists():
            return dict(self._defaults)

        try:
            content = self.config_path.read_text(encoding='utf-8')
            user_prefs = json.loads(content)
            # 合并默认值（递归）
            return self._deep_merge(self._defaults, user_prefs)
        except Exception as e:
            print(f"⚠️  加载用户偏好失败: {e}，使用默认配置")
            return dict(self._defaults)

    def save(self):
        """保存到文件"""
        with self.lock:
            try:
                self.config_path.parent.mkdir(parents=True, exist_ok=True)
                self.config_path.write_text(
                    json.dumps(self._prefs, indent=2, ensure_ascii=False),
                    encoding='utf-8'
                )
            except Exception as e:
                print(f"❌ 保存用户偏好失败: {e}")

    def get(self, key: str, default: Any = None) -> Any:
        """获取配置值

        支持嵌套键: get("window.size")

        Args:
            key: 键名（支持 dot notation）
            default: 默认值

        Returns:
            配置值
        """
        with self.lock:
            keys = key.split('.')
            value = self._prefs

            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return default

            return value

    def set(self, key: str, value: Any):
        """设置配置值

        支持嵌套键: set("window.size", "1600x1000")

        Args:
            key: 键名（支持 dot notation）
            value: 值
        """
        with self.lock:
            keys = key.split('.')
            target = self._prefs

            # 导航到父级
            for k in keys[:-1]:
                if k not in target or not isinstance(target[k], dict):
                    target[k] = {}
                target = target[k]

            # 设置值
            target[keys[-1]] = value

        if self.auto_save:
            self.save()

    def update(self, updates: Dict[str, Any]):
        """批量更新

        Args:
            updates: {键: 值, ...}
        """
        for key, value in updates.items():
            self.set(key, value)

    def reset(self):
        """重置为默认值"""
        with self.lock:
            self._prefs = dict(self._defaults)
        if self.auto_save:
            self.save()

    def export_to_file(self, path: Path):
        """导出配置到指定文件"""
        with self.lock:
            Path(path).write_text(
                json.dumps(self._prefs, indent=2, ensure_ascii=False),
                encoding='utf-8'
            )

    def import_from_file(self, path: Path):
        """从文件导入配置"""
        try:
            content = Path(path).read_text(encoding='utf-8')
            with self.lock:
                imported = json.loads(content)
                self._prefs = self._deep_merge(self._defaults, imported)
            if self.auto_save:
                self.save()
            return True
        except Exception as e:
            print(f"❌ 导入配置失败: {e}")
            return False

    @staticmethod
    def _deep_merge(base: dict, overlay: dict) -> dict:
        """递归合并两个字典"""
        result = dict(base)
        for key, value in overlay.items():
            if (key in result and isinstance(result[key], dict)
                    and isinstance(value, dict)):
                result[key] = UserPreferences._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def all(self) -> Dict[str, Any]:
        """获取全部配置（副本）"""
        with self.lock:
            return json.loads(json.dumps(self._prefs))


# 全局单例
_global_prefs: Optional[UserPreferences] = None
_prefs_lock = threading.Lock()


def get_preferences() -> UserPreferences:
    """获取全局偏好实例（单例）"""
    global _global_prefs
    if _global_prefs is None:
        with _prefs_lock:
            if _global_prefs is None:
                _global_prefs = UserPreferences()
    return _global_prefs
