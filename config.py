"""
统一配置模块
集中管理颜色、字体、默认值等配置项，方便主题化与个性化

可被主程序或任何模块导入使用：
    from config import COLORS, FONTS, AI_CONFIG
"""
import os
import json
from pathlib import Path

# ==================== 颜色主题 ====================
COLORS = {
    # 主色调
    "primary": "#2c3e50",      # 深蓝灰（标题、主要按钮）
    "success": "#27ae60",      # 绿色（成功、保存）
    "danger": "#e74c3c",       # 红色（删除、警告）
    "warning": "#f39c12",      # 橙色（次要操作）
    "info": "#3498db",         # 蓝色（信息、辅助）
    # 学习产物按钮专用
    "purple": "#9b59b6",       # 紫色（思维导图）
    "deep_purple": "#8e44ad",  # 深紫（闪卡）
    "teal": "#16a085",         # 青色（闪卡复习）
    "orange": "#e67e22",       # 橙色（知识问答）
    # 中性色
    "white": "#ffffff",
    "light_bg": "#f8f9fa",     # 浅灰背景
    "muted": "#95a5a6",        # 静音灰
    "text_secondary": "#666666",
    "text_tertiary": "#999999",
    "border": "#dddddd",
}

# ==================== 字体配置 ====================
FONTS = {
    "default": ("Microsoft YaHei", 9),
    "default_bold": ("Microsoft YaHei", 9, "bold"),
    "small": ("Microsoft YaHei", 8),
    "small_bold": ("Microsoft YaHei", 8, "bold"),
    "medium": ("Microsoft YaHei", 10),
    "medium_bold": ("Microsoft YaHei", 10, "bold"),
    "large": ("Microsoft YaHei", 12),
    "large_bold": ("Microsoft YaHei", 12, "bold"),
    "title": ("Microsoft YaHei", 24, "bold"),
    "code": ("Consolas", 11),
    "code_small": ("Consolas", 10),
    "italic": ("Microsoft YaHei", 9, "italic"),
}

# ==================== AI 模型配置 ====================
AI_CONFIG = {
    "qwen_model": os.getenv("QWEN_MODEL", "qwen3.6-plus"),
    "qwen_base_url": os.getenv(
        "QWEN_BASE_URL",
        "https://dashscope.aliyuncs.com/compatible-mode/v1"
    ),
    "default_temperature": 0.7,
    "default_max_tokens": 2500,
    "summary_temperature": 0.3,
    "summary_max_tokens": 1500,
    "artifact_temperature": 0.5,
    "artifact_max_tokens": 3000,
}

# ==================== 数据库配置 ====================
DB_CONFIG = {
    "db_path": os.getenv("SQLITE_DB_PATH", "cve_data/cve_database.db"),
    "wal_mode": os.getenv("SQLITE_WAL_MODE", "1") == "1",
    "cache_size": int(os.getenv("SQLITE_CACHE_SIZE", "10000")),
    "synchronous": os.getenv("SQLITE_SYNCHRONOUS", "NORMAL"),
    "temp_store": os.getenv("SQLITE_TEMP_STORE", "MEMORY"),
}

# ==================== 路径配置 ====================
DATA_DIR = Path(os.getenv("DATA_DIR", "cve_data"))
BACKUP_DIR = DATA_DIR / "backups"
NEWS_BRIEF_DIR = DATA_DIR / "news_briefs"

# ==================== 学习模块配置 ====================
LEARN_CONFIG = {
    "max_source_content": 16000,    # 学习资料最大字符数
    "summary_content_limit": 3000,  # 摘要生成时使用的字符数
    "conv_history_limit": 20,        # 对话历史最大轮数
    "artifact_conv_limit": 4000,     # 学习产物生成时使用的对话长度
    "default_topic": "CVE漏洞分析",
}

# ==================== UI 默认值 ====================
UI_CONFIG = {
    "stats_default_zoom": 1.0,       # 统计分析页默认缩放
    "stats_zoom_min": 0.7,
    "stats_zoom_max": 1.6,
    "stats_zoom_step": 0.1,
    "left_panel_width": 200,         # 智能学习左侧面板宽度
    "default_window_geometry": "1280x800",
}

# ==================== 语言配置 ====================
LANGUAGE_CONFIG_FILE = DATA_DIR / "language_config.json"


def get_language_setting() -> str:
    """获取保存的语言设置

    Returns:
        语言代码 ('zh_CN' 或 'en_US')，默认为 'zh_CN'
    """
    try:
        if LANGUAGE_CONFIG_FILE.exists():
            with open(LANGUAGE_CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
                return config.get('language', 'zh_CN')
    except Exception:
        pass
    return 'zh_CN'


def save_language_setting(language: str) -> bool:
    """保存语言设置

    Args:
        language: 语言代码 ('zh_CN' 或 'en_US')

    Returns:
        是否保存成功
    """
    try:
        # 确保数据目录存在
        LANGUAGE_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)

        config = {'language': language}
        with open(LANGUAGE_CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        print(f"保存语言设置失败: {e}")
        return False


def get_api_key(provider: str) -> str:
    """获取指定 AI 提供商的 API Key

    Args:
        provider: 'qwen' / 'claude' / 'exa' / 'nvd'

    Returns:
        API Key 字符串，若未配置则返回空字符串
    """
    keys = {
        "qwen": os.getenv("QWEN_API_KEY") or os.getenv("DASHSCOPE_API_KEY", ""),
        "claude": os.getenv("CLAUDE_API_KEY", ""),
        "exa": os.getenv("EXA_API_KEY", ""),
        "nvd": os.getenv("NVD_API_KEY", ""),
    }
    return keys.get(provider, "")
