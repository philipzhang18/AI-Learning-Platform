# LLM API 集成配置示例
# 复制此文件为 llm_config.py 并填入您的实际 API 密钥

import os

# 优先尝试加载本地环境文件（可选）
try:
    from dotenv import load_dotenv
    # 加载默认的 .env（若存在）
    load_dotenv(dotenv_path=os.path.join(os.getcwd(), ".env"), override=False)
    # 再加载 .env.llm（若存在，覆盖相同键）
    llm_env = os.path.join(os.getcwd(), ".env.llm")
    if os.path.exists(llm_env):
        load_dotenv(dotenv_path=llm_env, override=True)
except Exception:
    # 未安装 python-dotenv 或其他异常时忽略，继续走系统环境变量
    pass

# ============================================
# Claude API 配置
# ============================================
# 从环境变量读取，避免硬编码
# 申请地址：https://console.anthropic.com/
CLAUDE_API_KEY = os.getenv("CLAUDE_API_KEY", "")
CLAUDE_API_URL = os.getenv("CLAUDE_API_URL", "https://api.anthropic.com/v1/messages")
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-3-opus-20240229")

# ============================================
# Qwen API 配置（阿里云百炼，OpenAI 兼容端点）
# ============================================
# 申请地址：https://dashscope.console.aliyun.com/
QWEN_API_KEY = os.getenv("DASHSCOPE_API_KEY", os.getenv("QWEN_API_KEY", ""))
QWEN_BASE_URL = os.getenv("QWEN_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")
# 统一使用 coder plus 系列；可与控制台实际开通的模型保持一致
QWEN_MODEL = os.getenv("QWEN_MODEL", "qwen3-coder-plus")

# ============================================
# 系统配置
# ============================================
DEFAULT_MODEL_PROVIDER = os.getenv("DEFAULT_MODEL_PROVIDER", "claude")  # "claude" 或 "qwen"
AUTO_FALLBACK = os.getenv("AUTO_FALLBACK", "true").lower() == "true"
TIMEOUT_SECONDS = int(os.getenv("TIMEOUT_SECONDS", "30"))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))
RETRY_DELAY = int(os.getenv("RETRY_DELAY", "2"))

# ============================================
# 日志配置
# ============================================
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")  # 日志级别: DEBUG, INFO, WARNING, ERROR
LOG_FILE = os.getenv("LOG_FILE", "llm_api.log")  # 日志文件路径