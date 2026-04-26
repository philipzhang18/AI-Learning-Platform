"""
错误处理工具模块
提供统一的错误处理装饰器和结构化日志支持

使用示例：
    from error_utils import safe_execute, log_error

    @safe_execute("加载学习内容失败")
    def load_content(self):
        ...
"""
import functools
import traceback
from datetime import datetime
from typing import Callable, Optional


def log_error(error: Exception, context: str = "", logger: Optional[Callable] = None) -> str:
    """记录错误信息并返回格式化消息

    Args:
        error: 异常对象
        context: 错误上下文说明
        logger: 可选日志函数（如 self.log）

    Returns:
        格式化后的错误消息
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    error_type = type(error).__name__
    error_msg = str(error)

    full_msg = f"[{timestamp}] {context}: {error_type}: {error_msg}"

    if logger:
        try:
            logger(full_msg)
            logger(traceback.format_exc())
        except Exception:
            pass

    return full_msg


def safe_execute(error_message: str = "操作失败", show_traceback: bool = False):
    """安全执行装饰器，统一异常处理

    Args:
        error_message: 用户友好的错误消息前缀
        show_traceback: 是否在日志中显示完整堆栈
    """
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # 尝试从第一个参数获取 logger（通常是 self）
                logger = None
                if args and hasattr(args[0], 'log'):
                    logger = args[0].log

                msg = log_error(e, error_message, logger)

                if show_traceback and logger:
                    logger(traceback.format_exc())

                # 如果是 GUI 类，尝试更新状态栏
                if args and hasattr(args[0], 'learn_status_label'):
                    try:
                        args[0].learn_status_label.config(text=f"{error_message}: {str(e)}")
                    except Exception:
                        pass

                # 重新抛出异常，让调用方决定如何处理
                raise
        return wrapper
    return decorator
