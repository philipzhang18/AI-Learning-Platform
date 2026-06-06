"""
错误处理工具模块
提供统一的错误处理装饰器和结构化日志支持

使用示例：
    from error_utils import safe_execute, log_error, safe_db_operation, safe_api_call

    @safe_execute("加载学习内容失败")
    def load_content(self):
        ...

    @safe_db_operation("删除 CVE 失败")
    def delete_cve(self, cve_id: str):
        ...

    @safe_api_call("采集 CVE 数据失败")
    def collect_cves(self):
        ...
"""
import functools
import traceback
import logging
import sqlite3
from datetime import datetime
from typing import Callable, Optional, Any
try:
    import tkinter.messagebox as messagebox
    HAS_TKINTER = True
except ImportError:
    HAS_TKINTER = False

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cve_data/app.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


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


def safe_db_operation(user_message: str = "数据库操作失败", show_messagebox: bool = True):
    """数据库操作安全装饰器

    自动处理 sqlite3 异常，提供友好的用户提示

    Args:
        user_message: 用户友好的错误消息
        show_messagebox: 是否显示 messagebox（GUI 环境）
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            try:
                return func(*args, **kwargs)
            except sqlite3.OperationalError as e:
                logger.error(f"DB Operational Error in {func.__name__}: {e}", exc_info=True)
                error_detail = str(e)
                if "locked" in error_detail.lower():
                    error_detail = "数据库被锁定，请稍后重试"
                elif "no such table" in error_detail.lower():
                    error_detail = "数据表不存在，可能需要重新初始化数据库"
                else:
                    error_detail = f"数据库操作错误：{error_detail}"

                if show_messagebox and HAS_TKINTER:
                    messagebox.showerror("数据库错误", f"{user_message}\n\n{error_detail}")
                return None

            except sqlite3.IntegrityError as e:
                logger.error(f"DB Integrity Error in {func.__name__}: {e}", exc_info=True)
                error_detail = "数据完整性错误（可能是重复记录或外键约束）"
                if show_messagebox and HAS_TKINTER:
                    messagebox.showerror("数据库错误", f"{user_message}\n\n{error_detail}")
                return None

            except sqlite3.Error as e:
                logger.error(f"DB Error in {func.__name__}: {e}", exc_info=True)
                if show_messagebox and HAS_TKINTER:
                    messagebox.showerror("数据库错误", f"{user_message}\n\n详情：{str(e)}")
                return None

            except Exception as e:
                logger.error(f"Unexpected error in {func.__name__}: {e}", exc_info=True)
                if show_messagebox and HAS_TKINTER:
                    messagebox.showerror("未知错误", f"{user_message}\n\n请联系开发者")
                return None
        return wrapper
    return decorator


def safe_api_call(user_message: str = "API 调用失败", timeout_retry: int = 0):
    """API 调用安全装饰器

    自动处理网络请求异常，支持超时重试

    Args:
        user_message: 用户友好的错误消息
        timeout_retry: 超时重试次数（0 表示不重试）
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            import requests

            retry_count = 0
            max_retries = timeout_retry

            while retry_count <= max_retries:
                try:
                    return func(*args, **kwargs)

                except requests.Timeout as e:
                    retry_count += 1
                    if retry_count <= max_retries:
                        logger.warning(f"API timeout in {func.__name__}, retry {retry_count}/{max_retries}")
                        continue
                    else:
                        logger.error(f"API timeout in {func.__name__} after {max_retries} retries")
                        if HAS_TKINTER:
                            messagebox.showwarning("请求超时",
                                f"{user_message}\n\n网络请求超时，请检查网络连接")
                        return None

                except requests.ConnectionError as e:
                    logger.error(f"API connection error in {func.__name__}: {e}")
                    if HAS_TKINTER:
                        messagebox.showerror("连接错误",
                            f"{user_message}\n\n无法连接到服务器，请检查网络")
                    return None

                except requests.HTTPError as e:
                    logger.error(f"API HTTP error in {func.__name__}: {e}")
                    status_code = e.response.status_code if e.response else "Unknown"
                    if HAS_TKINTER:
                        messagebox.showerror("HTTP 错误",
                            f"{user_message}\n\nHTTP {status_code}: {str(e)}")
                    return None

                except requests.RequestException as e:
                    logger.error(f"API request error in {func.__name__}: {e}")
                    if HAS_TKINTER:
                        messagebox.showerror("网络错误", f"{user_message}\n\n{str(e)}")
                    return None

                except Exception as e:
                    logger.error(f"Unexpected error in {func.__name__}: {e}", exc_info=True)
                    if HAS_TKINTER:
                        messagebox.showerror("未知错误", f"{user_message}\n\n请联系开发者")
                    return None

        return wrapper
    return decorator


def safe_file_operation(user_message: str = "文件操作失败"):
    """文件操作安全装饰器

    自动处理文件 I/O 异常

    Args:
        user_message: 用户友好的错误消息
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            try:
                return func(*args, **kwargs)

            except FileNotFoundError as e:
                logger.error(f"File not found in {func.__name__}: {e}")
                if HAS_TKINTER:
                    messagebox.showerror("文件未找到",
                        f"{user_message}\n\n文件不存在：{e.filename}")
                return None

            except PermissionError as e:
                logger.error(f"Permission error in {func.__name__}: {e}")
                if HAS_TKINTER:
                    messagebox.showerror("权限错误",
                        f"{user_message}\n\n没有访问权限：{e.filename}")
                return None

            except OSError as e:
                logger.error(f"OS error in {func.__name__}: {e}")
                if HAS_TKINTER:
                    messagebox.showerror("系统错误", f"{user_message}\n\n{str(e)}")
                return None

            except Exception as e:
                logger.error(f"Unexpected error in {func.__name__}: {e}", exc_info=True)
                if HAS_TKINTER:
                    messagebox.showerror("未知错误", f"{user_message}\n\n请联系开发者")
                return None

        return wrapper
    return decorator


class ErrorContext:
    """错误上下文管理器，用于批量操作的错误收集"""

    def __init__(self, operation_name: str):
        self.operation_name = operation_name
        self.errors = []
        self.success_count = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            logger.error(f"Error in {self.operation_name}: {exc_val}", exc_info=True)
            return False  # 重新抛出异常
        return True

    def record_success(self):
        """记录一次成功操作"""
        self.success_count += 1

    def record_error(self, error: Exception, item: str = ""):
        """记录一次错误"""
        error_info = {
            "item": item,
            "error_type": type(error).__name__,
            "error_message": str(error),
            "timestamp": datetime.now().isoformat()
        }
        self.errors.append(error_info)
        logger.error(f"Error processing {item}: {error}")

    def get_summary(self) -> str:
        """获取操作摘要"""
        total = self.success_count + len(self.errors)
        if total == 0:
            return f"{self.operation_name}: 无操作"

        success_rate = (self.success_count / total) * 100 if total > 0 else 0

        summary = [
            f"{self.operation_name} 完成",
            f"成功: {self.success_count}/{total} ({success_rate:.1f}%)",
        ]

        if self.errors:
            summary.append(f"失败: {len(self.errors)} 项")
            # 显示前 3 个错误
            for i, err in enumerate(self.errors[:3], 1):
                summary.append(f"  {i}. {err['item']}: {err['error_type']}")
            if len(self.errors) > 3:
                summary.append(f"  ... 还有 {len(self.errors) - 3} 个错误")

        return "\n".join(summary)

