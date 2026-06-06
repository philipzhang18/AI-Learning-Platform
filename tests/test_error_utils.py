"""
测试错误处理工具模块
"""
import pytest
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from error_utils import (
    log_error,
    safe_execute,
    safe_db_operation,
    safe_api_call,
    safe_file_operation,
    ErrorContext,
)


class TestLogError:
    """测试错误日志"""

    def test_basic_log(self):
        try:
            raise ValueError("test error")
        except ValueError as e:
            msg = log_error(e, "测试上下文")
            assert "ValueError" in msg
            assert "test error" in msg
            assert "测试上下文" in msg

    def test_with_logger(self):
        logged = []

        def fake_logger(message):
            logged.append(message)

        try:
            raise RuntimeError("custom error")
        except RuntimeError as e:
            log_error(e, "context", logger=fake_logger)

        assert len(logged) >= 1
        assert any("RuntimeError" in m for m in logged)


class TestSafeExecute:
    """测试 safe_execute 装饰器"""

    def test_successful_execution(self):
        @safe_execute("test")
        def func(x, y):
            return x + y

        result = func(1, 2)
        assert result == 3

    def test_exception_reraised(self):
        @safe_execute("test")
        def func():
            raise ValueError("test")

        # safe_execute 默认会重新抛出异常
        with pytest.raises(ValueError):
            func()


class TestSafeDbOperation:
    """测试 safe_db_operation 装饰器"""

    def test_successful_db_operation(self):
        @safe_db_operation("查询失败", show_messagebox=False)
        def query():
            return {"data": "ok"}

        result = query()
        assert result == {"data": "ok"}

    def test_db_operational_error_returns_none(self):
        @safe_db_operation("查询失败", show_messagebox=False)
        def query():
            raise sqlite3.OperationalError("database is locked")

        result = query()
        assert result is None  # 异常被吞掉，返回 None

    def test_db_integrity_error(self):
        @safe_db_operation("插入失败", show_messagebox=False)
        def insert():
            raise sqlite3.IntegrityError("UNIQUE constraint failed")

        result = insert()
        assert result is None

    def test_unexpected_error(self):
        @safe_db_operation("操作失败", show_messagebox=False)
        def operation():
            raise RuntimeError("unexpected")

        result = operation()
        assert result is None


class TestSafeApiCall:
    """测试 safe_api_call 装饰器"""

    def test_successful_call(self):
        @safe_api_call("API 失败")
        def call():
            return {"status": "ok"}

        result = call()
        assert result == {"status": "ok"}

    def test_timeout_with_retry(self):
        import requests

        attempt_count = 0

        @safe_api_call("超时", timeout_retry=2)
        def call():
            nonlocal attempt_count
            attempt_count += 1
            if attempt_count < 3:
                raise requests.Timeout()
            return "success"

        result = call()
        assert result == "success"
        assert attempt_count == 3


class TestSafeFileOperation:
    """测试 safe_file_operation 装饰器"""

    def test_successful_file_operation(self, tmp_path):
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello")

        @safe_file_operation("读取失败")
        def read_file(path):
            return path.read_text()

        result = read_file(test_file)
        assert result == "hello"

    def test_file_not_found(self):
        @safe_file_operation("文件未找到")
        def read_file():
            with open("/nonexistent/file.txt", "r") as f:
                return f.read()

        result = read_file()
        assert result is None


class TestErrorContext:
    """测试错误上下文管理器"""

    def test_basic_usage(self):
        with ErrorContext("批量操作") as ctx:
            for i in range(10):
                if i % 3 == 0:
                    try:
                        raise ValueError(f"item {i} failed")
                    except ValueError as e:
                        ctx.record_error(e, item=f"item-{i}")
                else:
                    ctx.record_success()

        assert ctx.success_count == 6
        assert len(ctx.errors) == 4

    def test_summary(self):
        with ErrorContext("test") as ctx:
            ctx.record_success()
            ctx.record_success()
            try:
                raise ValueError("test")
            except ValueError as e:
                ctx.record_error(e, "item1")

        summary = ctx.get_summary()
        assert "成功: 2/3" in summary
        assert "失败: 1" in summary

    def test_no_operations(self):
        with ErrorContext("empty") as ctx:
            pass

        summary = ctx.get_summary()
        assert "无操作" in summary


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
