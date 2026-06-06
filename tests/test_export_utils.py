"""
测试导出工具模块
"""
import pytest
import json
import tempfile
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from gui.utils.export_utils import ExportManager, export_data


@pytest.fixture
def sample_data():
    """测试数据"""
    return [
        {"id": "CVE-2024-0001", "severity": "CRITICAL", "score": 9.8},
        {"id": "CVE-2024-0002", "severity": "HIGH", "score": 7.5},
        {"id": "CVE-2024-0003", "severity": "MEDIUM", "score": 5.0},
    ]


@pytest.fixture
def tmp_path_factory_safe(tmp_path):
    """安全临时目录"""
    return tmp_path


class TestExportManagerCSV:
    """测试 CSV 导出"""

    def test_basic_csv_export(self, sample_data, tmp_path):
        manager = ExportManager()
        output = tmp_path / "test.csv"
        result = manager.export_csv(sample_data, output)

        assert result.exists()
        content = output.read_text(encoding="utf-8")
        assert "CVE-2024-0001" in content
        assert "CRITICAL" in content

    def test_csv_with_specific_fields(self, sample_data, tmp_path):
        manager = ExportManager()
        output = tmp_path / "test.csv"
        manager.export_csv(sample_data, output, fields=["id", "severity"])

        content = output.read_text(encoding="utf-8")
        assert "score" not in content.split("\n")[0]  # 标题行不含 score

    def test_csv_empty_data(self, tmp_path):
        manager = ExportManager()
        output = tmp_path / "empty.csv"
        manager.export_csv([], output)
        assert output.exists()


class TestExportManagerJSON:
    """测试 JSON 导出"""

    def test_basic_json_export(self, sample_data, tmp_path):
        manager = ExportManager()
        output = tmp_path / "test.json"
        manager.export_json(sample_data, output)

        assert output.exists()
        loaded = json.loads(output.read_text(encoding="utf-8"))
        assert len(loaded) == 3
        assert loaded[0]["id"] == "CVE-2024-0001"

    def test_json_pretty_print(self, sample_data, tmp_path):
        manager = ExportManager()
        output = tmp_path / "pretty.json"
        manager.export_json(sample_data, output, pretty=True)

        content = output.read_text(encoding="utf-8")
        assert "  " in content  # 缩进

    def test_json_compact(self, sample_data, tmp_path):
        manager = ExportManager()
        output = tmp_path / "compact.json"
        manager.export_json(sample_data, output, pretty=False)

        content = output.read_text(encoding="utf-8")
        # 紧凑格式无多余空白
        assert "  " not in content


class TestExportManagerMarkdown:
    """测试 Markdown 导出"""

    def test_basic_markdown_export(self, sample_data, tmp_path):
        manager = ExportManager()
        output = tmp_path / "test.md"
        manager.export_markdown(sample_data, output, title="CVE 报告")

        content = output.read_text(encoding="utf-8")
        assert "# CVE 报告" in content
        assert "CVE-2024-0001" in content
        assert "|" in content  # 表格

    def test_markdown_with_metadata(self, sample_data, tmp_path):
        manager = ExportManager()
        output = tmp_path / "with_meta.md"
        manager.export_markdown(sample_data, output, include_metadata=True)

        content = output.read_text(encoding="utf-8")
        assert "生成时间" in content
        assert "记录数量" in content

    def test_markdown_without_metadata(self, sample_data, tmp_path):
        manager = ExportManager()
        output = tmp_path / "no_meta.md"
        manager.export_markdown(sample_data, output, include_metadata=False)

        content = output.read_text(encoding="utf-8")
        assert "生成时间" not in content


class TestExportManagerHTML:
    """测试 HTML 导出"""

    def test_basic_html_export(self, sample_data, tmp_path):
        manager = ExportManager()
        output = tmp_path / "test.html"
        manager.export_html(sample_data, output, title="CVE 报告")

        content = output.read_text(encoding="utf-8")
        assert "<html" in content
        assert "<table>" in content
        assert "CVE-2024-0001" in content
        assert "<title>CVE 报告</title>" in content

    def test_html_escaping(self, tmp_path):
        manager = ExportManager()
        data = [{"id": "<script>alert(1)</script>", "name": "Test & More"}]
        output = tmp_path / "escape.html"
        manager.export_html(data, output)

        content = output.read_text(encoding="utf-8")
        assert "&lt;script&gt;" in content
        assert "&amp;" in content


class TestExportManagerTXT:
    """测试 TXT 导出"""

    def test_basic_txt_export(self, sample_data, tmp_path):
        manager = ExportManager()
        output = tmp_path / "test.txt"
        manager.export_txt(sample_data, output, title="测试报告")

        content = output.read_text(encoding="utf-8")
        assert "测试报告" in content
        assert "CVE-2024-0001" in content


class TestExportDataFunction:
    """测试统一导出接口"""

    def test_auto_format_detection(self, sample_data, tmp_path):
        # 通过扩展名自动检测格式
        export_data(sample_data, tmp_path / "auto.csv")
        assert (tmp_path / "auto.csv").exists()

        export_data(sample_data, tmp_path / "auto.json")
        assert (tmp_path / "auto.json").exists()

        export_data(sample_data, tmp_path / "auto.md")
        assert (tmp_path / "auto.md").exists()

    def test_explicit_format(self, sample_data, tmp_path):
        output = tmp_path / "data.dat"
        export_data(sample_data, output, format="json")
        loaded = json.loads(output.read_text(encoding="utf-8"))
        assert len(loaded) == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
