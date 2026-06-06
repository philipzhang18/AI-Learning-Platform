"""
测试 secure_config 安全配置模块
"""
import pytest
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from secure_config import SecureConfig


class TestSecureConfig:
    """测试安全配置"""

    def test_create_cipher(self, tmp_path):
        """创建加密器（自动生成密钥）"""
        key_path = tmp_path / "test.key"
        config = SecureConfig(key_path=key_path)

        assert key_path.exists()
        assert len(key_path.read_bytes()) > 0

    def test_encrypt_decrypt_roundtrip(self, tmp_path):
        """加密解密往返测试"""
        env_path = tmp_path / ".env"
        env_path.write_text("API_KEY=secret123\nDB_URL=test\n")

        key_path = tmp_path / ".secret_key"
        config = SecureConfig(key_path=key_path)

        # 加密
        enc_path = config.encrypt_env_file(env_path)
        assert enc_path.exists()
        assert enc_path.read_bytes() != env_path.read_bytes()

        # 解密
        decrypted = config.decrypt_env_file(enc_path)
        assert "API_KEY=secret123" in decrypted
        assert "DB_URL=test" in decrypted

    def test_decrypt_and_load_env(self, tmp_path):
        """解密并加载到 os.environ"""
        env_path = tmp_path / ".env"
        env_path.write_text("TEST_KEY_XYZ=test_value_123\n")

        key_path = tmp_path / ".secret_key"
        config = SecureConfig(key_path=key_path)
        enc_path = config.encrypt_env_file(env_path)

        # 清除环境变量
        os.environ.pop("TEST_KEY_XYZ", None)

        # 加载加密文件
        config.decrypt_and_load_env(enc_path)

        assert os.environ.get("TEST_KEY_XYZ") == "test_value_123"

        # 清理
        os.environ.pop("TEST_KEY_XYZ", None)

    def test_validate_env_with_examples(self, tmp_path):
        """验证 .env 包含示例值"""
        env_path = tmp_path / ".env"
        env_path.write_text("API_KEY=your_api_key_here\n")

        key_path = tmp_path / ".secret_key"
        config = SecureConfig(key_path=key_path)
        result = config.validate_env_file(env_path)

        assert any("示例值" in w for w in result["warnings"])

    def test_validate_env_with_short_key(self, tmp_path):
        """验证弱密钥"""
        env_path = tmp_path / ".env"
        env_path.write_text("API_KEY=short\n")

        key_path = tmp_path / ".secret_key"
        config = SecureConfig(key_path=key_path)
        result = config.validate_env_file(env_path)

        assert any("过短" in w for w in result["warnings"])

    def test_validate_env_clean(self, tmp_path):
        """验证良好的 .env"""
        env_path = tmp_path / ".env"
        env_path.write_text(
            "API_KEY=a_very_long_secret_key_that_is_secure_enough_12345\n"
        )

        key_path = tmp_path / ".secret_key"
        config = SecureConfig(key_path=key_path)
        result = config.validate_env_file(env_path)

        # 不应有警告
        assert len(result["warnings"]) == 0

    def test_generate_template(self, tmp_path):
        """生成模板"""
        env_path = tmp_path / ".env"
        env_path.write_text("API_KEY=secret123\nDB_URL=postgres://...\n")

        key_path = tmp_path / ".secret_key"
        config = SecureConfig(key_path=key_path)

        template_path = tmp_path / ".env.example"
        config.generate_env_template(env_path, template_path)

        content = template_path.read_text()
        assert "API_KEY=your_api_key_here" in content
        assert "secret123" not in content
        assert "DB_URL=your_db_url_here" in content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
