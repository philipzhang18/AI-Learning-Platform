"""
安全配置管理工具
提供 API Key 加密存储和安全加载功能

使用示例:
    from secure_config import SecureConfig

    # 加密 .env 文件
    config = SecureConfig()
    config.encrypt_env_file(".env")

    # 解密并加载环境变量
    config.decrypt_and_load_env(".env.enc")

    # 验证配置文件
    config.validate_env_file(".env")
"""
import os
import re
import json
from pathlib import Path
from typing import Dict, List, Optional
from cryptography.fernet import Fernet


class SecureConfig:
    """安全配置管理器"""

    def __init__(self, key_path: Path = Path(".secret_key")):
        """初始化安全配置管理器

        Args:
            key_path: 加密密钥文件路径
        """
        self.key_path = key_path
        self.cipher = self._get_or_create_cipher()

    def _get_or_create_cipher(self) -> Fernet:
        """获取或创建加密器"""
        if not self.key_path.exists():
            key = Fernet.generate_key()
            self.key_path.write_bytes(key)
            # 设置文件权限（仅所有者可读）
            try:
                os.chmod(self.key_path, 0o600)
            except Exception:
                pass

        key = self.key_path.read_bytes()
        return Fernet(key)

    def encrypt_env_file(self, env_path: Path) -> Path:
        """加密 .env 文件

        Args:
            env_path: .env 文件路径

        Returns:
            加密后文件路径 (.env.enc)
        """
        if isinstance(env_path, str):
            env_path = Path(env_path)

        if not env_path.exists():
            raise FileNotFoundError(f".env 文件不存在: {env_path}")

        plaintext = env_path.read_bytes()
        encrypted = self.cipher.encrypt(plaintext)

        enc_path = env_path.with_suffix(env_path.suffix + ".enc")
        enc_path.write_bytes(encrypted)

        print(f"✅ 已加密: {env_path} → {enc_path}")
        return enc_path

    def decrypt_env_file(self, enc_path: Path) -> str:
        """解密 .env.enc 文件

        Args:
            enc_path: 加密文件路径

        Returns:
            解密后的内容
        """
        if isinstance(enc_path, str):
            enc_path = Path(enc_path)

        if not enc_path.exists():
            raise FileNotFoundError(f"加密文件不存在: {enc_path}")

        encrypted = enc_path.read_bytes()
        decrypted = self.cipher.decrypt(encrypted)

        return decrypted.decode('utf-8')

    def decrypt_and_load_env(self, enc_path: Path):
        """解密并加载环境变量到 os.environ

        Args:
            enc_path: 加密文件路径
        """
        content = self.decrypt_env_file(enc_path)

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if '=' in line:
                key, value = line.split('=', 1)
                os.environ[key.strip()] = value.strip()

        print(f"✅ 已加载环境变量: {enc_path}")

    def validate_env_file(self, env_path: Path) -> Dict[str, List[str]]:
        """验证 .env 文件安全性

        检查:
        1. 是否包含明文密钥
        2. 是否包含示例值
        3. 是否包含弱密钥

        Args:
            env_path: .env 文件路径

        Returns:
            验证结果字典 {"warnings": [...], "errors": [...]}
        """
        if isinstance(env_path, str):
            env_path = Path(env_path)

        if not env_path.exists():
            return {"errors": [f"文件不存在: {env_path}"]}

        content = env_path.read_text(encoding='utf-8')
        warnings = []
        errors = []

        # 检查示例值
        example_patterns = [
            r'your_.*_key',
            r'your_.*_api',
            r'example',
            r'placeholder',
            r'change_me',
            r'xxx',
        ]

        for pattern in example_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                warnings.append(f"⚠️  包含示例值: {pattern}")

        # 检查弱密钥（长度 < 16）
        for line in content.splitlines():
            if '=' in line and not line.strip().startswith('#'):
                key, value = line.split('=', 1)
                value = value.strip().strip('"').strip("'")
                if value and len(value) < 16 and not value.startswith('your_'):
                    warnings.append(f"⚠️  密钥过短: {key.strip()} (长度 {len(value)})")

        # 检查是否被 Git 跟踪
        if env_path.name == '.env':
            try:
                import subprocess
                result = subprocess.run(
                    ['git', 'ls-files', '--error-unmatch', str(env_path)],
                    capture_output=True,
                    text=True,
                    cwd=env_path.parent
                )
                if result.returncode == 0:
                    errors.append(f"❌ .env 文件被 Git 跟踪！请执行: git rm --cached {env_path.name}")
            except Exception:
                pass

        return {"warnings": warnings, "errors": errors}

    def generate_env_template(self, env_path: Path, output_path: Optional[Path] = None):
        """生成 .env.example 模板（移除实际密钥）

        Args:
            env_path: .env 文件路径
            output_path: 输出路径，默认为 .env.example
        """
        if isinstance(env_path, str):
            env_path = Path(env_path)

        if output_path is None:
            output_path = env_path.parent / ".env.example"

        if not env_path.exists():
            raise FileNotFoundError(f".env 文件不存在: {env_path}")

        content = env_path.read_text(encoding='utf-8')
        lines = []

        for line in content.splitlines():
            if '=' in line and not line.strip().startswith('#'):
                key, _ = line.split('=', 1)
                lines.append(f"{key.strip()}=your_{key.strip().lower()}_here")
            else:
                lines.append(line)

        output_path.write_text('\n'.join(lines), encoding='utf-8')
        print(f"✅ 已生成模板: {output_path}")


def check_env_security():
    """快速检查 .env 文件安全性（命令行工具）"""
    env_path = Path(".env")

    if not env_path.exists():
        print("✅ .env 文件不存在（良好）")
        return

    config = SecureConfig()
    result = config.validate_env_file(env_path)

    if result["errors"]:
        print("\n❌ 发现严重问题:")
        for error in result["errors"]:
            print(f"  {error}")

    if result["warnings"]:
        print("\n⚠️  发现警告:")
        for warning in result["warnings"]:
            print(f"  {warning}")

    if not result["errors"] and not result["warnings"]:
        print("✅ .env 文件安全检查通过")


if __name__ == "__main__":
    # 命令行模式
    import sys

    if len(sys.argv) < 2:
        print("用法:")
        print("  python secure_config.py check          # 检查 .env 安全性")
        print("  python secure_config.py encrypt .env   # 加密 .env 文件")
        print("  python secure_config.py template .env  # 生成 .env.example")
        sys.exit(1)

    command = sys.argv[1]
    config = SecureConfig()

    if command == "check":
        check_env_security()

    elif command == "encrypt":
        if len(sys.argv) < 3:
            print("错误: 请指定要加密的文件")
            sys.exit(1)
        env_file = Path(sys.argv[2])
        config.encrypt_env_file(env_file)

    elif command == "template":
        if len(sys.argv) < 3:
            print("错误: 请指定 .env 文件")
            sys.exit(1)
        env_file = Path(sys.argv[2])
        config.generate_env_template(env_file)

    else:
        print(f"未知命令: {command}")
        sys.exit(1)
