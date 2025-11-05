"""
CVE 系统完整测试脚本
测试所有核心功能模块
"""
import sys
import os
from pathlib import Path
import sqlite3
import json

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent))

# 测试结果收集
test_results = {
    "passed": [],
    "failed": [],
    "warnings": []
}

def log_test(test_name, status, message=""):
    """记录测试结果"""
    result = {"test": test_name, "message": message}
    if status == "PASS":
        test_results["passed"].append(result)
        print(f"[PASS] {test_name}: {message}")
    elif status == "FAIL":
        test_results["failed"].append(result)
        print(f"[FAIL] {test_name}: {message}")
    elif status == "WARN":
        test_results["warnings"].append(result)
        print(f"[WARN] {test_name}: {message}")

print("=" * 60)
print("CVE 系统完整测试")
print("=" * 60)
print()

# ==================== 测试 1: 基础依赖导入 ====================
print("[测试组 1] 基础依赖检查")
print("-" * 60)

try:
    import aiohttp
    log_test("aiohttp 导入", "PASS", f"版本 {aiohttp.__version__}")
except ImportError as e:
    log_test("aiohttp 导入", "FAIL", str(e))

try:
    import feedparser
    log_test("feedparser 导入", "PASS", f"版本 {feedparser.__version__}")
except ImportError as e:
    log_test("feedparser 导入", "FAIL", str(e))

try:
    from bs4 import BeautifulSoup
    log_test("beautifulsoup4 导入", "PASS", "已安装")
except ImportError as e:
    log_test("beautifulsoup4 导入", "FAIL", str(e))

try:
    import redis
    log_test("redis 导入", "PASS", f"版本 {redis.__version__}")
except ImportError as e:
    log_test("redis 导入", "FAIL", str(e))

try:
    from dotenv import load_dotenv
    log_test("python-dotenv 导入", "PASS", "已安装")
except ImportError as e:
    log_test("python-dotenv 导入", "FAIL", str(e))

print()

# ==================== 测试 2: 项目模块导入 ====================
print("[测试组 2] 项目模块检查")
print("-" * 60)

try:
    from collect_cves import CVECollector
    log_test("CVECollector 模块", "PASS", "成功导入")
except Exception as e:
    log_test("CVECollector 模块", "FAIL", str(e))

try:
    from dell_security_scraper import DellSecurityScraper
    log_test("DellSecurityScraper 模块", "PASS", "成功导入")
except Exception as e:
    log_test("DellSecurityScraper 模块", "FAIL", str(e))

try:
    from redis_manager import RedisDataManager
    log_test("RedisDataManager 模块", "PASS", "成功导入")
except Exception as e:
    log_test("RedisDataManager 模块", "FAIL", str(e))

print()

# ==================== 测试 3: SQLite 数据库 ====================
print("[测试组 3] SQLite 数据库")
print("-" * 60)

db_dir = Path("cve_data")
db_path = db_dir / "cve_database.db"

if not db_dir.exists():
    db_dir.mkdir(parents=True)
    log_test("数据目录创建", "PASS", f"创建目录: {db_dir}")

try:
    # 测试数据库连接
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # 检查表是否存在
    cursor.execute("""
        SELECT name FROM sqlite_master
        WHERE type='table' AND name IN ('cve_data', 'dell_advisories')
    """)
    tables = [row[0] for row in cursor.fetchall()]

    if tables:
        log_test("SQLite 数据库连接", "PASS", f"已有表: {', '.join(tables)}")

        # 检查数据量
        if 'cve_data' in tables:
            cursor.execute("SELECT COUNT(*) FROM cve_data")
            count = cursor.fetchone()[0]
            log_test("CVE 数据统计", "PASS", f"共 {count} 条记录")

        if 'dell_advisories' in tables:
            cursor.execute("SELECT COUNT(*) FROM dell_advisories")
            count = cursor.fetchone()[0]
            log_test("Dell 公告统计", "PASS", f"共 {count} 条记录")
    else:
        log_test("SQLite 数据库连接", "WARN", "数据库为空，需要首次数据收集")

    conn.close()
except Exception as e:
    log_test("SQLite 数据库连接", "FAIL", str(e))

# 检查数据库文件大小
if db_path.exists():
    db_size = db_path.stat().st_size / (1024 * 1024)  # MB
    log_test("数据库文件大小", "PASS", f"{db_size:.2f} MB")

print()

# ==================== 测试 4: Redis 连接 ====================
print("[测试组 4] Redis 连接测试")
print("-" * 60)

try:
    from redis_manager import RedisDataManager

    # 尝试连接 Redis
    redis_manager = RedisDataManager(
        host=os.getenv('REDIS_HOST', 'localhost'),
        port=int(os.getenv('REDIS_PORT', '6379')),
        password=os.getenv('REDIS_PASSWORD')
    )

    if redis_manager.ping():
        log_test("Redis 连接", "PASS", "连接成功")

        # 获取 Redis 信息
        info = redis_manager.redis_client.info()
        log_test("Redis 版本", "PASS", f"版本 {info.get('redis_version', 'unknown')}")
        log_test("Redis 内存使用", "PASS", f"{info.get('used_memory_human', 'unknown')}")

        # 测试 Redis 键统计
        cve_count = redis_manager.get_cve_count()
        dell_count = redis_manager.get_dell_count()
        log_test("Redis CVE 数据", "PASS", f"共 {cve_count} 条")
        log_test("Redis Dell 数据", "PASS", f"共 {dell_count} 条")
    else:
        log_test("Redis 连接", "WARN", "无法连接，将使用 SQLite 模式")
except Exception as e:
    log_test("Redis 连接", "WARN", f"Redis 不可用: {str(e)[:50]}")

print()

# ==================== 测试 5: 环境配置 ====================
print("[测试组 5] 环境配置")
print("-" * 60)

env_file = Path(".env")
env_example = Path(".env.example")

if env_file.exists():
    log_test(".env 文件", "PASS", "配置文件存在")

    from dotenv import load_dotenv
    load_dotenv()

    # 检查关键配置
    configs = {
        "REDIS_HOST": os.getenv('REDIS_HOST'),
        "REDIS_PORT": os.getenv('REDIS_PORT'),
        "SQLITE_DB_PATH": os.getenv('SQLITE_DB_PATH'),
        "ENABLE_GPU_FEATURES": os.getenv('ENABLE_GPU_FEATURES', '0'),
    }

    for key, value in configs.items():
        if value:
            log_test(f"配置项 {key}", "PASS", f"= {value}")
        else:
            log_test(f"配置项 {key}", "WARN", "未设置")
else:
    log_test(".env 文件", "WARN", f"不存在，请从 {env_example} 复制")

print()

# ==================== 测试 6: 启动脚本检查 ====================
print("[测试组 6] 启动脚本")
print("-" * 60)

scripts = {
    "start_cve_sqlite.sh": "SQLite 轻量模式",
    "start_cve_wsl_redis.sh": "WSL Redis 混合模式",
    "check_wsl_environment.sh": "WSL 环境检查",
}

for script, desc in scripts.items():
    script_path = Path(script)
    if script_path.exists():
        log_test(f"脚本 {script}", "PASS", desc)
    else:
        log_test(f"脚本 {script}", "FAIL", f"文件不存在")

print()

# ==================== 测试总结 ====================
print("=" * 60)
print("测试总结")
print("=" * 60)

total = len(test_results["passed"]) + len(test_results["failed"]) + len(test_results["warnings"])
print(f"Total Tests: {total}")
print(f"[PASS] Passed: {len(test_results['passed'])}")
print(f"[FAIL] Failed: {len(test_results['failed'])}")
print(f"[WARN] Warnings: {len(test_results['warnings'])}")
print()

if test_results["failed"]:
    print("Failed Tests:")
    for item in test_results["failed"]:
        print(f"  - {item['test']}: {item['message']}")
    print()

if test_results["warnings"]:
    print("Warnings:")
    for item in test_results["warnings"]:
        print(f"  - {item['test']}: {item['message']}")
    print()

# 保存测试报告
report_path = Path("SYSTEM_TEST_REPORT.md")
with open(report_path, "w", encoding="utf-8") as f:
    f.write("# CVE System Test Report\n\n")
    f.write(f"**Test Time**: {os.popen('date /t && time /t').read().strip()}\n\n")
    f.write(f"## Test Summary\n\n")
    f.write(f"- Total Tests: {total}\n")
    f.write(f"- Passed: {len(test_results['passed'])}\n")
    f.write(f"- Failed: {len(test_results['failed'])}\n")
    f.write(f"- Warnings: {len(test_results['warnings'])}\n\n")

    f.write("## Passed Tests\n\n")
    for item in test_results["passed"]:
        f.write(f"- [PASS] **{item['test']}**: {item['message']}\n")

    if test_results["failed"]:
        f.write("\n## Failed Tests\n\n")
        for item in test_results["failed"]:
            f.write(f"- [FAIL] **{item['test']}**: {item['message']}\n")

    if test_results["warnings"]:
        f.write("\n## Warnings\n\n")
        for item in test_results["warnings"]:
            f.write(f"- [WARN] **{item['test']}**: {item['message']}\n")

    f.write("\n## Recommendations\n\n")
    if test_results["failed"]:
        f.write("### 修复失败项\n")
        f.write("1. 检查依赖项是否完整安装: `pip install -r requirements.txt`\n")
        f.write("2. 确认项目模块文件是否存在\n")
        f.write("3. 验证数据库文件权限\n\n")

    if test_results["warnings"]:
        f.write("### 处理警告\n")
        f.write("1. 如未连接 Redis，系统将自动回退到 SQLite 模式\n")
        f.write("2. 首次运行需要执行数据收集\n")
        f.write("3. 建议配置 .env 文件以优化性能\n\n")

    f.write("## 下一步操作\n\n")
    f.write("### 启动系统\n\n")
    f.write("**方式 1: SQLite 轻量模式**\n")
    f.write("```bash\n")
    f.write("bash start_cve_sqlite.sh\n")
    f.write("```\n\n")
    f.write("**方式 2: WSL Redis 混合模式**\n")
    f.write("```bash\n")
    f.write("bash start_cve_wsl_redis.sh\n")
    f.write("```\n\n")
    f.write("**方式 3: Windows 批处理**\n")
    f.write("```cmd\n")
    f.write("启动CVE系统-SQLite.bat\n")
    f.write("```\n\n")

print(f"[PASS] Test report saved: {report_path}")
print()

# 退出码
exit_code = 1 if test_results["failed"] else 0
sys.exit(exit_code)
