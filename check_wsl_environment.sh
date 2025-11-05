#!/bin/bash
# CVE 系统 - WSL 环境检查脚本
# 检查 WSL Redis 和必要的依赖

echo "========================================"
echo "CVE 系统 - WSL 环境检查"
echo "========================================"
echo ""

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 测试计数
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# 测试函数
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -n "[$TOTAL_TESTS] $test_name ... "
    
    if eval "$test_command" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ PASS${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        echo -e "${RED}✗ FAIL${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# 测试 1: WSL 基础环境
echo -e "${BLUE}[测试组 1] WSL 基础环境${NC}"
echo "----------------------------------------"

run_test "WSL 已安装并运行" "uname -r | grep -iq microsoft || uname -r | grep -iq wsl"

# 测试 2: Redis 服务
echo ""
echo -e "${BLUE}[测试组 2] Redis 服务${NC}"
echo "----------------------------------------"

if run_test "Redis 服务运行中" "redis-cli ping | grep -q PONG"; then
    # Redis 额外信息
    echo ""
    echo "  Redis 服务器信息:"
    REDIS_VERSION=$(redis-cli INFO server | grep "redis_version" | cut -d: -f2 | tr -d '\r')
    REDIS_PORT=$(redis-cli CONFIG GET port | tail -1 | tr -d '\r')
    REDIS_MEMORY=$(redis-cli INFO memory | grep "used_memory_human" | cut -d: -f2 | tr -d '\r')
    
    echo -e "    版本: ${GREEN}$REDIS_VERSION${NC}"
    echo -e "    端口: ${GREEN}$REDIS_PORT${NC}"
    echo -e "    内存使用: ${GREEN}$REDIS_MEMORY${NC}"
    
    # 检查密码配置
    if redis-cli CONFIG GET requirepass | grep -q '""'; then
        echo -e "    密码: ${YELLOW}未设置${NC}"
        echo "    提示: 建议在生产环境中设置 Redis 密码"
    else
        echo -e "    密码: ${GREEN}已设置${NC}"
    fi
else
    echo ""
    echo -e "${YELLOW}  [!] Redis 未运行。启动 Redis:${NC}"
    echo "      sudo service redis-server start"
    echo "      或"
    echo "      redis-server /etc/redis/redis.conf &"
fi

# 测试 3: 网络连通性
echo ""
echo -e "${BLUE}[测试组 3] 网络连通性${NC}"
echo "----------------------------------------"

# 测试从 Windows 访问 WSL Redis
echo -n "从 Windows 访问 WSL Redis ... "
if powershell.exe -Command "Test-Connection -ComputerName localhost -Port 6379 -InformationLevel Quiet" 2>/dev/null; then
    echo -e "${GREEN}✓ 可访问${NC}"
else
    echo -e "${YELLOW}⚠ 检测失败${NC}"
    echo "  提示: 确保 Windows 防火墙允许端口 6379"
fi

# 测试 4: Python 环境
echo ""
echo -e "${BLUE}[测试组 4] Python 环境${NC}"
echo "----------------------------------------"

run_test "Python 3 已安装" "python3 --version"
run_test "pip 已安装" "pip3 --version"

# 检查虚拟环境
if [ -f "/mnt/d/AI/cursor/starone/.venv/bin/python" ]; then
    run_test "虚拟环境可用" "test -f /mnt/d/AI/cursor/starone/.venv/bin/python"
    
    # 检查关键依赖
    echo ""
    echo "  检查 Python 依赖:"
    
    source /mnt/d/AI/cursor/starone/.venv/bin/activate 2>/dev/null
    
    for pkg in redis aiohttp feedparser beautifulsoup4; do
        echo -n "    $pkg ... "
        if python3 -c "import $pkg" 2>/dev/null; then
            echo -e "${GREEN}✓${NC}"
        else
            echo -e "${RED}✗${NC}"
        fi
    done
else
    echo -e "${YELLOW}  [!] 虚拟环境未找到: /mnt/d/AI/cursor/starone/.venv${NC}"
fi

# 测试 5: 数据目录
echo ""
echo -e "${BLUE}[测试组 5] 数据目录${NC}"
echo "----------------------------------------"

CVE_DIR="/mnt/d/AI/Claude/CVE"
if [ -d "$CVE_DIR" ]; then
    run_test "项目目录存在" "test -d $CVE_DIR"
    run_test "数据目录可写" "test -w $CVE_DIR"
    
    # 检查 SQLite 数据库
    if [ -f "$CVE_DIR/cve_data/cve_database.db" ]; then
        DB_SIZE=$(du -h "$CVE_DIR/cve_data/cve_database.db" | cut -f1)
        echo "  SQLite 数据库大小: $DB_SIZE"
    else
        echo "  SQLite 数据库: 未创建（首次运行时自动创建）"
    fi
else
    echo -e "${RED}  [!] 项目目录不存在: $CVE_DIR${NC}"
fi

# 测试 6: GPU 可用性（可选）
echo ""
echo -e "${BLUE}[测试组 6] GPU 可用性（可选）${NC}"
echo "----------------------------------------"

if command -v nvidia-smi &> /dev/null; then
    GPU_INFO=$(nvidia-smi --query-gpu=name,memory.total --format=csv,noheader)
    echo -e "  GPU: ${GREEN}$GPU_INFO${NC}"
    CUDA_VERSION=$(nvidia-smi | grep "CUDA Version" | awk '{print $9}')
    echo -e "  CUDA: ${GREEN}$CUDA_VERSION${NC}"
else
    echo -e "  GPU: ${YELLOW}未检测到（GPU 加速功能不可用）${NC}"
fi

# 测试总结
echo ""
echo "========================================"
echo "测试总结"
echo "========================================"
echo "总测试数: $TOTAL_TESTS"
echo -e "通过: ${GREEN}$PASSED_TESTS${NC}"
echo -e "失败: ${RED}$FAILED_TESTS${NC}"

if [ $FAILED_TESTS -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✓ 所有核心测试通过！环境配置正确。${NC}"
    echo ""
    echo "下一步操作:"
    echo "  1. 启动 CVE 系统"
    echo "     cd /mnt/d/AI/Claude/CVE"
    echo "     source /mnt/d/AI/cursor/starone/.venv/bin/activate"
    echo "     python cve_integrated_gui.py"
    echo ""
    echo "  2. 或使用 Windows 批处理文件启动"
    echo "     双击: 启动CVE系统-WSL.bat"
else
    echo ""
    echo -e "${YELLOW}⚠ 部分测试失败，请检查上述输出并修复问题${NC}"
    echo ""
    echo "常见问题修复:"
    echo "  - Redis 未运行: sudo service redis-server start"
    echo "  - Python 依赖缺失: pip install -r requirements.txt"
    echo "  - 虚拟环境未找到: 检查路径是否正确"
fi

echo "========================================"
