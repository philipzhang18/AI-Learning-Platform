#!/bin/bash
# GPU 服务功能测试脚本

echo "========================================"
echo "CVE 系统 - GPU 功能测试"
echo "========================================"
echo ""

cd /D/AI/Claude/CVE

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
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

# 测试 1: Docker 服务状态
echo "[测试组 1] Docker 服务状态"
echo "----------------------------------------"

run_test "MongoDB 容器运行" "docker ps | grep -q cve-mongodb"
run_test "Redis 容器运行" "docker ps | grep -q cve-redis"
run_test "PostgreSQL 容器运行" "docker ps | grep -q cve-postgres-vector"
run_test "Ollama 容器运行" "docker ps | grep -q cve-ollama"

# 测试 2: 服务连接性
echo ""
echo "[测试组 2] 服务连接性"
echo "----------------------------------------"

run_test "Redis 连接" "docker exec cve-redis redis-cli -a defaultpassword PING | grep -q PONG"
run_test "MongoDB 连接" "docker exec cve-mongodb mongosh --eval 'db.adminCommand(\"ping\")' --quiet | grep -q ok"
run_test "PostgreSQL 连接" "docker exec cve-postgres-vector pg_isready -U admin | grep -q 'accepting connections'"
run_test "Ollama API 连接" "curl -s http://localhost:11434/api/tags"

# 测试 3: GPU 可用性
echo ""
echo "[测试组 3] GPU 可用性"
echo "----------------------------------------"

if docker exec cve-ollama nvidia-smi >/dev/null 2>&1; then
    echo -n "[$((TOTAL_TESTS + 1))] GPU 在容器中可见 ... "
    echo -e "${GREEN}✓ PASS${NC}"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    PASSED_TESTS=$((PASSED_TESTS + 1))

    # 显示 GPU 信息
    echo ""
    echo "GPU 信息:"
    docker exec cve-ollama nvidia-smi --query-gpu=name,memory.total,memory.used --format=csv,noheader | sed 's/^/  /'
else
    echo -n "[$((TOTAL_TESTS + 1))] GPU 在容器中可见 ... "
    echo -e "${YELLOW}⚠ WARN${NC}"
    echo "  提示: GPU 不可用，可能影响性能"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
fi

# 测试 4: Ollama 模型
echo ""
echo "[测试组 4] Ollama 模型检查"
echo "----------------------------------------"

MODELS=$(curl -s http://localhost:11434/api/tags | grep -o '"name":"[^"]*"' | cut -d'"' -f4)

if [ -z "$MODELS" ]; then
    echo -e "${YELLOW}[!] 未安装任何模型${NC}"
    echo ""
    echo "推荐安装以下模型："
    echo "  1. nomic-embed-text  - 向量生成 (~137MB)"
    echo "     docker exec -it cve-ollama ollama pull nomic-embed-text"
    echo ""
    echo "  2. qwen2.5:3b        - CVE 智能分析 (~2GB)"
    echo "     docker exec -it cve-ollama ollama pull qwen2.5:3b"
    echo ""
else
    echo "已安装的模型:"
    echo "$MODELS" | sed 's/^/  - /'
    echo ""

    # 测试向量生成模型
    if echo "$MODELS" | grep -q "nomic-embed-text"; then
        echo -n "测试向量生成 (nomic-embed-text) ... "
        if curl -s -X POST http://localhost:11434/api/embeddings \
            -d '{"model":"nomic-embed-text","prompt":"test"}' | grep -q "embedding"; then
            echo -e "${GREEN}✓ OK${NC}"
        else
            echo -e "${RED}✗ FAIL${NC}"
        fi
    fi
fi

# 测试 5: Python 环境
echo ""
echo "[测试组 5] Python 环境检查"
echo "----------------------------------------"

# 激活虚拟环境并测试
source /D/AI/cursor/starone/.venv/Scripts/activate 2>/dev/null

run_test "虚拟环境可用" "test -f /D/AI/cursor/starone/.venv/Scripts/python.exe"
run_test "psycopg2 已安装" "/D/AI/cursor/starone/.venv/Scripts/python.exe -c 'import psycopg2'"
run_test "requests 已安装" "/D/AI/cursor/starone/.venv/Scripts/python.exe -c 'import requests'"

# 测试 6: 数据库表结构
echo ""
echo "[测试组 6] 向量数据库检查"
echo "----------------------------------------"

# 检查 pgvector 扩展
echo -n "pgvector 扩展已安装 ... "
if docker exec cve-postgres-vector psql -U admin -d cve_vectors -c "SELECT * FROM pg_extension WHERE extname='vector';" 2>/dev/null | grep -q "vector"; then
    echo -e "${GREEN}✓ PASS${NC}"
else
    echo -e "${YELLOW}⚠ NOT FOUND${NC}"
    echo "  提示: 运行初始化脚本创建扩展"
fi

# 检查表是否存在
echo -n "cve_embeddings 表存在 ... "
if docker exec cve-postgres-vector psql -U admin -d cve_vectors -c "\dt cve_embeddings" 2>/dev/null | grep -q "cve_embeddings"; then
    echo -e "${GREEN}✓ PASS${NC}"

    # 显示记录数
    COUNT=$(docker exec cve-postgres-vector psql -U admin -d cve_vectors -t -c "SELECT COUNT(*) FROM cve_embeddings;" 2>/dev/null | tr -d ' ')
    echo "  向量记录数: $COUNT"
else
    echo -e "${YELLOW}⚠ NOT FOUND${NC}"
    echo "  提示: 表将在首次同步时自动创建"
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
    echo -e "${GREEN}✓ 所有核心测试通过！${NC}"
    echo ""
    echo "下一步操作:"
    echo "  1. 安装 LLM 模型（如果还没有）"
    echo "     docker exec -it cve-ollama ollama pull nomic-embed-text"
    echo ""
    echo "  2. 运行 GPU 同步脚本"
    echo "     source /D/AI/cursor/starone/.venv/Scripts/activate"
    echo "     python gpu_cve_sync.py"
    echo ""
    echo "  3. 测试性能"
    echo "     python gpu_performance_test.py"
else
    echo ""
    echo -e "${YELLOW}⚠ 部分测试失败，请检查上述输出${NC}"
fi

echo "========================================"
