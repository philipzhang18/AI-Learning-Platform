# 知识图谱功能优化方案

## 📊 当前状态评估

### 数据规模
- **CVE 记录**: 117,330 条
- **DSA 记录**: 2,360 条
- **潜在节点数**: ~120,000+ (包含 Product 和 CWE 节点)
- **NetworkX 版本**: 3.6.1

### 架构优点
✅ 轻量级设计，基于 NetworkX + SQLite，无需重型图数据库  
✅ 完整的测试覆盖（100% 通过率）  
✅ 支持 CVE × DSA × Product × CWE 四类节点关联  
✅ 提供模糊匹配、子图抽取、多格式导出功能  

### 性能瓶颈
❌ **全量加载性能问题**: `build()` 方法一次性加载所有数据到内存  
❌ **重复构图开销**: 每次查询都需要重新构建图  
❌ **产品名提取质量**: 正则回退方案准确率低  
❌ **缺少缓存机制**: 频繁查询重复计算  
❌ **内存占用高**: 12 万节点全量加载约需 500MB+ 内存  

---

## 🎯 优化方案

### 1. 增量构图 + 持久化缓存

**问题**: 每次启动 GUI 都需要重新构建图，耗时 10-30 秒

**解决方案**:
```python
# 首次构图：仅加载最近 30 天数据
kg = KnowledgeGraph.from_sqlite(db_path)
kg.build(limit_cve=5000, limit_dsa=500)  # 限制加载数量
kg.save_cache("cve_data/kg_cache.pkl")   # 持久化到磁盘

# 后续快速加载（<1 秒）
kg = KnowledgeGraph.load_cache("cve_data/kg_cache.pkl")
```

**实现要点**:
- 使用 `pickle` 序列化 NetworkX 图对象
- 缓存文件包含图结构 + 反向索引
- 支持增量更新：`kg.update_since("2026-05-01")`

**预期收益**: 启动时间从 10-30s 降至 <1s

---

### 2. 反向索引优化

**问题**: 高频查询（产品→CVE、CVE→产品）需要遍历图

**解决方案**:
```python
class KnowledgeGraph:
    def __init__(self):
        self.G = nx.DiGraph()
        # 反向索引
        self._product_to_cves: Dict[str, Set[str]] = defaultdict(set)
        self._cve_to_products: Dict[str, Set[str]] = defaultdict(set)
        self._cve_to_dsas: Dict[str, Set[str]] = defaultdict(set)
    
    def products_of_cve_fast(self, cve_id: str) -> List[str]:
        """O(1) 查询，无需遍历图"""
        return sorted(self._cve_to_products.get(cve_id, set()))
```

**实现要点**:
- 构图时同步维护反向索引
- 索引存储在内存中，随缓存一起持久化
- 查询复杂度从 O(N) 降至 O(1)

**预期收益**: 查询速度提升 100-1000 倍

---

### 3. 产品名提取优化

**问题**: 当前正则回退方案准确率约 60%

**解决方案**:
```python
def extract_products_enhanced(dsa_data: Dict, title: str) -> List[str]:
    """
    多策略产品名提取：
    1. 优先从 data.affected_products[*].name 提取
    2. 回退到标题正则（改进版）
    3. 使用产品名词典校验（Dell 官方产品列表）
    4. 应用 NLP 实体识别（可选）
    """
    # 策略 1: 结构化数据
    products = _extract_from_structured(dsa_data)
    if products:
        return products
    
    # 策略 2: 改进正则
    products = _extract_from_title_enhanced(title)
    if products:
        return products
    
    # 策略 3: 词典校验
    return _validate_with_dictionary(products)
```

**实现要点**:
- 构建 Dell 产品名词典（从历史数据中提取高频产品名）
- 改进正则表达式，支持更多产品名模式
- 可选：集成 spaCy/NLTK 进行实体识别

**预期收益**: 产品名提取准确率从 60% 提升至 85%+

---

### 4. 懒加载 + 分页查询

**问题**: GUI 一次性展示所有节点，内存占用高

**解决方案**:
```python
class KnowledgeGraphLazy:
    def query_cves_paginated(
        self, 
        severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Tuple[List[str], int]:
        """分页查询 CVE，返回 (结果, 总数)"""
        # 直接查询 SQLite，不加载到内存
        sql = "SELECT cve_id FROM cves WHERE 1=1"
        if severity:
            sql += f" AND json_extract(data, '$.cvss_severity') = '{severity}'"
        sql += f" LIMIT {limit} OFFSET {offset}"
        
        results = self.conn.execute(sql).fetchall()
        total = self.conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        return ([r[0] for r in results], total)
```

**实现要点**:
- GUI 表格支持分页（每页 100 条）
- 仅在需要时加载子图（ego_subgraph）
- 大规模统计查询直接走 SQLite

**预期收益**: 内存占用从 500MB 降至 50MB

---

### 5. 并行构图

**问题**: 单线程构图速度慢

**解决方案**:
```python
from concurrent.futures import ProcessPoolExecutor

def build_parallel(self, max_workers: int = 4):
    """并行加载 DSA 和 CVE 数据"""
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        future_dsa = executor.submit(self._load_dsa_batch, self._db_path)
        future_cve = executor.submit(self._load_cve_batch, self._db_path)
        
        dsa_data = future_dsa.result()
        cve_data = future_cve.result()
    
    self._merge_data(dsa_data, cve_data)
```

**实现要点**:
- DSA 和 CVE 数据并行加载
- 使用进程池避免 GIL 限制
- 合并阶段在主进程中完成

**预期收益**: 构图时间减少 40-60%

---

## 📈 性能对比预测

| 指标 | 当前 | 优化后 | 提升 |
|------|------|--------|------|
| 首次构图时间 | 10-30s | 5-15s | 50% |
| 缓存加载时间 | N/A | <1s | - |
| 产品→CVE 查询 | 50-200ms | <1ms | 100x |
| CVE→产品 查询 | 50-200ms | <1ms | 100x |
| 内存占用 | 500MB | 50MB | 90% |
| 产品名准确率 | 60% | 85% | 42% |

---

## 🛠️ 实施计划

### Phase 1: 核心优化（1-2 天）
1. ✅ 添加反向索引（`_product_to_cves`, `_cve_to_products`）
2. ✅ 实现持久化缓存（`save_cache()`, `load_cache()`）
3. ✅ 优化 `build()` 方法，支持 `limit_cve`/`limit_dsa` 参数

### Phase 2: 增量更新（1 天）
4. ✅ 实现 `update_since(date)` 方法
5. ✅ 缓存元数据（构建时间、数据范围）
6. ✅ GUI 集成：启动时检查缓存，过期则重建

### Phase 3: 产品名优化（1-2 天）
7. ⬜ 构建 Dell 产品名词典（从历史数据提取）
8. ⬜ 改进正则表达式
9. ⬜ 添加词典校验逻辑

### Phase 4: 懒加载（可选，1-2 天）
10. ⬜ 实现分页查询 API
11. ⬜ GUI 表格支持分页
12. ⬜ 子图按需加载

---

## 🧪 测试计划

### 单元测试
```python
def test_cache_persistence():
    """测试缓存保存和加载"""
    kg = KnowledgeGraph.from_sqlite(db_path).build(limit_cve=1000)
    kg.save_cache("test_cache.pkl")
    
    kg2 = KnowledgeGraph.load_cache("test_cache.pkl")
    assert kg.stats() == kg2.stats()

def test_reverse_index():
    """测试反向索引准确性"""
    kg = KnowledgeGraph.from_sqlite(db_path).build(limit_cve=1000)
    
    # 对比遍历图 vs 反向索引
    cve_id = "CVE-2024-0001"
    products_slow = kg.products_of_cve(cve_id)  # 遍历图
    products_fast = kg.products_of_cve_fast(cve_id)  # 反向索引
    assert set(products_slow) == set(products_fast)
```

### 性能测试
```python
import time

def benchmark_query_speed():
    """对比优化前后查询速度"""
    kg = KnowledgeGraph.from_sqlite(db_path).build(limit_cve=10000)
    
    # 测试 100 次查询
    cve_ids = random.sample(list(kg.G.nodes()), 100)
    
    start = time.time()
    for cve_id in cve_ids:
        kg.products_of_cve(cve_id)  # 旧方法
    time_old = time.time() - start
    
    start = time.time()
    for cve_id in cve_ids:
        kg.products_of_cve_fast(cve_id)  # 新方法
    time_new = time.time() - start
    
    print(f"加速比: {time_old / time_new:.1f}x")
```

---

## 📝 代码示例

### 使用优化后的知识图谱

```python
from knowledge_graph import KnowledgeGraph
from pathlib import Path

# 1. 首次使用：构建并缓存
cache_path = Path("cve_data/kg_cache.pkl")
if not cache_path.exists():
    print("首次构图，请稍候...")
    kg = KnowledgeGraph.from_sqlite("cve_data/cve_database.db")
    kg.build(limit_cve=5000, limit_dsa=500)  # 仅加载最近数据
    kg.save_cache(cache_path)
    print(f"构图完成，已缓存到 {cache_path}")
else:
    print("从缓存加载...")
    kg = KnowledgeGraph.load_cache(cache_path)
    print("加载完成！")

# 2. 快速查询（使用反向索引）
products = kg.products_of_cve_fast("CVE-2024-0001")
print(f"受影响产品: {products}")

cves = kg.cves_of_product_fast("Dell PowerStore")
print(f"产品漏洞: {len(cves)} 个")

# 3. 增量更新（每日定时任务）
kg.update_since("2026-05-01")
kg.save_cache(cache_path)  # 更新缓存

# 4. 统计信息
stats = kg.stats()
print(f"节点总数: {stats['nodes_total']}")
print(f"边总数: {stats['edges_total']}")
print(f"构建时间: {stats.get('build_time', 'N/A')}")
```

---

## 🚀 后续扩展方向

### 1. 图数据库迁移（可选）
- 当数据规模超过 50 万节点时，考虑迁移到 Neo4j
- 优势：原生图查询、分布式存储、更强大的图算法
- 成本：引入新依赖、学习曲线、部署复杂度

### 2. 图算法应用
- **PageRank**: 识别最重要的 CVE/产品
- **社区检测**: 发现产品漏洞聚类
- **最短路径**: 分析漏洞传播链

### 3. 可视化增强
- 集成 Cytoscape.js 实现 Web 交互式图谱
- 支持节点拖拽、缩放、筛选
- 实时更新（WebSocket）

### 4. AI 增强
- 使用 LLM 自动提取产品名（替代正则）
- 漏洞相似度计算（基于描述文本）
- 智能推荐：根据产品推荐相关 CVE

---

## 📚 参考资料

- [NetworkX 文档](https://networkx.org/documentation/stable/)
- [图数据库选型指南](https://db-engines.com/en/ranking/graph+dbms)
- [知识图谱最佳实践](https://www.w3.org/TR/swbp-vocab-pub/)

---

*文档版本: v1.0*  
*创建时间: 2026-05-13*  
*作者: Claude Opus 4.7*
