"""README for DAO Layer

## 数据访问层 (DAO) 架构

将所有数据库操作从 GUI 层分离出来，实现关注点分离。

### 结构

```
dao/
├── __init__.py          # DAO 包入口
├── cve_dao.py           # CVE 数据访问
├── dell_dao.py          # Dell 安全公告数据访问
└── dell_kb_dao.py       # Dell 技术库数据访问
```

### 使用方式

```python
from dao import CveDAO, DellAdvisoryDAO, DellKbDAO

# 初始化 DAO
cve_dao = CveDAO(conn)
dell_dao = DellAdvisoryDAO(conn)
kb_dao = DellKbDAO(conn)

# 查询单条记录
cve = cve_dao.get_by_id("CVE-2024-1234")

# 搜索（使用 FTS5）
results = cve_dao.search_by_keyword("PowerEdge", limit=100)

# 插入/更新
cve_dao.insert(cve_data)

# 批量删除
cve_dao.delete_by_ids(["CVE-2024-1", "CVE-2024-2"])

# 统计
total = cve_dao.count_total()
```

### 优势

1. **关注点分离**: GUI 不再直接写 SQL
2. **代码复用**: 消除重复的数据库操作代码
3. **易于测试**: DAO 方法可以独立单元测试
4. **易于维护**: 修改数据库 schema 只需改 DAO 层
5. **性能优化**: 在 DAO 层统一优化查询（FTS5、索引等）

### 迁移计划

逐步将 `cve_integrated_gui.py` 中的 SQL 操作迁移到 DAO：

- [ ] CVE 查询操作 → `CveDAO`
- [ ] Dell 公告操作 → `DellAdvisoryDAO`
- [ ] Dell 技术库操作 → `DellKbDAO`
- [ ] AI 解决方案操作 → `AiSolutionDAO` (待创建)
- [ ] 学习模块操作 → `LearnDAO` (待创建)
"""
