# CVE 集成监控系统配置说明

## 已实现功能概述

### 1. CSV 数据加载功能
- **位置限制**: CSV 加载按钮仅在 Dell 安全公告界面可用
- **文件路径**: 默认查找 `d:/download/sample_2025_10_30.csv`
- **格式支持**: 自动识别 CSV 分隔符，支持多种字段命名方式

### 2. 手动搜索功能
- **触发方式**: 仅通过点击搜索按钮触发（禁用实时搜索）
- **应用范围**: NVD CVE 数据和 Dell 安全公告均支持
- **性能优化**: 减少不必要的实时计算，提升响应速度

### 3. 本地数据库增量收集
- **数据库类型**: SQLite 本地数据库
- **增量逻辑**: 只收集并存储新发现的 CVE 数据
- **数据持久化**: 应用重启后保留所有收集的数据
- **分块收集**: 避免 NVD API 日期范围限制（120天分块）

## 技术实现细节

### 数据库结构
```sql
-- CVE 数据表
CREATE TABLE cves (
    cve_id TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    last_modified TEXT,
    published_date TEXT
);

-- 收集历史表
CREATE TABLE collection_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT,
    collected_date TEXT,
    FOREIGN KEY (cve_id) REFERENCES cves (cve_id)
);
```

### 增量收集工作流程
1. 查询数据库中已存在的 CVE ID 列表
2. 从 NVD API 收集指定时间范围内的新数据
3. 对比新数据与现有数据，只存储新发现的 CVE
4. 更新已存在但可能变更的 CVE 信息
5. 将所有数据加载到界面供用户查看

### 错误处理机制
- **API 404 错误**: 自动分块处理大时间范围请求
- **数据库错误**: 参数验证和事务回滚机制
- **网络错误**: 重试机制和优雅降级

## 配置文件说明

### 主要配置项
- `version`: 配置版本号
- `features`: 各功能模块状态
- `database_config`: 数据库配置信息
- `api_settings`: API 调用设置

### 文件路径
- 主程序: `cve_integrated_gui.py`
- 数据库: `cve_data/cve_database.db`
- 示例CSV: `d:/download/sample_2025_10_30.csv`

## 使用注意事项

1. **首次运行**: 系统会自动创建数据库和数据目录
2. **数据收集**: 建议配置 NVD API Key 以获得更快的收集速度
3. **CSV 加载**: 确保 CSV 文件格式正确且包含 CVE ID 字段
4. **搜索功能**: 输入关键字后需点击搜索按钮才能触发查询

## 性能优化特性

- **数据库索引**: CVE ID 字段为主键，查询速度快
- **内存管理**: 分批处理大数据集，避免内存溢出
- **并发控制**: 线程安全的数据库操作
- **API 礼貌**: 请求间适当延时，避免对服务器造成压力