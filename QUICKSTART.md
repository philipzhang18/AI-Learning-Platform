# CVE 漏洞监控系统 - 快速开始指南

**版本**: v3.6
**预计完成时间**: 5-10 分钟

---

## 🚀 三步快速启动

### 步骤 1: 准备环境（2 分钟）

```bash
# 1. 确认 Python 版本
python --version
# 应该是 3.12 或更高版本

# 2. 克隆项目（如果还没有）
cd E:\AI\Claude\CVE
```

### 步骤 2: 启动 Redis（1 分钟）

```bash
# 在 WSL 中启动 Redis
wsl sudo service redis-server start

# 验证 Redis 运行
wsl redis-cli PING
# 应返回 PONG
```

### 步骤 3: 运行应用（1 分钟）

```bash
# 安装 Python 依赖（首次运行）
pip install -r requirements.txt

# 启动 GUI 应用
python cve_integrated_gui.py
```

**完成！** 应用窗口应该已经打开。

---

## 📝 首次使用流程

### 场景 1: 采集 NVD CVE 数据

1. **切换到"NVD CVE 数据"标签页**
2. **选择时间范围**: 例如"1个月"
3. **点击"▶ 采集 NVD 数据"**
4. **等待采集完成**（通常 5-15 分钟）
5. **查看结果**: 数据自动显示在列表中
6. **双击任意 CVE**: 查看详细信息

**预期结果**:
```
✓ 成功获取 XXX 条 CVE 数据
✓ 新增 XXX 条
✓ 数据库总计 XXX 条
```

### 场景 2: 采集 Dell 安全公告

1. **切换到"Dell 安全公告"标签页**
2. **选择时间范围**: 例如"1个月"
3. **点击"▶ 采集Dell安全公告"**
4. **等待采集完成**（通常 1-3 分钟）
5. **查看结果**: 公告自动显示在列表中

**预期结果**:
```
✓ 成功获取 XX 条 Dell 安全公告
✓ 新增 XX 条
✓ 数据库总计 XXX 条
```

### 场景 3: 加载本地 CSV 数据

1. **切换到"Dell 安全公告"标签页**
2. **点击"📊 加载CSV数据"**
3. **选择 CSV 文件**（Dell 安全公告格式）
4. **自动解析和导入**

**CSV 格式要求**:
```csv
TITLE,CVE IDENTIFIER,PUBLISHED,IMPACT
DSA-2025-386: Security Update...,CVE-2024-12345,OCT 29 2025,HIGH
```

**预期结果**:
```
✓ 成功加载 Dell CSV 数据
✓ 新增 XX 条
✓ 新增数据已保存到 dell_csv_new_YYYYMMDD_HHMMSS.json
✓ 全量数据已保存到 dell_csv_full_YYYYMMDD_HHMMSS.json
```

### 场景 4: 查看关联匹配

1. **切换到"CVE-Dell 关联"标签页**
2. **点击"🔄 刷新关联数据"**（或自动刷新）
3. **查看匹配结果**

**预期结果**:
- 显示 CVE ID、严重等级、Dell 公告 ID、受影响产品
- 提供解决方案预览
- 双击查看完整关联详情

### 场景 5: 查看统计分析

1. **切换到"统计分析"标签页**
2. **查看数据统计**:
   - NVD CVE 总数
   - Dell 公告数
   - 关联匹配数
   - 严重等级分布（CRITICAL/HIGH/MEDIUM/LOW）

---

## ⚡ 性能优化建议

### 必做优化

1. **配置 NVD API Key**（强烈推荐）

```bash
# 1. 申请免费 API Key
# https://nvd.nist.gov/developers/request-an-api-key

# 2. 设置环境变量
# Windows PowerShell:
$env:NVD_API_KEY="your-api-key-here"

# Linux/Mac:
export NVD_API_KEY="your-api-key-here"
```

**效果**: 采集速度提升 **10 倍** ⚡

### 可选优化

2. **确保 Redis 运行**

```bash
# 检查 Redis 状态
wsl redis-cli PING

# 如果未运行，启动它
wsl sudo service redis-server start
```

**效果**: 数据加载和统计计算提升 **20-300 倍** 🚀

---

## 🐛 常见问题快速解决

### 问题 1: Redis 连接失败

**症状**:
```
Redis 连接失败 - 回退到 SQLite 模式
```

**解决方案**:
```bash
# 启动 Redis（WSL）
wsl sudo service redis-server start

# 重启应用
python cve_integrated_gui.py
```

### 问题 2: 采集速度慢

**症状**: NVD 采集每次请求需要 6 秒

**解决方案**: 配置 NVD API Key（见上方"性能优化建议"）

### 问题 3: CSV 加载失败

**症状**:
```
加载CSV文件失败: 'utf-8' codec can't decode
```

**解决方案**:
- 使用文本编辑器（如 VSCode）将 CSV 转换为 UTF-8 编码
- 或使用 Excel "另存为" → 选择 "CSV UTF-8"

### 问题 4: 界面卡顿

**已自动优化**:
- ✅ 数据采集增量显示
- ✅ 关联匹配算法优化
- ✅ 限制显示数量

**如仍然卡顿**: 清理旧数据，只保留最近 6-12 个月

---

## 📊 数据说明

### 数据存储位置

```
cve_data/
├── cve_database.db              # SQLite 数据库（本地备份）
├── cves_YYYYMMDD_HHMMSS.json   # NVD CVE 数据文件
├── dell_advisories_*.json       # Dell 公告数据文件
└── dell_csv_*.json              # CSV 导入数据
```

### Redis 数据

- **位置**: WSL Redis 本地存储（`/var/lib/redis/`）
- **持久化**: 自动保存到本地磁盘
- **查看数据**:
```bash
wsl redis-cli
> KEYS cve:*
> GET cve:CVE-2024-12345
```

---

## 🔗 下一步

- 阅读 [README.md](README.md) 了解完整功能
- 查看 [CONFIG.md](CONFIG.md) 进行高级配置
- 浏览 [docs/](docs/) 目录查看详细优化报告

---

## ❓ 需要帮助？

- **GitHub Issues**: https://github.com/philipzhang18/CVE-Security-Solution/issues
- **配置指南**: [CONFIG.md](CONFIG.md)
- **完整文档**: [README.md](README.md)

---

**维护者**: Claude AI + Philip Zhang
**最后更新**: 2025-11-02
**指南版本**: v3.6

**🎉 现在开始使用 CVE 漏洞监控系统！**
