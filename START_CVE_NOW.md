# CVE 程序快速启动指南

## 🎯 当前系统状态

✅ **后端服务已就绪**

```
服务名称           内存使用      状态
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MongoDB 7.0       271.6MB      健康运行
Redis 7           3.3MB        健康运行
Redis Commander   17MB         运行中
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
数据完整性:       51,126 CVE + 431 Dell ✓
```

---

## 🚀 立即启动 CVE 程序

### 方法 1: Git Bash / Linux 终端（推荐）

打开 Git Bash，执行：

```bash
cd /D/AI/Claude/CVE
bash start_cve_gui.sh
```

**效果**：
- 自动检查并启动后端服务
- 启动 CVE 漏洞监控系统 GUI
- 显示系统状态信息

---

### 方法 2: Windows 双击启动

**最简单的方式**：

1. 打开文件资源管理器
2. 进入目录：`D:\AI\Claude\CVE`
3. 双击运行：`启动CVE程序.bat`

**自动完成**：
- ✓ 检查后端服务
- ✓ 启动 MongoDB/Redis（如需要）
- ✓ 启动 GUI 程序

---

### 方法 3: Windows PowerShell

打开 PowerShell，执行：

```powershell
cd D:\AI\Claude\CVE
.\启动CVE程序.bat
```

---

### 方法 4: 手动启动（高级）

如果您希望完全控制启动流程：

```bash
# 1. 进入项目目录
cd /D/AI/Claude/CVE

# 2. 确认后端服务运行
docker ps | grep -E "cve-mongodb|cve-redis"

# 3. 如果服务未运行，启动它们
docker-compose -f docker-compose-mongodb-optimized.yml up -d

# 4. 启动 GUI
/D/AI/cursor/starone/.venv/Scripts/python.exe cve_integrated_gui.py
```

---

## 📊 启动后你将看到

### GUI 界面包含 5 个标签页

#### 1. 📊 NVD CVE 数据
- 采集 NVD 官方 CVE 数据
- 支持时间范围选择（一周/1个月/3个月/半年/1年）
- 显示 CVE ID、严重等级、CVSS 评分、发布日期、描述
- 支持搜索过滤

#### 2. 🏢 Dell 安全公告
- 采集 Dell 官方安全公告
- 显示 DSA 公告 ID、标题、相关 CVE、发布日期
- 支持加载 CSV 数据
- 产品型号匹配

#### 3. 🔗 CVE-Dell 关联
- 自动关联 NVD CVE 与 Dell 公告
- 显示完整的漏洞影响链
- Dell 产品受影响信息
- 解决方案预览

#### 4. 📈 统计分析
- 数据总览（CVE 总数、Dell 公告数、关联数）
- 严重等级分布（CRITICAL/HIGH/MEDIUM/LOW）
- 最新 CVE 列表
- 最新 Dell 公告列表

#### 5. 📝 操作日志
- 实时显示所有操作日志
- 数据采集进度
- 错误提示信息

---

## 💡 首次使用建议

### 第一步：查看本地数据

程序启动后，会自动从数据库加载现有数据：

```
已从数据库加载 NVD 数据: 51,126 条
从 Redis 加载 Dell 数据: 431 条
关联匹配完成：找到 XXX 条匹配的 CVE-Dell 数据
```

### 第二步：浏览各个标签页

1. 点击 **"📊 NVD CVE 数据"** 查看 CVE 列表
2. 点击 **"🏢 Dell 安全公告"** 查看 Dell 公告
3. 点击 **"🔗 CVE-Dell 关联"** 查看匹配结果
4. 点击 **"📈 统计分析"** 查看数据统计

### 第三步：尝试采集新数据（可选）

如需更新数据：

1. 在 NVD 标签页点击 **"▶ 采集 NVD 数据"**
2. 选择时间范围（建议：1个月）
3. 等待采集完成（约 1-2 分钟）

**注意**：
- 如已配置 `NVD_API_KEY` 环境变量，采集速度可提升 10 倍
- 未配置 API Key 时，采集速度较慢但仍可使用

---

## 🔧 故障排查

### 问题 1: GUI 窗口无法打开

**可能原因**：Tkinter 依赖缺失

**解决方法**：
```bash
# 验证 Tkinter
/D/AI/cursor/starone/.venv/Scripts/python.exe -c "import tkinter; print('OK')"
```

如提示错误，需要重新安装 Python（确保包含 Tkinter 支持）。

---

### 问题 2: 提示 MongoDB 连接失败

**症状**：日志显示 "Redis 连接失败 - 回退到 SQLite 模式"

**解决方法**：
```bash
# 检查服务状态
docker ps | grep cve-

# 如服务未运行，启动它们
cd /D/AI/Claude/CVE
docker-compose -f docker-compose-mongodb-optimized.yml up -d
```

---

### 问题 3: 数据显示为空

**可能原因**：数据库文件路径错误

**解决方法**：
```bash
# 确认数据库文件存在
ls -lh /D/AI/Claude/CVE/cve_data/cve_database.db

# 应显示约 143MB 的数据库文件
```

如文件不存在，请从备份恢复：
```bash
cp /D/AI/Claude/CVE/backups/cve_database_backup_*.db /D/AI/Claude/CVE/cve_data/cve_database.db
```

---

### 问题 4: Redis 连接警告

**症状**：日志显示 "Redis 初始化失败 - 回退到 SQLite 模式"

**说明**：这是正常的降级行为，不影响功能

- 当前 GUI 主要使用 SQLite 数据库
- Redis 作为可选缓存层
- 即使 Redis 不可用，程序仍可正常运行

**如需启用 Redis**：
```bash
docker-compose -f docker-compose-mongodb-optimized.yml up -d redis
```

---

## 📚 相关文档

| 文档名称 | 说明 |
|---------|------|
| `RUN_CVE_GUIDE.md` | 完整使用指南（详细） |
| `DEPLOYMENT_REPORT_20251104.md` | MongoDB 部署报告 |
| `DOCKER_OPTIMIZATION_REPORT.md` | Docker 优化报告 |
| `start_cve_gui.sh` | Linux 启动脚本 |
| `启动CVE程序.bat` | Windows 启动脚本 |

---

## 🎉 现在就启动！

**推荐命令（Git Bash）**：
```bash
cd /D/AI/Claude/CVE && bash start_cve_gui.sh
```

**或者双击运行**：
```
D:\AI\Claude\CVE\启动CVE程序.bat
```

---

**系统已完全就绪，祝您使用愉快！** 🚀

如遇到问题，请参考本文档的故障排查章节。
