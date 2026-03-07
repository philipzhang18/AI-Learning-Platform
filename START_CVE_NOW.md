# CVE 程序快速启动指南

## 🚀 立即启动

### 方法 1: 双击启动（推荐）

进入目录 `E:\AI\Claude\CVE`，双击运行：

```
start_cve_with_wsl_redis.bat
```

**自动完成**：
- 在 WSL 中启动 Redis 服务
- 验证 Redis 连接
- 启动 CVE GUI 程序

---

### 方法 2: Git Bash 手动启动

```bash
# 1. 启动 WSL Redis
wsl sudo service redis-server start

# 2. 进入项目目录
cd /E/AI/Claude/CVE

# 3. 激活虚拟环境
source /E/AI/cursor/starone/.venv/Scripts/activate

# 4. 启动程序
python cve_integrated_gui.py
```

---

### 方法 3: Windows PowerShell

```powershell
cd E:\AI\Claude\CVE
.\start_cve_with_wsl_redis.bat
```

---

## 📊 启动后界面说明

| 标签页 | 功能 |
|--------|------|
| 📰 IT新闻早晚报 | RSS 新闻采集与阅读 |
| 📊 NVD CVE 数据 | 采集/查看/搜索/删除 CVE 数据 |
| 🏢 Dell 安全公告 | 采集/URL抓取/查看/删除 Dell 公告 |
| 🔗 CVE-Dell 关联 | 自动关联匹配结果 |
| 💡 解决方案 | AI 生成漏洞修复方案 |
| 📈 统计分析 | 数据总览与分布图 |
| 🧠 智能学习 | 费曼学习法辅助 |
| 📝 操作日志 | 实时运行日志 |

---

## 🔧 故障排查

### Redis 连接失败

```bash
# WSL 中启动 Redis
wsl sudo service redis-server start

# 验证
wsl redis-cli PING
# 应返回 PONG
```

程序无 Redis 时自动降级为 SQLite 模式，功能不受影响。

### GUI 窗口无法打开

```bash
# 验证 Tkinter
/E/AI/cursor/starone/.venv/Scripts/python.exe -c "import tkinter; print('OK')"

# 确认数据库文件存在
ls -lh /E/AI/Claude/CVE/cve_data/cve_database.db
```

---

**启动脚本**: `start_cve_with_wsl_redis.bat`
**数据库**: `cve_data/cve_database.db`（SQLite）
**Python**: `E:\AI\cursor\starone\.venv\Scripts\python.exe`
