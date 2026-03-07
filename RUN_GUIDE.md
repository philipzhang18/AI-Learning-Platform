# CVE项目启动指南

**日期**: 2025-11-04
**程序**: cve_integrated_gui.py
**状态**: ✅ 已启动

---

## 🚀 启动步骤

### 自动启动（刚才执行的）

```bash
# 1. 切换到项目目录
cd /E/AI/Claude/CVE

# 2. 使用虚拟环境Python运行
/E/AI/cursor/starone/.venv/Scripts/python.exe cve_integrated_gui.py
```

**启动结果**: ✅ 程序已在后台运行

---

## 📋 手动启动方法

### 方法1: Windows CMD

```cmd
:: 切换到项目目录
cd E:\AI\Claude\CVE

:: 激活虚拟环境
E:\AI\cursor\starone\.venv\Scripts\activate.bat

:: 运行程序
python cve_integrated_gui.py
```

### 方法2: PowerShell

```powershell
# 切换到项目目录
cd E:\AI\Claude\CVE

# 激活虚拟环境
E:\AI\cursor\starone\.venv\Scripts\Activate.ps1

# 运行程序
python cve_integrated_gui.py
```

### 方法3: Git Bash

```bash
# 切换到项目目录
cd /E/AI/Claude/CVE

# 激活虚拟环境
source /E/AI/cursor/starone/.venv/Scripts/activate

# 运行程序
python cve_integrated_gui.py
```

---

## 🖥️ GUI界面说明

### 启动后界面

程序启动后会显示一个图形界面窗口，包含以下标签页：

#### 1. 📊 NVD CVE数据
- **时间范围选择**: 最近一周、一个月、三个月等
- **采集按钮**: 点击开始采集CVE数据
- **数据显示**: 树状视图显示CVE列表
- **搜索过滤**: 可按CVE ID、严重程度筛选

#### 2. 🔒 Dell安全公告
- **时间范围选择**: 最近一年、两年、三年
- **采集按钮**: 点击开始采集Dell数据
- **数据显示**: 显示Dell安全公告列表
- **详情查看**: 双击查看详细信息

#### 3. 🤖 LLM智能分析（如果启用）
- **CVE分析**: 使用AI分析CVE漏洞
- **风险评估**: 智能风险评级
- **建议措施**: 修复建议

#### 4. 🔗 关联数据
- **CVE-Dell关联**: 显示CVE与Dell公告的关联
- **交叉引用**: 快速查找相关信息

#### 5. 📝 操作日志
- **实时日志**: 显示程序运行日志
- **错误信息**: 显示错误和警告
- **状态更新**: 采集进度显示

---

## ⚙️ 首次使用配置

### 1. 检查Redis连接（可选）

**使用 WSL Redis**:
```bash
wsl sudo service redis-server start
wsl redis-cli PING
```

**如果没有Redis**:
- 程序会自动使用SQLite模式
- 功能完全正常，只是速度稍慢

### 2. 配置NVD API Key（推荐）

编辑 `.env` 文件:
```bash
# 添加你的API Key
NVD_API_KEY=your_api_key_here
```

**获取API Key**:
- 访问: https://nvd.nist.gov/developers/request-an-api-key
- 免费申请，提升采集速度10倍

### 3. 测试采集

1. 打开GUI后，选择 **"📊 NVD CVE 数据"** 标签
2. 时间范围选择 **"最近一周"**
3. 点击 **"▶ 采集 NVD 数据"** 按钮
4. 观察日志输出和数据显示

---

## 🔍 常见问题

### Q1: 程序启动后没有窗口显示？

**检查**:
1. 查看任务栏，可能在后台
2. 检查日志输出是否有错误
3. 确认Python版本是否正确（需要3.8+）

**解决**:
```bash
# 查看详细错误
cd /E/AI/Claude/CVE
/E/AI/cursor/starone/.venv/Scripts/python.exe cve_integrated_gui.py 2>&1 | tee gui_output.log
```

### Q2: Redis连接失败？

**症状**: GUI顶部显示 "⚠ Redis未连接"

**影响**: 无，程序会自动使用SQLite

**解决**（如果需要Redis）:
```bash
# WSL 启动 Redis
wsl sudo service redis-server start
```

### Q3: 采集速度很慢？

**原因**: 未配置NVD API Key

**速度对比**:
- 无API Key: ~6秒/请求
- 有API Key: ~0.6秒/请求（10倍提升）

**解决**: 编辑 `.env` 添加API Key

### Q4: Tkinter错误？

**症状**: `ModuleNotFoundError: No module named 'tkinter'`

**解决**:
- **Windows**: 重新安装Python（确保勾选tcl/tk选项）
- **Linux**: `sudo apt-get install python3-tk`
- **macOS**: 通常默认安装

---

## 📊 程序功能

### 数据采集
- ✅ NVD CVE数据库采集
- ✅ Dell安全公告采集
- ✅ 增量采集（避免重复）
- ✅ 断点续传（出错自动重试）

### 数据存储
- ✅ Redis高性能缓存（主存储）
- ✅ SQLite自动备份（备份存储）
- ✅ 数据持久化
- ✅ 导出功能（JSON/CSV）

### 数据分析
- ✅ CVE严重程度统计
- ✅ CVE-Dell关联分析
- ✅ 时间趋势分析
- ✅ LLM智能分析（可选）

### 用户界面
- ✅ 图形化操作
- ✅ 实时数据显示
- ✅ 搜索和过滤
- ✅ 详情查看
- ✅ 批量导出

---

## 🎯 快速操作流程

### 首次使用完整流程

1. **启动程序**
   ```bash
   cd /E/AI/Claude/CVE
   /E/AI/cursor/starone/.venv/Scripts/python.exe cve_integrated_gui.py
   ```

2. **检查连接状态**
   - 查看窗口顶部状态栏
   - ✅ Redis已连接 或 ⚠ 使用SQLite模式

3. **采集CVE数据**
   - 切换到 "📊 NVD CVE数据" 标签
   - 选择时间范围（建议从"最近一周"开始）
   - 点击 "▶ 采集 NVD 数据"
   - 等待采集完成（查看日志）

4. **采集Dell数据**
   - 切换到 "🔒 Dell安全公告" 标签
   - 选择时间范围
   - 点击 "▶ 采集 Dell 数据"
   - 等待采集完成

5. **查看关联数据**
   - 切换到 "🔗 关联数据" 标签
   - 查看CVE与Dell公告的关联
   - 点击条目查看详情

6. **导出数据**
   - 点击各标签页的 "💾 导出" 按钮
   - 选择保存位置
   - 数据保存为JSON或CSV格式

---

## 🔧 高级配置

### GPU加速（可选）

如果需要使用LLM智能分析功能，在 `.env` 中启用：

```bash
ENABLE_GPU=true
GPU_DEVICE=0
```

### 数据库管理

**Redis CLI（WSL）**:
```bash
wsl redis-cli
> KEYS *
> INFO memory
```

**SQLite数据库位置**:
```
E:\AI\Claude\CVE\cve_data\cve_database.db
```

---

## 📞 获取帮助

### 文档
- **快速开始**: `QUICKSTART.md`
- **配置指南**: `CONFIG.md`
- **优化指南**: `QUICK_OPTIMIZATION_GUIDE.md`
- **故障排查**: `RUN_CVE_GUIDE.md`

### 日志
程序运行日志会显示在GUI的 "📝 操作日志" 标签页

### 问题反馈
GitHub Issues: https://github.com/philipzhang18/CVE-Security-Solution/issues

---

## ✨ 功能亮点

### 性能优化
- ⚡ 数据实时显示（增量更新）
- ⚡ Redis缓存加速（批量操作）
- ⚡ GPU加速分析（可选）
- ⚡ 多线程采集

### 用户体验
- 🎨 直观的图形界面
- 📊 实时进度显示
- 🔍 强大的搜索过滤
- 💾 一键导出数据

### 稳定可靠
- 🛡️ 自动错误恢复
- 💾 双重数据备份
- 🔄 断点续传
- 📝 详细日志记录

---

**创建时间**: 2025-11-04
**程序版本**: v3.7
**Python要求**: 3.8+
**状态**: ✅ 已启动并运行
