# CVE 漏洞监控系统 - 使用说明

## 系统概述

CVE 漏洞监控系统是一个集成了 NVD（National Vulnerability Database）CVE 数据和 Dell 安全公告的桌面应用程序。该系统支持数据的在线采集、本地存储和离线查看。

## 主要功能

### 1. NVD CVE 数据采集
- 支持采集最近 **7天、30天、90天、180天、365天** 的 CVE 数据
- 支持使用 **NVD API Key** 提高采集速度（推荐）
- 自动保存数据到本地 JSON 文件
- 支持离线加载本地数据

### 2. Dell 安全公告采集
- 从 Dell 官方 RSS 源采集安全公告
- 提取 CVE ID、受影响产品、解决方案等信息
- 自动保存数据到本地 JSON 文件
- 支持离线加载本地数据

### 3. CVE-Dell 关联匹配
- 自动匹配 NVD CVE 数据和 Dell 安全公告
- 显示关联的 CVE 的 Dell 解决方案
- 展示受影响的 Dell 产品型号和版本
- 提供详细的操作方法和修复建议

### 4. 数据可视化
- 树形表格展示 CVE 数据
- 按严重等级分类（CRITICAL、HIGH、MEDIUM、LOW）
- 颜色标识不同严重等级
- 支持搜索和过滤

### 5. 统计分析
- CVE 数量统计
- 严重等级分布
- 关联匹配率
- 详细统计报告

## 安装依赖

### 1. 创建虚拟环境（如果未创建）

```bash
python -m venv .venv
```

### 2. 激活虚拟环境

**Windows (Git Bash):**
```bash
source /D/AI/cursor/starone/.venv/Scripts/activate
```

**Windows (PowerShell):**
```powershell
D:\AI\cursor\starone\.venv\Scripts\Activate.ps1
```

**Windows (CMD):**
```cmd
D:\AI\cursor\starone\.venv\Scripts\activate.bat
```

### 3. 安装依赖包

```bash
pip install -r requirements.txt
```

主要依赖：
- `tkinter` - GUI 界面（Python 内置）
- `aiohttp` - 异步 HTTP 客户端
- `feedparser` - RSS 解析
- `python-dateutil` - 日期处理

## 使用方法

### 启动程序

```bash
# 在虚拟环境中运行
source /D/AI/cursor/starone/.venv/Scripts/activate
python cve_integrated_gui.py
```

### 界面说明

程序启动后会显示以下标签页：

#### 1. 📊 NVD CVE 数据

**功能：**
- 采集并展示 NVD CVE 数据
- 支持按天数范围采集（7-365天）
- 支持配置 NVD API Key

**操作步骤：**
1. 选择采集天数范围（建议从小范围开始测试）
2. （可选）输入 NVD API Key（提高采集速度）
3. 点击 "▶ 采集 NVD 数据" 按钮
4. 等待采集完成（较大范围可能需要较长时间）
5. 双击任一条目查看详细信息

**获取 NVD API Key：**
- 访问：https://nvd.nist.gov/developers/request-an-api-key
- 免费申请，大幅提高请求速度（从 10次/分钟 提升到 100次/分钟）

**搜索功能：**
- 支持按 CVE ID、描述、严重等级搜索
- 实时过滤显示结果

#### 2. 🏢 Dell 安全公告

**功能：**
- 采集 Dell 官方安全公告
- 提取相关 CVE ID、受影响产品、解决方案

**操作步骤：**
1. 点击 "▶ 采集 Dell 安全公告" 按钮
2. 等待采集完成
3. 双击任一条目查看详细信息

**搜索功能：**
- 支持按 CVE ID、标题、产品名称搜索

#### 3. 🔗 CVE-Dell 关联

**功能：**
- 显示 NVD CVE 数据与 Dell 安全公告的匹配结果
- 展示 Dell 的详细解决方案

**操作步骤：**
1. 确保已采集 NVD CVE 数据和 Dell 安全公告
2. 点击 "🔄 刷新关联数据" 按钮
3. 双击任一条目查看完整的关联详情

**关联详情包括：**
- CVE 基本信息（编号、严重等级、评分、描述）
- Dell 公告信息（公告 ID、标题）
- **受影响的 Dell 产品型号**
- **Dell 官方解决方案和操作方法**
- 参考链接（NVD 链接、Dell 公告链接）

#### 4. 📈 统计分析

**功能：**
- 数据统计概览
- 严重等级分布
- 详细统计报告

**显示内容：**
- NVD CVE 总数
- Dell 公告数
- 关联匹配数和匹配率
- 严重等级分布（CRITICAL、HIGH、MEDIUM、LOW）
- 最新 CVE 列表
- 最新 Dell 安全公告

#### 5. 📝 操作日志

**功能：**
- 显示所有操作的日志信息
- 采集进度跟踪
- 错误信息提示

### 离线数据查看

**功能：**
- 程序启动时自动加载最新的本地数据
- 支持手动加载历史数据文件

**手动加载：**
1. 点击相应页面的 "📁 加载本地数据" 按钮
2. 选择数据文件（JSON 格式）
3. 数据将显示在树形表格中

**数据文件位置：**
```
cve_data/
├── nvd_cves_YYYYMMDD_HHMMSS.json      # NVD CVE 数据
├── dell_advisories_YYYYMMDD_HHMMSS.json   # Dell 安全公告数据
└── cves_YYYYMMDD_HHMMSS.json          # 旧版数据（兼容）
```

## 数据文件格式

### NVD CVE 数据格式

```json
[
  {
    "cve_id": "CVE-2024-1234",
    "description": "漏洞描述",
    "published_date": "2024-01-01T00:00:00",
    "last_modified": "2024-01-01T00:00:00",
    "vuln_status": "Analyzed",
    "cvss_score": 9.8,
    "cvss_severity": "CRITICAL",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "references": [
      {
        "url": "https://example.com",
        "source": "source",
        "tags": ["Patch", "Vendor Advisory"]
      }
    ],
    "affected_products": [
      {
        "cpe": "cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*",
        "vendor": "vendor",
        "product": "product",
        "version": "1.0.0",
        "versionEndExcluding": "1.0.1"
      }
    ],
    "weaknesses": ["CWE-79"],
    "source": "NVD"
  }
]
```

### Dell 安全公告数据格式

```json
[
  {
    "title": "公告标题",
    "summary": "摘要",
    "link": "https://www.dell.com/...",
    "published_date": "2024-01-01T00:00:00",
    "cve_ids": ["CVE-2024-1234", "CVE-2024-5678"],
    "description": "详细描述",
    "guid": "唯一标识",
    "dell_security_advisory": "DSA-2024-001",
    "affected_products": [
      {
        "name": "Dell PowerEdge R750",
        "model": "R750",
        "version_range": "BIOS version < 1.2.3"
      }
    ],
    "solution": "更新固件到版本 1.2.3 或更高版本..."
  }
]
```

## 使用技巧

### 1. 提高采集速度

**申请 NVD API Key：**
- 免费申请：https://nvd.nist.gov/developers/request-an-api-key
- 在程序中配置 API Key
- 采集速度提升 10 倍

### 2. 分批采集大量数据

对于大时间范围的数据采集：
1. 先采集 7 天数据测试
2. 然后采集 30 天
3. 最后采集 365 天（需要较长时间）

### 3. 定期更新数据

建议每周或每月运行一次采集：
1. 采集最近 7 天的 NVD CVE 数据
2. 采集 Dell 安全公告
3. 刷新关联数据
4. 查看是否有影响你的 Dell 设备的新漏洞

### 4. 关注高危漏洞

使用搜索功能过滤：
- 搜索 "CRITICAL" 查看严重漏洞
- 搜索 "HIGH" 查看高危漏洞
- 搜索特定产品型号（如 "R750"）

### 5. 导出和备份数据

数据文件保存在 `cve_data/` 目录：
- 可以备份到其他位置
- 可以与团队共享
- 支持版本控制

## 常见问题

### Q1: 采集 NVD 数据时报错 "API 请求失败: HTTP 404"

**原因：** NVD API 端点或参数错误

**解决方案：**
1. 检查网络连接
2. 确认 NVD API 服务是否正常
3. 尝试使用 API Key
4. 检查日期范围是否合理

### Q2: 采集 Dell 安全公告失败

**原因：** Dell RSS 源 URL 可能已更改

**解决方案：**
1. 访问 Dell 安全网站确认 RSS 源地址
2. 更新 `dell_security.py` 中的 `self.rss_url`
3. 常见 URL：
   - https://www.dell.com/support/security/en-us/rss
   - https://www.dell.com/support/kbdoc/rss/security-advisories

### Q3: 关联数据为空

**原因：** NVD CVE 数据和 Dell 公告数据没有匹配的 CVE ID

**解决方案：**
1. 确保两边都有数据
2. 采集更大范围的数据
3. Dell 安全公告可能不包含所有 CVE

### Q4: 采集速度很慢

**原因：** 未使用 API Key，受到速率限制

**解决方案：**
1. 申请 NVD API Key
2. 在程序中配置 API Key
3. 采集较小范围的数据（如 7-30 天）

### Q5: 程序启动报错缺少模块

**原因：** 未安装依赖包或未激活虚拟环境

**解决方案：**
```bash
# 激活虚拟环境
source /D/AI/cursor/starone/.venv/Scripts/activate

# 安装依赖
pip install -r requirements.txt
```

## 系统要求

- **操作系统：** Windows 10/11, Linux, macOS
- **Python 版本：** 3.8 或更高
- **内存：** 至少 4GB RAM
- **磁盘空间：** 至少 1GB 可用空间（用于存储数据）
- **网络：** 互联网连接（用于数据采集）

## 文件说明

```
CVE/
├── cve_integrated_gui.py          # 主程序（整合版 GUI）
├── collect_cves.py                # NVD CVE 数据采集模块
├── dell_security.py               # Dell 安全公告采集模块
├── requirements.txt               # Python 依赖包列表
├── CLAUDE.md                      # 开发环境配置
├── README_使用说明.md             # 本文档
├── cve_data/                      # 数据存储目录
│   ├── nvd_cves_*.json           # NVD CVE 数据文件
│   └── dell_advisories_*.json    # Dell 安全公告数据文件
└── .venv/                         # Python 虚拟环境（可选）
```

## 技术支持

如遇到问题：

1. **查看日志：** 在程序的 "📝 操作日志" 标签页中查看详细错误信息
2. **检查网络：** 确保能够访问 NVD 和 Dell 网站
3. **更新依赖：** 运行 `pip install --upgrade -r requirements.txt`
4. **重新采集：** 删除旧数据文件，重新采集

## 更新日志

### v1.0.0 (2025-10-30)

**新增功能：**
- ✅ NVD CVE 数据采集（支持最近一年）
- ✅ Dell 安全公告采集
- ✅ CVE-Dell 关联匹配
- ✅ 离线数据查看
- ✅ 数据搜索和过滤
- ✅ 详细统计分析
- ✅ 完整的 GUI 界面
- ✅ 多标签页管理
- ✅ 本地数据存储（JSON 格式）

**特色功能：**
- 🎯 自动匹配 CVE ID
- 🏢 显示 Dell 设备型号和解决方案
- 📊 实时统计和可视化
- 🔍 强大的搜索功能
- 💾 支持离线使用

## 许可证

本项目仅供学习和研究使用。

## 致谢

- NVD (National Vulnerability Database): https://nvd.nist.gov/
- Dell Security Advisories: https://www.dell.com/support/security/

---

**最后更新：** 2025-10-30
**版本：** v1.0.0
