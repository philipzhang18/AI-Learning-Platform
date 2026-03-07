# Dell Security Advisory (DSA) 爬虫使用说明

## 功能概述

`dell_security_scraper.py` 用于从 Dell 官方网站采集安全公告信息（DSA - Dell Security Advisory），集成在 `cve_integrated_gui.py` 的 **Dell 安全公告** 标签页中。

### 核心特性

- 多策略采集：Exa API（优先） → HTTP + BeautifulSoup（回退） → Selenium（兜底）
- 增量采集：自动跳过数据库中已存在的 DSA 公告，只抓取新内容
- Impact 提取：从页面 Impact 区域解析 Critical / High / Medium / Low 等级
- 不生成示例数据，所有数据均来自 Dell 官网真实页面

### 采集的字段

| 字段 | 说明 | 示例 |
|------|------|------|
| dell_security_advisory | DSA 公告编号 | DSA-2026-001 |
| title | 公告标题 | Dell PowerEdge Server BIOS Security Update |
| impact | 影响等级 | Critical / High / Medium / Low |
| cve_ids | 关联的 CVE 编号列表 | CVE-2026-1234, CVE-2026-5678 |
| published_date | 发布日期 | 2026-03-01T00:00:00 |
| link | 公告详情页 URL | https://www.dell.com/support/kbdoc/en-us/... |
| summary | 摘要（前 500 字符） | Critical severity security update... |
| affected_products | 受影响产品列表 | Dell PowerEdge, Dell Latitude... |
| solution | 解决方案 | Apply the latest security update... |

## 安装依赖

### 必需依赖

```bash
pip install aiohttp beautifulsoup4
```

### 可选依赖（按策略）

```bash
# Exa API（推荐，需要设置 EXA_API_KEY 环境变量）
# 无额外安装，使用 aiohttp 调用 API

# Selenium（处理 JS 动态渲染页面）
pip install selenium webdriver-manager
# 需要安装 Chrome 浏览器
```

### 环境变量

```bash
# Exa API 密钥（可选但推荐）
export EXA_API_KEY="your_exa_api_key"

# 或在 Windows 中
set EXA_API_KEY=your_exa_api_key
```

## 采集流程

### 整体架构

```
用户点击 [采集 Dell 安全公告]
    |
    v
collect_dell_advisories_async()          <-- GUI 入口
    |
    v
get_existing_dell_ids()                  <-- 获取数据库已有 DSA ID
    |
    v
scraper.fetch_security_advisories()      <-- 爬虫主入口
    |
    +-- Step 1: 发现公告链接 -----------+
    |   |                                |
    |   +-- Exa search API               |
    |   +-- HTTP 爬取列表页              |
    |   +-- Selenium（JS 渲染）          |
    |                                    |
    +-- Step 2: 过滤已存在的 DSA --------+
    |   (比对 existing_dsa_ids)          |
    |                                    |
    +-- Step 3: 逐个抓取新公告详情 ------+
        |                                |
        +-- Exa contents API             |
        +-- HTTP + BeautifulSoup         |
        +-- Selenium                     |
        |                                |
        v                                |
    _parse_advisory_content()            |
        |                                |
        +-- 提取 DSA ID, 标题, CVE IDs   |
        +-- 提取 Impact 等级             |
        +-- 提取发布日期, 产品, 方案      |
        |                                |
        v                                |
    store_dell_advisory()  <-- 入库 -----+
```

### Step 1: 发现公告链接

从 `https://www.dell.com/support/security/en-us/` 页面结构下发现 DSA 链接。

**策略 1 — Exa 搜索 API（优先）**

使用 Exa 的 `/search` 端点按域名和时间范围搜索 Dell 安全公告页面：

```
POST https://api.exa.ai/search
{
  "query": "Dell DSA security advisory vulnerability update",
  "includeDomains": ["dell.com"],
  "startPublishedDate": "2026-01-01T00:00:00.000Z",
  "numResults": 50
}
```

返回的 URL 中提取 DSA ID（如 `DSA-2026-001`）。

**策略 2 — HTTP 爬取列表页**

直接 GET 请求列表页 HTML，BeautifulSoup 解析所有 `<a>` 标签，从 href 和文本中匹配 `DSA-\d{4}-\d+` 模式。

**策略 3 — Selenium**

无头 Chrome 加载页面，等待 JS 渲染完毕后提取所有链接。适用于列表页为 JavaScript 动态渲染的情况。

### Step 2: 过滤已存在的 DSA

将发现的 DSA ID 与数据库中 `dell_advisories` 表的 `dsa_id` 比对（不区分大小写），已存在的直接跳过，不浪费 API 调用和网络请求。

### Step 3: 抓取并解析详情页

对每个新 DSA，依次尝试三种方式获取页面正文文本：

1. **Exa contents API** — `POST /contents`，传入 URL 获取纯文本，干净且能绕过 JS 渲染
2. **HTTP + BeautifulSoup** — 直接请求 HTML，移除 script/style/nav 等噪声标签后提取文本
3. **Selenium** — 无头 Chrome 渲染后获取 `<body>` 文本

### Impact 提取逻辑

从页面文本中匹配 Dell 安全公告的多种 Impact 表述格式：

```
Impact
Critical              <-- Dell 页面 Impact 区域标题 + 换行 + 等级

Critical severity     <-- 摘要文本中的描述

Severity: High        <-- 标签式格式

CVSS ... Medium       <-- CVSS 描述中的等级
```

对应正则：

```python
r'Impact\s*[\n:]\s*(Critical|High|Medium|Low)'
r'\b(Critical|High|Medium|Low)\b\s+severity'
r'[Ss]everity\s*[:\s]\s*(Critical|High|Medium|Low)'
r'CVSS.*?\b(Critical|High|Medium|Low)\b'
```

## 两种使用方式

### 方式 1: GUI 中 "采集 Dell 安全公告" 按钮

在 `cve_integrated_gui.py` 的 Dell 安全公告标签页中，选择时间范围后点击 **采集 Dell 安全公告** 按钮，自动执行完整的发现→过滤→抓取→入库流程。

### 方式 2: GUI 中 "抓取并入库" 按钮

手动输入单条 Dell 安全公告 URL，点击 **抓取并入库** 按钮，直接抓取并解析该页面。使用相同的 Exa → HTTP 回退策略和 Impact 提取逻辑。

### 方式 3: 独立运行脚本

```bash
# 激活虚拟环境
source /E/AI/cursor/starone/.venv/Scripts/activate

# 运行测试
python dell_security_scraper.py
```

## 数据存储

采集到的公告以 JSON 序列化存入 SQLite 数据库 `cve_data/cve_database.db` 的 `dell_advisories` 表：

| 列 | 类型 | 说明 |
|----|------|------|
| dsa_id | TEXT PRIMARY KEY | DSA 公告编号 |
| title | TEXT | 标题 |
| cve_ids | TEXT | 关联 CVE（逗号分隔） |
| data | TEXT | 完整 JSON 数据 |
| published_date | TEXT | 发布日期 |
| collected_date | TEXT | 采集日期 |
| link | TEXT | 详情页 URL |

启用 Redis 时，Redis 为主存储，SQLite 异步备份。

## 故障排除

### 问题 1: 未发现任何公告链接

**可能原因：**
- 未配置 EXA_API_KEY 且 Dell 列表页为 JS 渲染
- 网络连接问题

**解决方法：**
1. 配置 `EXA_API_KEY` 环境变量（推荐）
2. 安装 Selenium：`pip install selenium`，确保已安装 Chrome 浏览器
3. 使用 "抓取并入库" 按钮手动输入单条 URL

### 问题 2: 页面内容为空

**可能原因：**
- 页面为 JS 动态加载，HTTP 请求无法获取完整内容

**解决方法：**
1. 确认 Exa API Key 已配置（Exa 能获取 JS 渲染后的内容）
2. 安装 Selenium 作为第三回退方案

### 问题 3: Impact 字段为空

**可能原因：**
- 页面中未包含标准的 Impact / Severity 描述

**解决方法：**
- Impact 字段不影响入库，界面显示为 "N/A"
- 可通过 "抓取并入库" 按钮重新抓取该 URL 获取更完整的解析

## 注意事项

- 请求间隔默认 1.5 秒，避免对 Dell 服务器造成压力
- 遵守网站的 robots.txt 和相关法律法规
- 仅用于安全研究和漏洞管理等合法用途
- Exa API 有调用额度限制，大量采集时注意配额

## 许可证

本脚本仅供学习和研究使用。使用前请确保遵守相关法律法规和网站使用条款。
