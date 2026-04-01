# 智能知识管理平台

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-5.1.0-orange.svg)](CHANGELOG.md)

以**知识管理**为核心的智能平台，通过多渠道收集学习资料（播客、文件、网页、数据库数据），采用 AI 方法进行深度学习与分析。

---

## 功能概览

### 内容收集
- **NVD CVE 数据采集** — 从 NVD 获取最新漏洞数据，支持自定义时间范围
- **Dell 安全公告** — 多策略抓取（Exa API / HTTP / Selenium），支持单条 URL 抓取
- **Dell 技术库** — 单条 kbdoc URL 抓取技术文档，提取文章编号/内容/解决方案
- **IT 新闻简报** — 自动采集科技新闻，AI 生成每日简报和播客脚本
- **网页/文件/RSS** — 支持从任意 URL、本地文件加载学习内容

### AI 深度学习
- **费曼学习法** — AI 辅助的交互式学习对话，支持从数据库/文件/网页加载内容
- **AI 分析** — 漏洞分析、新闻解读、知识点深度分析（Claude / Qwen 多模型）
- **CVE-Dell 关联** — 自动匹配漏洞与厂商公告的关联关系

### 辅助功能
- **统计分析** — 可视化图表（严重性分布、趋势分析）
- **TTS 播报** — 新闻简报语音播放（Windows SAPI）
- **数据导出** — CSV / TXT / HTML 导出，支持选中条目导出

---

## 快速开始

### 环境要求
- Python 3.8+
- Windows 10/11（推荐）
- 可选：WSL2 + Redis（高性能缓存）

### 安装依赖
```bash
pip install -r requirements.txt
```

### 启动方式

**方式一：SQLite 轻量模式（推荐）**
```
双击运行：启动CVE系统-SQLite.bat
```

**方式二：混合模式（SQLite + WSL Redis）**
```
双击运行：启动CVE系统-混合模式.bat
```

**方式三：命令行**
```bash
python cve_integrated_gui.py
```

### API Key 配置

复制 `.env.example` 为 `.env`，填入实际密钥：
```
NVD_API_KEY=your_nvd_api_key
DASHSCOPE_API_KEY=your_qwen_api_key
CLAUDE_API_KEY=your_claude_api_key
EXA_API_KEY=your_exa_api_key
```

---

## 技术架构

```
智能知识管理平台
├── 数据层
│   ├── SQLite（主存储，WAL 模式）
│   └── Redis（可选缓存，WSL 部署）
├── 采集层
│   ├── NVD REST API（CVE 数据）
│   ├── Exa API + HTTP + Selenium（Dell 公告 / 网页）
│   └── RSS / 本地文件
├── AI 层
│   ├── Claude API（Anthropic）
│   ├── Qwen API（阿里云百炼）
│   └── Ollama（本地模型，可选）
└── 界面层
    └── tkinter GUI（9 标签页）
```

---

## 项目结构

```
├── cve_integrated_gui.py      # 主程序（GUI 入口）
├── collect_cves.py            # NVD CVE 数据采集器
├── dell_security_scraper.py   # Dell 安全公告爬虫
├── redis_manager.py           # Redis 缓存管理
├── llm_config.py              # LLM API 配置
├── qwen_assistant.py          # Qwen AI 助手（CLI）
├── ollama_llm_service.py      # Ollama 本地模型 + 向量搜索
├── requirements.txt           # Python 依赖
├── .env.example               # 环境变量模板
├── CLAUDE.md                  # Claude 开发配置
├── CONFIG.md                  # 系统配置指南
└── docs/                      # 技术文档
```

---

## 版本历史

| 版本 | 日期 | 主要变更 |
|------|------|----------|
| v5.1.0 | 2026-03-30 | 新增 Dell 技术库标签页，解决方案 HTML 导出 |
| v5.0.0 | 2026-03-14 | 重命名为"智能知识管理平台"，项目清理，架构优化 |
| v4.4.0 | 2025-11-05 | SQLite 主存储 + 双写一致性架构 |
| v4.3.0 | 2025-11-04 | 智能学习 Web URL 来源，保存对话 |
| v4.2.0 | 2025-11-03 | 删除/搜索功能，路径迁移至 E 盘 |

详见 [CHANGELOG.md](CHANGELOG.md)

---

## License

MIT License
