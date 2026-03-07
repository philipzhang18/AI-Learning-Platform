# 🛡️ CVE Security Solution

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-4.3.0-orange.svg)](CHANGELOG.md)
[![Status](https://img.shields.io/badge/status-active-brightgreen.svg)](#)

A professional **CVE vulnerability monitoring and management system** with **AI-powered analysis** capabilities. Integrates NVD CVE data with Dell security advisories for comprehensive vulnerability assessment and threat analysis.

---

## 📑 Quick Navigation

- [Features](#-features)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [Usage Guide](#-usage-guide)
- [AI Features](#-ai-features)
- [System Architecture](#-system-architecture)
- [Performance](#-performance)
- [FAQ](#-faq)
- [Documentation](#-documentation)
- [License](#-license)

---

## ✨ Features

### 🎯 Core Capabilities

#### CVE Data Collection
- ✅ Real-time NVD CVE database integration
- ✅ Customizable time ranges (1 week to 1 year)
- ✅ 10x faster with NVD API Key
- ✅ SQLite + Redis (WSL) dual-storage support
- ✅ Async processing for large datasets

#### Dell Security Advisory Integration
- ✅ Automated Dell advisory scraping
- ✅ Single URL fetch with Exa API (+ HTTP fallback)
- ✅ Intelligent CVE ID extraction
- ✅ Affected product identification
- ✅ CSV batch import

#### CVE-Dell Correlation Analysis
- ✅ Automatic vulnerability-advisory matching
- ✅ Real-time correlation statistics
- ✅ Risk assessment and prioritization

#### 🤖 AI-Powered Analysis
- ✅ Qwen 3.5-Plus / Claude model integration
- ✅ NVD tab: standalone CVE vulnerability analysis (Dell advisory ID = "NA")
- ✅ Correlation tab: CVE + Dell joint analysis (with Dell advisory context)
- ✅ Popup dialog with save-to-solutions button
- ✅ Intelligent remediation suggestions
- ✅ Solution history management with delete
- ✅ Real-time analysis date injection (prevents incorrect AI-generated dates)

#### 🧠 Feynman Learning Module
- ✅ AI-assisted security concept learning
- ✅ Interactive teach-back method
- ✅ Cascading data source selector: IT News / Dell Advisory / CVE / AI Records / Learning Sessions
- ✅ Load specific items: news by date, advisory by ID, CVE by ID
- ✅ Web URL content fetching for learning (Exa API + HTTP fallback)
- ✅ Save & reload conversation history as learning material

### 📊 Data Visualization & Management
- ✅ Modern GUI with 8 tabs (Tkinter)
- ✅ Full-database search (memory + SQLite fallback)
- ✅ Multi-select delete with confirmation
- ✅ JSON/CSV export support
- ✅ Statistics dashboard with matplotlib charts (15.6" optimized)
- ✅ Separate CVE severity pie chart + Dell impact pie chart + bar chart

### ⚡ Performance Features
- ✅ Optional WSL Redis caching layer
- ✅ Local SQLite database (lightweight, no Docker)
- ✅ Asynchronous data loading
- ✅ Optimized batch queries
- ✅ Background threading for UI responsiveness

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Windows 10/11 (with WSL for optional Redis)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/philipzhang18/CVE-Security-Solution.git
cd CVE-Security-Solution

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
# Edit .env and set your API keys
```

### Run the Application

**Recommended (with WSL Redis):**
```batch
start_cve_with_wsl_redis.bat
```

**Or directly:**
```bash
python cve_integrated_gui.py
```

> The application works fully with SQLite alone. Redis is optional for performance.

---

## ⚙️ Configuration

### Environment Variables (`.env`)

```ini
# NVD API (recommended, 10x faster collection)
# Apply: https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY=your_api_key_here

# Exa API (for Dell URL fetch & Smart Learning web content)
EXA_API_KEY=your_exa_api_key_here

# Qwen AI (for vulnerability analysis)
# Apply: https://dashscope.console.aliyun.com/
DASHSCOPE_API_KEY=sk-your-api-key-here
QWEN_MODEL=qwen3.5-plus

# Redis (optional, WSL)
USE_REDIS=true
REDIS_HOST=localhost
REDIS_PORT=6379

# Architecture
ARCHITECTURE=lightweight
USE_DOCKER=false
SQLITE_DB_PATH=cve_data/cve_database.db
```

---

## 📖 Usage Guide

### GUI Tabs

| Tab | Purpose |
|-----|---------|
| 📰 IT News | RSS tech news collection, AI daily brief generation |
| 📊 NVD CVE Data | Import, browse, search, delete CVEs; AI vulnerability analysis |
| 🏢 Dell Advisory | Import, URL-fetch, browse, search, delete Dell advisories |
| 🔗 CVE-Dell Correlation | Auto-matched CVE ↔ Dell results; AI joint analysis |
| 💡 Solutions | AI-generated analysis history with save/delete management |
| 📈 Statistics | Separate CVE & Dell severity pie charts, bar chart, top-10 lists |
| 🧠 Smart Learning | Feynman learning with DB / file / web URL sources; save & reload sessions |
| 📝 Logs | Real-time operation logs |

### Key Workflows

1. **Collect Data** → NVD / Dell tabs → Click collect button
2. **Search** → Type in search box → Searches memory then full database
3. **Delete Records** → Ctrl/Shift multi-select → Click delete button
4. **Single URL Fetch** → Dell tab → Paste advisory URL → Click fetch
5. **AI Analysis (NVD)** → NVD tab → Select CVE → Click AI Solution → Popup with save
6. **AI Analysis (Correlation)** → Correlation tab → Select pair → Click AI Solution → CVE+Dell joint analysis
7. **Smart Learning** → Select data source (DB / file / web URL) → Pick specific item → Start Feynman session
8. **Save Learning** → After Feynman session → Click "Save Conversation" → Reload later from "Learning Sessions"

---

## 🤖 AI Features

### Vulnerability Analysis
Automatically analyze CVE vulnerabilities with Qwen 3.5-Plus AI:

- **Vulnerability Details**: Attack vectors, impact scope, CVSS vector analysis
- **Dell Products Impact**: Affected systems and versions (correlation tab)
- **Remediation Plans**: Patch availability, upgrade paths
- **Temporary Mitigations**: Quick workarounds
- **Detection Methods**: Monitoring recommendations

**Two analysis modes:**
- **NVD Tab**: Pure CVE analysis — analyzes CVE ID, description, CWE, CVSS, affected products, and references. Dell advisory ID is saved as "NA".
- **Correlation Tab**: Joint CVE + Dell analysis — includes Dell advisory title, affected products, and solution context when available.

Both modes inject the current date/time into the AI system prompt to ensure accurate analysis dates. Results display in a popup dialog. Click "Save to Solutions" to persist results in the Solutions tab.

### Feynman Learning Module
Learn security concepts through the Feynman teach-back method with AI guidance:

- **Three content sources**: Database records, local files, or web URLs (Exa API + HTTP fallback)
- **Five database categories**: IT News / Dell Advisory / CVE / AI Records / Learning Sessions
- **Save & reload**: Persist conversations to database for future review and continued learning
- **Three difficulty levels**: Beginner (analogies) / Professional (technical depth) / Expert (Socratic challenge)

See [AI_SOLUTION_USAGE_GUIDE.md](AI_SOLUTION_USAGE_GUIDE.md) for complete guide.

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CVE Security Solution v4.3                 │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐        │
│  │   NVD API   │  │ Dell Website │  │   Exa API    │        │
│  └──────┬──────┘  └──────┬───────┘  └──────┬───────┘        │
│         │                │                  │                 │
│         └────────────────┼──────────────────┘                 │
│                          │                                    │
│                  ┌───────▼─────────┐     ┌──────────────┐    │
│                  │  Application    │────▶│  Qwen AI /   │    │
│                  │  (Main Program) │◀────│  Claude API  │    │
│                  └───────┬─────────┘     └──────────────┘    │
│                          │                                    │
│            ┌─────────────┼─────────────┐                     │
│            │             │             │                     │
│       ┌────▼────┐  ┌─────▼────┐  ┌───▼──────┐              │
│       │ SQLite  │  │   Redis  │  │ Tkinter  │              │
│       │Database │  │  (WSL)   │  │   GUI    │              │
│       │ (Main)  │  │ (Cache)  │  │ (8 Tabs) │              │
│       └─────────┘  └──────────┘  └──────────┘              │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Technology Stack

| Layer | Technology |
|-------|-----------|
| **UI** | Tkinter (8-tab interface) |
| **Data Collection** | aiohttp, asyncio, Exa API |
| **Storage** | SQLite3 (primary), Redis/WSL (optional cache) |
| **AI** | Qwen 3.5-Plus / Claude API (OpenAI-compatible) |
| **Visualization** | matplotlib (pie charts, bar charts) |
| **Web Scraping** | Feedparser, requests, BeautifulSoup |

---

## ⚡ Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Load 100 CVEs | < 1s | Cached |
| Full-database search | < 2s | SQLite indexed |
| AI Analysis | 30-60s | Per vulnerability |
| GUI Startup | < 2s | With Redis |

---

## ❓ FAQ

**Q: Do I need Docker?**
A: **No.** The project uses SQLite by default. Docker has been removed entirely.

**Q: Do I need Redis?**
A: Optional. SQLite works standalone. WSL Redis improves cache performance.

**Q: Do I need an API key?**
A: Optional but recommended:
- **NVD API Key**: 10x faster collection
- **Qwen API Key**: Required for AI analysis (model: qwen3.5-plus)
- **Exa API Key**: For Dell URL fetch & Smart Learning web content

**Q: Do I need matplotlib?**
A: Optional. Required for pie/bar charts on the Statistics tab. Install with `pip install matplotlib`. The app works without it (charts show a fallback message).

**Q: How to start Redis?**
A:
```bash
wsl sudo service redis-server start
```

---

## 📚 Documentation

- 📖 [QUICKSTART.md](QUICKSTART.md) - 3-minute setup guide
- 🚀 [START_CVE_NOW.md](START_CVE_NOW.md) - Launch instructions
- 🤖 [AI_SOLUTION_USAGE_GUIDE.md](AI_SOLUTION_USAGE_GUIDE.md) - AI analysis tutorial
- ⚙️ [QUICK_QWEN_CONFIG_GUIDE.md](QUICK_QWEN_CONFIG_GUIDE.md) - Qwen API setup
- 🔴 [Redis Guide](docs/REDIS_GUIDE.md) - WSL Redis setup
- 📋 [docs/](docs/) - Detailed documentation

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **NVD (National Vulnerability Database)**: CVE data source
- **Dell Security**: Advisory data source
- **Alibaba Qwen**: AI analysis capabilities
- **Exa AI**: Web content extraction

---

## 🎯 Project Status

- ✅ v4.3.0 Released (2026-03-07)
- ✅ Smart Learning: web URL content fetching (Exa API + HTTP fallback)
- ✅ Smart Learning: save & reload conversation history (learn_sessions table)
- ✅ Smart Learning: 5 cascading data sources (IT News / Dell / CVE / AI / Learning Sessions)
- ✅ AI analysis date injection — reports now show correct analysis date
- ✅ Dell affected_products dict/str compatibility fix
- ✅ Expanded data limits (dropdown items, AI context, file loading)
- ✅ Separate CVE & Dell severity pie charts (matplotlib, 15.6" optimized)
- ✅ NVD tab AI analysis (pure CVE, Dell ID = "NA")
- ✅ Correlation tab AI analysis (CVE + Dell joint)
- ✅ Qwen model: qwen3.5-plus
- ✅ Docker removed — Lightweight SQLite architecture
- ✅ Production Ready

---

**Made with ❤️ for cybersecurity professionals**

Last Updated: 2026-03-07 | Version: 4.3.0
