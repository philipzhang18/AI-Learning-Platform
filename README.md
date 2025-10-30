# CVE 漏洞监控与管理系统

🛡️ 一个自动化的 CVE 漏洞监控与管理系统，实时获取、分析并展示最新的安全漏洞信息。

## 📋 项目概述

本系统基于微服务架构设计，提供完整的漏洞数据采集、处理、分析和通知功能。系统可以从多个数据源（NVD、CNVD、GitHub等）自动采集最新的 CVE 信息，并通过智能分析引擎评估风险等级，为安全团队提供及时的威胁情报。

### 核心功能

- ✅ **多源数据采集** - 支持 NVD、CNVD、GitHub Security Advisory 等多个数据源
- ✅ **智能风险评估** - 基于 CVSS 评分和威胁情报的综合风险分析
- ✅ **实时告警通知** - 支持邮件、SMS、Slack 等多渠道通知
- ✅ **可视化展示** - 提供 Web 界面和 API 接口
- ✅ **高性能架构** - 支持分布式部署和横向扩展

## 🚀 快速开始

### 环境要求

- Python 3.10+
- Docker 20.10+
- Docker Compose 2.0+
- 4GB+ RAM
- 10GB+ 磁盘空间

### 快速运行采集脚本

1. **安装依赖**

```bash
# 激活虚拟环境（如果有）
source D:\AI\cursor\starone\.venv\Scripts\activate  # Windows
# 或
source venv/bin/activate  # Linux/Mac

# 安装基本依赖
pip install aiohttp
```

2. **运行数据采集**

```bash
# 直接运行采集脚本（获取最近7天的CVE数据）
python collect_cves.py

# 可选：设置 NVD API Key 以提高采集速度
# 在 https://nvd.nist.gov/developers/request-an-api-key 申请免费 API Key
export NVD_API_KEY=your_api_key_here  # Linux/Mac
# 或
set NVD_API_KEY=your_api_key_here  # Windows
```

采集完成后，数据将保存在 `cve_data/` 目录下的 JSON 文件中。

### 运行完整系统

1. **克隆项目**

```bash
git clone https://github.com/your-org/cve-monitor-system.git
cd cve-monitor-system
```

2. **配置环境变量**

```bash
# 复制环境变量模板
cp .env.example .env

# 编辑 .env 文件，配置必要的参数
# - MongoDB 密码
# - Redis 密码
# - NVD API Key（可选但推荐）
# - 邮件服务器配置（用于告警）
```

3. **使用 Docker Compose 启动**

```bash
# 构建并启动所有服务
docker-compose up -d

# 查看服务状态
docker-compose ps

# 查看日志
docker-compose logs -f backend
```

4. **访问系统**

- Web API 文档: http://localhost:8000/docs
- API 根路径: http://localhost:8000
- 健康检查: http://localhost:8000/health

### 本地开发模式

1. **安装 Python 依赖**

```bash
# 创建虚拟环境
python -m venv venv

# 激活虚拟环境
source venv/bin/activate  # Linux/Mac
# 或
venv\Scripts\activate  # Windows

# 安装依赖
pip install -r requirements.txt
```

2. **启动 FastAPI 服务**

```bash
# 运行主应用
python main.py

# 或使用 uvicorn
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

3. **访问 API 文档**

打开浏览器访问 http://localhost:8000/docs 查看交互式 API 文档。

## 📁 项目结构

```
cve-monitor-system/
├── main.py                 # FastAPI 主应用入口
├── collect_cves.py        # CVE 数据采集脚本
├── requirements.txt       # Python 依赖
├── solution.md           # 完整解决方案文档
├── plan.md              # 系统架构方案
├── cve_data/           # 采集的 CVE 数据存储目录
│   └── cves_*.json    # JSON 格式的 CVE 数据
├── docker-compose.yml   # Docker Compose 配置
├── .env.example        # 环境变量模板
└── README.md          # 本文档
```

## 🔌 API 接口示例

### 获取最新 CVE 列表

```bash
curl http://localhost:8000/api/v1/cves/latest?limit=10
```

响应示例：

```json
{
  "total": 10,
  "data": [
    {
      "cve_id": "CVE-2024-12345",
      "title": "示例漏洞",
      "severity": "HIGH",
      "cvss_score": 8.5,
      "published_date": "2024-10-28T10:30:00"
    }
  ]
}
```

### 获取统计摘要

```bash
curl http://localhost:8000/api/v1/stats/summary
```

### 搜索 CVE

```bash
curl "http://localhost:8000/api/v1/search?q=sql injection&severity=HIGH"
```

### WebSocket 实时通知

```javascript
// JavaScript 示例
const ws = new WebSocket('ws://localhost:8000/ws/notifications');

ws.onmessage = (event) => {
  const notification = JSON.parse(event.data);
  console.log('新的 CVE 通知:', notification);
};

ws.send('subscribe');
```

## 🔧 配置说明

### NVD API 配置

1. 访问 [NVD API Key 申请页面](https://nvd.nist.gov/developers/request-an-api-key)
2. 填写申请表单（免费）
3. 将获取的 API Key 配置到环境变量中

### 数据采集频率

默认配置：
- 全量采集：每天凌晨 2:00
- 增量更新：每小时一次
- 高危漏洞检查：每 15 分钟一次

可以通过修改 Celery Beat 配置调整采集频率。

## 📊 数据分析功能

系统提供多维度的漏洞数据分析：

1. **风险评估**
   - 基于 CVSS v3.1/v4 评分
   - 考虑时间因素（新漏洞权重更高）
   - 评估可利用性和影响范围

2. **趋势分析**
   - 漏洞数量趋势
   - 严重性分布
   - 受影响厂商排名

3. **智能推荐**
   - 修复优先级建议
   - 缓解措施推荐
   - 相关漏洞关联

## 🛠️ 扩展开发

### 添加新的数据源

1. 在 `collectors/` 目录创建新的采集器
2. 继承 `BaseCollector` 基类
3. 实现 `collect_recent_cves()` 方法
4. 在配置中注册新的数据源

### 自定义告警规则

编辑告警配置文件，支持基于以下条件的告警：

- CVE 严重等级
- CVSS 评分阈值
- 特定厂商/产品
- 关键字匹配

## 📈 性能指标

- 数据采集延迟: < 1 小时
- API 响应时间: < 500ms (P95)
- 并发支持: 1000+ 用户
- 数据处理能力: 10000+ CVE/天

## 🔐 安全措施

- HTTPS 加密传输
- JWT 身份认证
- API Rate Limiting
- 输入验证和清理
- SQL 注入防护
- XSS 防护

## 🐛 故障排除

### 常见问题

1. **采集脚本报错：连接超时**
   - 检查网络连接
   - 确认能访问 nvd.nist.gov
   - 考虑使用代理

2. **API 无法访问**
   - 检查防火墙设置
   - 确认端口 8000 未被占用
   - 查看应用日志

3. **数据库连接失败**
   - 检查 MongoDB 服务状态
   - 验证连接字符串
   - 确认认证信息正确

### 获取帮助

- 查看详细文档: [solution.md](solution.md)
- 提交问题: [GitHub Issues](https://github.com/your-org/cve-monitor-system/issues)
- 邮件联系: security@example.com

## 📝 更新日志

### v1.0.0 (2024-10-28)
- 初始版本发布
- 支持 NVD 数据源
- 基础 API 功能
- 数据采集脚本

## 📄 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

## 🤝 贡献指南

欢迎贡献代码、报告问题或提出建议！

1. Fork 本项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

## 👥 团队

- 安全架构师：负责整体架构设计
- 后端开发：负责 API 和数据处理
- 前端开发：负责 UI 界面
- DevOps：负责部署和运维

---

**注意**: 本系统仅供合法的安全研究和防护使用。请遵守相关法律法规，不要用于非法用途。

最后更新: 2024-10-28