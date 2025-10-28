# CVE 漏洞监控与管理系统 - 实施解决方案

## 1. 系统概述

基于 plan.md 的架构设计，本解决方案提供了一个完整的 CVE 漏洞监控与管理系统实现，包含数据采集、处理、分析、存储和通知等核心功能模块。

## 2. 技术栈选型

### 后端技术
- **编程语言**: Python 3.10+
- **Web框架**: FastAPI (高性能异步框架)
- **任务队列**: Celery + Redis (分布式任务调度)
- **数据库**: MongoDB (文档存储) + PostgreSQL (关系型数据)
- **缓存**: Redis
- **消息队列**: RabbitMQ

### 前端技术
- **框架**: React 18 + TypeScript
- **状态管理**: Redux Toolkit
- **UI组件**: Ant Design
- **图表**: ECharts

### 基础设施
- **容器化**: Docker + Docker Compose
- **编排**: Kubernetes
- **监控**: Prometheus + Grafana
- **日志**: ELK Stack (Elasticsearch, Logstash, Kibana)

## 3. 项目结构

```
cve-monitor-system/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                 # FastAPI 主应用入口
│   │   ├── core/                   # 核心配置
│   │   │   ├── __init__.py
│   │   │   ├── config.py          # 系统配置
│   │   │   ├── security.py        # 安全认证
│   │   │   └── database.py        # 数据库连接
│   │   ├── models/                 # 数据模型
│   │   │   ├── __init__.py
│   │   │   ├── cve.py             # CVE 数据模型
│   │   │   ├── user.py            # 用户模型
│   │   │   └── alert.py           # 告警模型
│   │   ├── collectors/             # 数据采集器
│   │   │   ├── __init__.py
│   │   │   ├── base.py            # 采集器基类
│   │   │   ├── nvd_collector.py   # NVD 采集器
│   │   │   ├── cnvd_collector.py  # CNVD 采集器
│   │   │   └── github_collector.py # GitHub 采集器
│   │   ├── processors/             # 数据处理器
│   │   │   ├── __init__.py
│   │   │   ├── parser.py          # 数据解析器
│   │   │   ├── normalizer.py      # 数据标准化
│   │   │   └── translator.py      # 翻译器
│   │   ├── analyzers/              # 分析引擎
│   │   │   ├── __init__.py
│   │   │   ├── cvss_calculator.py # CVSS 评分计算
│   │   │   ├── cwe_mapper.py      # CWE 映射
│   │   │   └── risk_assessor.py   # 风险评估
│   │   ├── api/                    # API 路由
│   │   │   ├── __init__.py
│   │   │   ├── v1/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── cve.py         # CVE API
│   │   │   │   ├── auth.py        # 认证 API
│   │   │   │   └── alerts.py      # 告警 API
│   │   ├── services/               # 业务服务
│   │   │   ├── __init__.py
│   │   │   ├── cve_service.py
│   │   │   ├── alert_service.py
│   │   │   └── notification_service.py
│   │   └── tasks/                  # Celery 任务
│   │       ├── __init__.py
│   │       ├── collect.py         # 数据采集任务
│   │       └── notify.py          # 通知任务
│   ├── tests/                      # 测试
│   ├── migrations/                 # 数据库迁移
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── services/
│   │   ├── store/
│   │   └── utils/
│   ├── package.json
│   └── Dockerfile
├── docker-compose.yml
├── kubernetes/
│   ├── deployments/
│   ├── services/
│   └── configmaps/
└── README.md
```

## 4. 核心模块实现

### 4.1 数据采集模块

```python
# backend/app/collectors/nvd_collector.py
import aiohttp
import asyncio
from typing import List, Dict, Any
from datetime import datetime, timedelta
import json
from app.core.config import settings
from app.collectors.base import BaseCollector

class NVDCollector(BaseCollector):
    """NVD (National Vulnerability Database) 数据采集器"""

    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = settings.NVD_API_KEY
        self.session = None

    async def init_session(self):
        """初始化异步 HTTP 会话"""
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers={"apiKey": self.api_key}
            )

    async def collect_recent_cves(self, days: int = 1) -> List[Dict[str, Any]]:
        """
        采集最近的 CVE 数据

        Args:
            days: 获取最近几天的数据

        Returns:
            CVE 数据列表
        """
        await self.init_session()

        # 计算时间范围
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 100
        }

        all_cves = []
        start_index = 0

        while True:
            params["startIndex"] = start_index

            try:
                async with self.session.get(self.base_url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        vulnerabilities = data.get("vulnerabilities", [])

                        if not vulnerabilities:
                            break

                        all_cves.extend(vulnerabilities)

                        # 检查是否还有更多数据
                        total_results = data.get("totalResults", 0)
                        if start_index + len(vulnerabilities) >= total_results:
                            break

                        start_index += len(vulnerabilities)

                        # 避免请求过快
                        await asyncio.sleep(0.5)
                    else:
                        self.logger.error(f"NVD API 请求失败: {response.status}")
                        break

            except Exception as e:
                self.logger.error(f"采集 NVD 数据时出错: {str(e)}")
                break

        return self.parse_cves(all_cves)

    def parse_cves(self, raw_cves: List[Dict]) -> List[Dict[str, Any]]:
        """
        解析原始 CVE 数据

        Args:
            raw_cves: 原始 CVE 数据

        Returns:
            标准化的 CVE 数据列表
        """
        parsed_cves = []

        for item in raw_cves:
            cve = item.get("cve", {})

            # 提取基本信息
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            description = next(
                (d.get("value") for d in descriptions if d.get("lang") == "en"),
                ""
            )

            # 提取 CVSS 评分
            metrics = cve.get("metrics", {})
            cvss_v3 = metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else {}
            cvss_data = cvss_v3.get("cvssData", {})

            # 提取引用链接
            references = cve.get("references", [])

            # 提取受影响的产品
            configurations = cve.get("configurations", [])
            affected_products = self.extract_affected_products(configurations)

            parsed_cve = {
                "cve_id": cve_id,
                "description": description,
                "published_date": cve.get("published", ""),
                "last_modified": cve.get("lastModified", ""),
                "cvss_score": cvss_data.get("baseScore"),
                "cvss_severity": cvss_data.get("baseSeverity"),
                "cvss_vector": cvss_data.get("vectorString"),
                "references": [ref.get("url") for ref in references],
                "affected_products": affected_products,
                "source": "NVD",
                "raw_data": cve
            }

            parsed_cves.append(parsed_cve)

        return parsed_cves

    def extract_affected_products(self, configurations: List[Dict]) -> List[str]:
        """提取受影响的产品列表"""
        products = []

        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                cpe_matches = node.get("cpeMatch", [])
                for cpe in cpe_matches:
                    if cpe.get("vulnerable"):
                        products.append(cpe.get("criteria", ""))

        return products

    async def close(self):
        """关闭 HTTP 会话"""
        if self.session:
            await self.session.close()
```

### 4.2 数据处理模块

```python
# backend/app/processors/parser.py
import re
from typing import Dict, Any, List, Optional
from datetime import datetime
import hashlib
import json

class CVEParser:
    """CVE 数据解析器"""

    def __init__(self):
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}')
        self.cwe_pattern = re.compile(r'CWE-\d+')

    def parse_and_normalize(self, raw_cve: Dict[str, Any]) -> Dict[str, Any]:
        """
        解析并标准化 CVE 数据

        Args:
            raw_cve: 原始 CVE 数据

        Returns:
            标准化的 CVE 数据
        """
        normalized = {
            "cve_id": self.extract_cve_id(raw_cve),
            "title": self.extract_title(raw_cve),
            "description": self.clean_description(raw_cve.get("description", "")),
            "severity": self.normalize_severity(raw_cve.get("cvss_severity")),
            "cvss_score": self.validate_cvss_score(raw_cve.get("cvss_score")),
            "cvss_vector": raw_cve.get("cvss_vector", ""),
            "cwe_ids": self.extract_cwe_ids(raw_cve),
            "affected_products": self.parse_affected_products(raw_cve.get("affected_products", [])),
            "references": self.validate_references(raw_cve.get("references", [])),
            "published_date": self.parse_date(raw_cve.get("published_date")),
            "last_modified": self.parse_date(raw_cve.get("last_modified")),
            "tags": self.generate_tags(raw_cve),
            "hash": self.generate_hash(raw_cve),
            "source": raw_cve.get("source", "UNKNOWN"),
            "metadata": self.extract_metadata(raw_cve)
        }

        return normalized

    def extract_cve_id(self, raw_cve: Dict) -> str:
        """提取并验证 CVE ID"""
        cve_id = raw_cve.get("cve_id", "")
        if self.cve_pattern.match(cve_id):
            return cve_id
        return ""

    def extract_title(self, raw_cve: Dict) -> str:
        """生成 CVE 标题"""
        cve_id = raw_cve.get("cve_id", "")
        products = raw_cve.get("affected_products", [])

        if products:
            # 简化产品名称
            product_names = []
            for product in products[:3]:  # 最多显示3个产品
                parts = product.split(":")
                if len(parts) >= 4:
                    vendor = parts[3]
                    product_name = parts[4]
                    product_names.append(f"{vendor} {product_name}")

            if product_names:
                return f"{cve_id}: 影响 {', '.join(product_names)} 的漏洞"

        return f"{cve_id}: 安全漏洞"

    def clean_description(self, description: str) -> str:
        """清理和格式化描述文本"""
        # 移除多余的空白字符
        description = re.sub(r'\s+', ' ', description)
        # 移除 HTML 标签
        description = re.sub(r'<[^>]+>', '', description)
        return description.strip()

    def normalize_severity(self, severity: Optional[str]) -> str:
        """标准化严重等级"""
        if not severity:
            return "UNKNOWN"

        severity_map = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
            "NONE": "INFO"
        }

        return severity_map.get(severity.upper(), "UNKNOWN")

    def validate_cvss_score(self, score: Optional[float]) -> Optional[float]:
        """验证 CVSS 评分"""
        if score is None:
            return None

        try:
            score = float(score)
            if 0.0 <= score <= 10.0:
                return round(score, 1)
        except (ValueError, TypeError):
            pass

        return None

    def extract_cwe_ids(self, raw_cve: Dict) -> List[str]:
        """提取 CWE ID"""
        cwe_ids = []
        description = raw_cve.get("description", "")
        raw_data = raw_cve.get("raw_data", {})

        # 从描述中提取
        cwe_matches = self.cwe_pattern.findall(description)
        cwe_ids.extend(cwe_matches)

        # 从原始数据中提取
        weaknesses = raw_data.get("weaknesses", [])
        for weakness in weaknesses:
            descriptions = weakness.get("description", [])
            for desc in descriptions:
                value = desc.get("value", "")
                if value.startswith("CWE-"):
                    cwe_ids.append(value)

        return list(set(cwe_ids))

    def parse_affected_products(self, products: List[str]) -> List[Dict[str, str]]:
        """解析受影响的产品"""
        parsed_products = []

        for product in products:
            # CPE 格式: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
            parts = product.split(":")

            if len(parts) >= 5:
                parsed_product = {
                    "vendor": parts[3] if len(parts) > 3 else "",
                    "product": parts[4] if len(parts) > 4 else "",
                    "version": parts[5] if len(parts) > 5 else "*",
                    "cpe": product
                }
                parsed_products.append(parsed_product)

        return parsed_products

    def validate_references(self, references: List[str]) -> List[Dict[str, str]]:
        """验证和分类引用链接"""
        validated_refs = []

        for ref in references:
            if not ref or not ref.startswith(("http://", "https://")):
                continue

            ref_type = "OTHER"

            # 识别引用类型
            if "github.com" in ref:
                ref_type = "GITHUB"
            elif "cve.mitre.org" in ref:
                ref_type = "MITRE"
            elif "nvd.nist.gov" in ref:
                ref_type = "NVD"
            elif "exploit-db.com" in ref:
                ref_type = "EXPLOIT"
            elif any(vendor in ref for vendor in ["microsoft.com", "apple.com", "oracle.com"]):
                ref_type = "VENDOR"

            validated_refs.append({
                "url": ref,
                "type": ref_type
            })

        return validated_refs

    def parse_date(self, date_str: str) -> Optional[datetime]:
        """解析日期字符串"""
        if not date_str:
            return None

        date_formats = [
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d"
        ]

        for fmt in date_formats:
            try:
                return datetime.strptime(date_str.replace("Z", ""), fmt)
            except ValueError:
                continue

        return None

    def generate_tags(self, raw_cve: Dict) -> List[str]:
        """生成标签"""
        tags = []

        # 基于严重性的标签
        severity = raw_cve.get("cvss_severity", "")
        if severity in ["CRITICAL", "HIGH"]:
            tags.append("紧急")

        # 基于 CWE 的标签
        description = raw_cve.get("description", "").lower()

        tag_keywords = {
            "远程代码执行": ["remote code execution", "rce"],
            "SQL注入": ["sql injection", "sqli"],
            "跨站脚本": ["cross-site scripting", "xss"],
            "缓冲区溢出": ["buffer overflow", "stack overflow"],
            "权限提升": ["privilege escalation", "elevation of privilege"],
            "拒绝服务": ["denial of service", "dos", "ddos"],
            "信息泄露": ["information disclosure", "data leak"],
            "身份认证绕过": ["authentication bypass", "auth bypass"]
        }

        for tag, keywords in tag_keywords.items():
            if any(keyword in description for keyword in keywords):
                tags.append(tag)

        return tags

    def generate_hash(self, raw_cve: Dict) -> str:
        """生成数据哈希值用于去重"""
        unique_string = f"{raw_cve.get('cve_id', '')}_{raw_cve.get('last_modified', '')}"
        return hashlib.md5(unique_string.encode()).hexdigest()

    def extract_metadata(self, raw_cve: Dict) -> Dict[str, Any]:
        """提取额外的元数据"""
        metadata = {
            "import_timestamp": datetime.now().isoformat(),
            "data_version": "2.0"
        }

        # 提取额外信息
        raw_data = raw_cve.get("raw_data", {})
        if raw_data:
            metadata["assigner"] = raw_data.get("sourceIdentifier", "")
            metadata["vuln_status"] = raw_data.get("vulnStatus", "")

        return metadata
```

### 4.3 数据库存储层

```python
# backend/app/models/cve.py
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
from bson import ObjectId

class CVEModel(BaseModel):
    """CVE 数据模型"""

    id: Optional[str] = Field(None, alias="_id")
    cve_id: str = Field(..., description="CVE 编号")
    title: str = Field(..., description="漏洞标题")
    description: str = Field(..., description="漏洞描述")
    severity: str = Field(..., description="严重等级")
    cvss_score: Optional[float] = Field(None, description="CVSS 评分")
    cvss_vector: Optional[str] = Field(None, description="CVSS 向量")
    cwe_ids: List[str] = Field(default_factory=list, description="CWE ID 列表")
    affected_products: List[Dict[str, str]] = Field(default_factory=list, description="受影响产品")
    references: List[Dict[str, str]] = Field(default_factory=list, description="参考链接")
    published_date: Optional[datetime] = Field(None, description="发布日期")
    last_modified: Optional[datetime] = Field(None, description="最后修改日期")
    tags: List[str] = Field(default_factory=list, description="标签")
    hash: str = Field(..., description="数据哈希")
    source: str = Field(..., description="数据源")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="元数据")

    # 分析结果
    risk_score: Optional[float] = Field(None, description="风险评分")
    exploitability: Optional[str] = Field(None, description="可利用性")
    remediation: Optional[str] = Field(None, description="修复建议")

    # 状态字段
    status: str = Field(default="NEW", description="处理状态")
    reviewed: bool = Field(default=False, description="是否已审核")
    notifications_sent: bool = Field(default=False, description="是否已发送通知")

    class Config:
        populate_by_name = True
        json_encoders = {
            ObjectId: str,
            datetime: lambda v: v.isoformat() if v else None
        }
```

```python
# backend/app/core/database.py
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import ASCENDING, DESCENDING, TEXT
from typing import Optional
import redis.asyncio as redis
from app.core.config import settings

class MongoDB:
    client: Optional[AsyncIOMotorClient] = None
    database: Optional[AsyncIOMotorDatabase] = None

class RedisCache:
    client: Optional[redis.Redis] = None

mongodb = MongoDB()
redis_cache = RedisCache()

async def connect_to_mongo():
    """连接到 MongoDB"""
    mongodb.client = AsyncIOMotorClient(settings.MONGODB_URL)
    mongodb.database = mongodb.client[settings.MONGODB_DB_NAME]

    # 创建索引
    await create_indexes()

async def close_mongo_connection():
    """关闭 MongoDB 连接"""
    if mongodb.client:
        mongodb.client.close()

async def connect_to_redis():
    """连接到 Redis"""
    redis_cache.client = await redis.from_url(
        settings.REDIS_URL,
        encoding="utf-8",
        decode_responses=True
    )

async def close_redis_connection():
    """关闭 Redis 连接"""
    if redis_cache.client:
        await redis_cache.client.close()

async def create_indexes():
    """创建数据库索引"""
    cve_collection = mongodb.database.cves

    # 创建索引
    await cve_collection.create_index([("cve_id", ASCENDING)], unique=True)
    await cve_collection.create_index([("published_date", DESCENDING)])
    await cve_collection.create_index([("severity", ASCENDING)])
    await cve_collection.create_index([("cvss_score", DESCENDING)])
    await cve_collection.create_index([("tags", ASCENDING)])
    await cve_collection.create_index([("hash", ASCENDING)], unique=True)

    # 全文搜索索引
    await cve_collection.create_index([
        ("description", TEXT),
        ("title", TEXT)
    ])

def get_database() -> AsyncIOMotorDatabase:
    """获取数据库实例"""
    return mongodb.database

def get_redis() -> redis.Redis:
    """获取 Redis 实例"""
    return redis_cache.client
```

### 4.4 分析引擎模块

```python
# backend/app/analyzers/risk_assessor.py
from typing import Dict, Any, List, Tuple
from datetime import datetime, timedelta
import math

class RiskAssessor:
    """风险评估器"""

    def __init__(self):
        self.exploit_db_cache = {}
        self.threat_intelligence = {}

    def calculate_risk_score(self, cve_data: Dict[str, Any]) -> Tuple[float, str]:
        """
        计算综合风险评分

        Args:
            cve_data: CVE 数据

        Returns:
            (风险评分, 风险等级)
        """
        # 基础评分因子
        cvss_weight = 0.4
        exploitability_weight = 0.3
        impact_weight = 0.2
        temporal_weight = 0.1

        # CVSS 评分
        cvss_score = cve_data.get("cvss_score", 0) or 0
        cvss_factor = cvss_score / 10.0

        # 可利用性评分
        exploitability_factor = self.assess_exploitability(cve_data)

        # 影响范围评分
        impact_factor = self.assess_impact(cve_data)

        # 时间因子（新漏洞权重更高）
        temporal_factor = self.calculate_temporal_factor(cve_data)

        # 计算综合风险评分
        risk_score = (
            cvss_factor * cvss_weight +
            exploitability_factor * exploitability_weight +
            impact_factor * impact_weight +
            temporal_factor * temporal_weight
        ) * 100

        # 确定风险等级
        risk_level = self.determine_risk_level(risk_score)

        return round(risk_score, 2), risk_level

    def assess_exploitability(self, cve_data: Dict[str, Any]) -> float:
        """
        评估可利用性

        Args:
            cve_data: CVE 数据

        Returns:
            可利用性评分 (0-1)
        """
        score = 0.0

        # 检查是否存在公开利用代码
        references = cve_data.get("references", [])
        exploit_indicators = ["exploit-db.com", "github.com", "metasploit"]

        for ref in references:
            url = ref.get("url", "").lower()
            if any(indicator in url for indicator in exploit_indicators):
                score += 0.3
                break

        # 检查漏洞类型
        cwe_ids = cve_data.get("cwe_ids", [])
        high_risk_cwes = [
            "CWE-78",   # OS Command Injection
            "CWE-89",   # SQL Injection
            "CWE-79",   # Cross-site Scripting
            "CWE-434",  # Unrestricted Upload
            "CWE-611",  # XXE
            "CWE-918",  # SSRF
        ]

        if any(cwe in cwe_ids for cwe in high_risk_cwes):
            score += 0.4

        # 检查 CVSS 向量
        cvss_vector = cve_data.get("cvss_vector", "")

        # 网络可达性
        if "AV:N" in cvss_vector:  # Network
            score += 0.2
        elif "AV:A" in cvss_vector:  # Adjacent
            score += 0.1

        # 攻击复杂度
        if "AC:L" in cvss_vector:  # Low
            score += 0.1

        return min(score, 1.0)

    def assess_impact(self, cve_data: Dict[str, Any]) -> float:
        """
        评估影响范围

        Args:
            cve_data: CVE 数据

        Returns:
            影响评分 (0-1)
        """
        score = 0.0

        # 受影响产品数量
        affected_products = cve_data.get("affected_products", [])
        product_count = len(affected_products)

        if product_count > 10:
            score += 0.3
        elif product_count > 5:
            score += 0.2
        elif product_count > 0:
            score += 0.1

        # 检查关键产品
        critical_vendors = [
            "microsoft", "apple", "google", "oracle",
            "cisco", "vmware", "adobe", "apache"
        ]

        for product in affected_products:
            vendor = product.get("vendor", "").lower()
            if any(critical in vendor for critical in critical_vendors):
                score += 0.3
                break

        # CVSS 影响指标
        cvss_vector = cve_data.get("cvss_vector", "")

        if "C:H" in cvss_vector:  # Confidentiality High
            score += 0.1
        if "I:H" in cvss_vector:  # Integrity High
            score += 0.1
        if "A:H" in cvss_vector:  # Availability High
            score += 0.1

        # 检查是否影响认证
        if "CWE-287" in cve_data.get("cwe_ids", []):  # Authentication Issues
            score += 0.1

        return min(score, 1.0)

    def calculate_temporal_factor(self, cve_data: Dict[str, Any]) -> float:
        """
        计算时间因子

        Args:
            cve_data: CVE 数据

        Returns:
            时间因子 (0-1)
        """
        published_date = cve_data.get("published_date")

        if not published_date:
            return 0.5

        # 计算漏洞年龄（天）
        if isinstance(published_date, str):
            try:
                published_date = datetime.fromisoformat(published_date.replace("Z", ""))
            except:
                return 0.5

        age_days = (datetime.now() - published_date).days

        # 使用指数衰减函数
        # 新漏洞（<7天）权重最高，随时间递减
        if age_days <= 7:
            return 1.0
        elif age_days <= 30:
            return 0.8
        elif age_days <= 90:
            return 0.6
        elif age_days <= 180:
            return 0.4
        else:
            # 使用指数衰减
            return max(0.2, math.exp(-age_days / 365))

    def determine_risk_level(self, risk_score: float) -> str:
        """
        确定风险等级

        Args:
            risk_score: 风险评分

        Returns:
            风险等级
        """
        if risk_score >= 90:
            return "CRITICAL"
        elif risk_score >= 70:
            return "HIGH"
        elif risk_score >= 40:
            return "MEDIUM"
        elif risk_score >= 10:
            return "LOW"
        else:
            return "INFO"

    def generate_remediation_advice(self, cve_data: Dict[str, Any]) -> str:
        """
        生成修复建议

        Args:
            cve_data: CVE 数据

        Returns:
            修复建议
        """
        advice = []
        severity = cve_data.get("severity", "")
        cwe_ids = cve_data.get("cwe_ids", [])

        # 基于严重性的建议
        if severity in ["CRITICAL", "HIGH"]:
            advice.append("【紧急】建议立即采取修复措施")
            advice.append("1. 立即评估受影响系统")
            advice.append("2. 应用官方补丁或临时缓解措施")
            advice.append("3. 监控系统日志以检测潜在攻击")
        elif severity == "MEDIUM":
            advice.append("【重要】建议在计划维护窗口内修复")
            advice.append("1. 评估业务影响")
            advice.append("2. 制定修复计划")
            advice.append("3. 在测试环境验证补丁")
        else:
            advice.append("【常规】建议在下次更新周期修复")

        # 基于 CWE 的特定建议
        cwe_advice = {
            "CWE-89": [
                "使用参数化查询防止 SQL 注入",
                "实施输入验证和过滤",
                "应用最小权限原则"
            ],
            "CWE-79": [
                "对所有用户输入进行编码",
                "实施内容安全策略(CSP)",
                "使用安全的框架和库"
            ],
            "CWE-78": [
                "避免使用系统命令",
                "严格验证和清理输入",
                "使用白名单验证"
            ]
        }

        for cwe in cwe_ids:
            if cwe in cwe_advice:
                advice.extend(cwe_advice[cwe])
                break

        # 通用建议
        advice.extend([
            "",
            "通用安全措施：",
            "• 及时更新到最新版本",
            "• 实施纵深防御策略",
            "• 定期进行安全审计",
            "• 保持安全补丁更新"
        ])

        return "\n".join(advice)
```

### 4.5 API 接口模块

```python
# backend/app/api/v1/cve.py
from fastapi import APIRouter, Query, HTTPException, Depends
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from app.models.cve import CVEModel
from app.services.cve_service import CVEService
from app.core.database import get_database
from app.api.deps import get_current_user

router = APIRouter()

@router.get("/cves", response_model=List[CVEModel])
async def get_cves(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[str] = None,
    search: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    db = Depends(get_database)
):
    """
    获取 CVE 列表

    支持分页、过滤和搜索
    """
    service = CVEService(db)

    filters = {}

    if severity:
        filters["severity"] = severity.upper()

    if search:
        filters["$text"] = {"$search": search}

    if start_date:
        filters["published_date"] = {"$gte": start_date}

    if end_date:
        if "published_date" not in filters:
            filters["published_date"] = {}
        filters["published_date"]["$lte"] = end_date

    cves = await service.get_cves(
        filters=filters,
        skip=(page - 1) * page_size,
        limit=page_size
    )

    return cves

@router.get("/cves/{cve_id}", response_model=CVEModel)
async def get_cve(
    cve_id: str,
    db = Depends(get_database)
):
    """
    获取单个 CVE 详情
    """
    service = CVEService(db)
    cve = await service.get_cve_by_id(cve_id)

    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")

    return cve

@router.get("/cves/stats/overview")
async def get_stats_overview(
    days: int = Query(7, ge=1, le=365),
    db = Depends(get_database)
):
    """
    获取统计概览
    """
    service = CVEService(db)

    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)

    stats = await service.get_statistics(start_date, end_date)

    return stats

@router.get("/cves/stats/trending")
async def get_trending_cves(
    limit: int = Query(10, ge=1, le=50),
    db = Depends(get_database)
):
    """
    获取热门/高风险 CVE
    """
    service = CVEService(db)

    trending = await service.get_trending_cves(limit)

    return trending

@router.post("/cves/{cve_id}/subscribe")
async def subscribe_to_cve(
    cve_id: str,
    notification_channels: List[str],
    current_user = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    订阅 CVE 更新通知
    """
    service = CVEService(db)

    subscription = await service.create_subscription(
        user_id=current_user.id,
        cve_id=cve_id,
        channels=notification_channels
    )

    return {"message": "Successfully subscribed", "subscription_id": subscription.id}

@router.get("/cves/export")
async def export_cves(
    format: str = Query("json", regex="^(json|csv|pdf)$"),
    severity: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    current_user = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    导出 CVE 数据
    """
    service = CVEService(db)

    filters = {}
    if severity:
        filters["severity"] = severity.upper()
    if start_date:
        filters["published_date"] = {"$gte": start_date}
    if end_date:
        if "published_date" not in filters:
            filters["published_date"] = {}
        filters["published_date"]["$lte"] = end_date

    export_data = await service.export_data(
        filters=filters,
        format=format,
        user_id=current_user.id
    )

    return export_data
```

## 5. 部署配置

### 5.1 Docker Compose 配置

```yaml
# docker-compose.yml
version: '3.8'

services:
  # MongoDB 数据库
  mongodb:
    image: mongo:6.0
    container_name: cve-mongodb
    restart: always
    ports:
      - "27017:27017"
    environment:
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: ${MONGO_PASSWORD}
      MONGO_INITDB_DATABASE: cve_monitor
    volumes:
      - mongo-data:/data/db
      - ./init-mongo.js:/docker-entrypoint-initdb.d/init-mongo.js:ro
    networks:
      - cve-network

  # Redis 缓存
  redis:
    image: redis:7-alpine
    container_name: cve-redis
    restart: always
    ports:
      - "6379:6379"
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis-data:/data
    networks:
      - cve-network

  # RabbitMQ 消息队列
  rabbitmq:
    image: rabbitmq:3.12-management
    container_name: cve-rabbitmq
    restart: always
    ports:
      - "5672:5672"
      - "15672:15672"
    environment:
      RABBITMQ_DEFAULT_USER: admin
      RABBITMQ_DEFAULT_PASS: ${RABBITMQ_PASSWORD}
    volumes:
      - rabbitmq-data:/var/lib/rabbitmq
    networks:
      - cve-network

  # 后端 API 服务
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    container_name: cve-backend
    restart: always
    ports:
      - "8000:8000"
    environment:
      MONGODB_URL: mongodb://admin:${MONGO_PASSWORD}@mongodb:27017/cve_monitor?authSource=admin
      REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379/0
      RABBITMQ_URL: amqp://admin:${RABBITMQ_PASSWORD}@rabbitmq:5672/
      NVD_API_KEY: ${NVD_API_KEY}
      SECRET_KEY: ${SECRET_KEY}
    depends_on:
      - mongodb
      - redis
      - rabbitmq
    volumes:
      - ./backend/app:/app
    networks:
      - cve-network

  # Celery Worker
  celery-worker:
    build:
      context: ./backend
      dockerfile: Dockerfile
    container_name: cve-celery-worker
    restart: always
    command: celery -A app.tasks worker --loglevel=info
    environment:
      MONGODB_URL: mongodb://admin:${MONGO_PASSWORD}@mongodb:27017/cve_monitor?authSource=admin
      REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379/0
      RABBITMQ_URL: amqp://admin:${RABBITMQ_PASSWORD}@rabbitmq:5672/
    depends_on:
      - mongodb
      - redis
      - rabbitmq
    volumes:
      - ./backend/app:/app
    networks:
      - cve-network

  # Celery Beat (定时任务调度)
  celery-beat:
    build:
      context: ./backend
      dockerfile: Dockerfile
    container_name: cve-celery-beat
    restart: always
    command: celery -A app.tasks beat --loglevel=info
    environment:
      MONGODB_URL: mongodb://admin:${MONGO_PASSWORD}@mongodb:27017/cve_monitor?authSource=admin
      REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379/0
      RABBITMQ_URL: amqp://admin:${RABBITMQ_PASSWORD}@rabbitmq:5672/
    depends_on:
      - mongodb
      - redis
      - rabbitmq
    volumes:
      - ./backend/app:/app
    networks:
      - cve-network

  # 前端应用
  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    container_name: cve-frontend
    restart: always
    ports:
      - "3000:80"
    environment:
      REACT_APP_API_URL: http://backend:8000
    depends_on:
      - backend
    networks:
      - cve-network

  # Nginx 反向代理
  nginx:
    image: nginx:alpine
    container_name: cve-nginx
    restart: always
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
    depends_on:
      - backend
      - frontend
    networks:
      - cve-network

volumes:
  mongo-data:
  redis-data:
  rabbitmq-data:

networks:
  cve-network:
    driver: bridge
```

### 5.2 环境变量配置

```bash
# .env
# MongoDB
MONGO_PASSWORD=your_secure_password_here

# Redis
REDIS_PASSWORD=your_redis_password_here

# RabbitMQ
RABBITMQ_PASSWORD=your_rabbitmq_password_here

# NVD API
NVD_API_KEY=your_nvd_api_key_here

# Application
SECRET_KEY=your_secret_key_here
JWT_SECRET_KEY=your_jwt_secret_here

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_email_password

# Notification Webhooks
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

## 6. 快速启动指南

### 6.1 前置要求

- Docker 20.10+
- Docker Compose 2.0+
- Python 3.10+ (用于本地开发)
- Node.js 16+ (用于前端开发)
- Git

### 6.2 安装步骤

```bash
# 1. 克隆项目
git clone https://github.com/your-org/cve-monitor-system.git
cd cve-monitor-system

# 2. 配置环境变量
cp .env.example .env
# 编辑 .env 文件，填入实际配置

# 3. 启动所有服务
docker-compose up -d

# 4. 初始化数据库
docker-compose exec backend python -m app.scripts.init_db

# 5. 创建管理员用户
docker-compose exec backend python -m app.scripts.create_admin

# 6. 访问应用
# Web界面: http://localhost
# API文档: http://localhost:8000/docs
# RabbitMQ管理界面: http://localhost:15672
```

### 6.3 开发模式

```bash
# 激活虚拟环境
source D:\AI\cursor\starone\.venv\Scripts\activate

# 安装后端依赖
cd backend
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 运行后端开发服务器
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# 安装前端依赖
cd ../frontend
npm install

# 运行前端开发服务器
npm start
```

## 7. 测试策略

### 7.1 单元测试

```python
# backend/tests/test_collectors.py
import pytest
from unittest.mock import Mock, patch
from app.collectors.nvd_collector import NVDCollector

@pytest.mark.asyncio
async def test_nvd_collector_parse_cves():
    collector = NVDCollector()

    raw_cves = [{
        "cve": {
            "id": "CVE-2024-12345",
            "descriptions": [
                {"lang": "en", "value": "Test vulnerability"}
            ],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH"
                    }
                }]
            }
        }
    }]

    parsed = collector.parse_cves(raw_cves)

    assert len(parsed) == 1
    assert parsed[0]["cve_id"] == "CVE-2024-12345"
    assert parsed[0]["cvss_score"] == 7.5
```

### 7.2 集成测试

```python
# backend/tests/test_api.py
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_get_cves():
    response = client.get("/api/v1/cves?page=1&page_size=10")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_get_cve_by_id():
    response = client.get("/api/v1/cves/CVE-2024-12345")
    assert response.status_code in [200, 404]
```

## 8. 监控和运维

### 8.1 Prometheus 配置

```yaml
# prometheus/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'cve-backend'
    static_configs:
      - targets: ['backend:8000']
    metrics_path: '/metrics'

  - job_name: 'mongodb'
    static_configs:
      - targets: ['mongodb-exporter:9216']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']
```

### 8.2 日志配置

```python
# backend/app/core/logging.py
import logging
from logging.handlers import RotatingFileHandler
import sys

def setup_logging():
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter(log_format))

    # File handler with rotation
    file_handler = RotatingFileHandler(
        "logs/app.log",
        maxBytes=10485760,  # 10MB
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(log_format))

    # Configure root logger
    logging.root.setLevel(logging.INFO)
    logging.root.addHandler(console_handler)
    logging.root.addHandler(file_handler)
```

## 9. 安全加固

### 9.1 API 安全

- JWT 认证
- Rate Limiting
- CORS 配置
- Input Validation
- SQL Injection Prevention

### 9.2 数据安全

- 数据加密传输 (HTTPS)
- 敏感数据脱敏
- 定期安全审计
- 访问控制 (RBAC)

## 10. 性能优化

### 10.1 数据库优化

- 索引优化
- 查询优化
- 连接池配置
- 读写分离

### 10.2 缓存策略

- Redis 缓存热点数据
- CDN 加速静态资源
- 浏览器缓存优化

## 11. 后续改进计划

1. **AI 增强功能**
   - 智能漏洞分类
   - 自动修复建议生成
   - 威胁情报关联

2. **扩展数据源**
   - 更多漏洞数据库集成
   - 暗网威胁情报
   - 社交媒体监控

3. **可视化增强**
   - 实时大屏展示
   - 3D 威胁地图
   - 趋势预测图表

4. **自动化响应**
   - 自动补丁部署
   - 防火墙规则更新
   - 事件响应工作流

---

## 总结

本解决方案提供了一个完整、可扩展的 CVE 漏洞监控与管理系统，涵盖了从数据采集到分析展示的全流程。系统采用微服务架构，支持容器化部署，具有良好的可扩展性和维护性。通过实施本方案，组织可以及时发现和响应安全威胁，提升整体安全防护能力。