"""
CVE 数据采集脚本 - 可直接运行
用于从 NVD (National Vulnerability Database) 采集最新的 CVE 数据
"""
import asyncio
import aiohttp
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any
import logging
import os
from pathlib import Path
from dotenv import load_dotenv  # Add this import to load .env file

# Load environment variables from .env file
load_dotenv(override=True)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CVECollector:
    """CVE 数据采集器"""

    def __init__(self, api_key: str = None):
        """
        初始化采集器

        Args:
            api_key: NVD API 密钥，如果不提供将从环境变量 NVD_API_KEY 获取
        """
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        # Ensure api_key parameter is handled properly - only use if provided
        # This prevents API key from being set to None when None is passed
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.session = None
        self.data_dir = Path("cve_data")
        self.data_dir.mkdir(exist_ok=True)

    async def __aenter__(self):
        """异步上下文管理器入口"""
        timeout = aiohttp.ClientTimeout(total=30)
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        self.session = aiohttp.ClientSession(
            timeout=timeout,
            headers=headers
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器出口"""
        if self.session:
            await self.session.close()

    async def fetch_cves(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """
        获取指定时间范围的 CVE 数据

        Args:
            start_date: 开始日期
            end_date: 结束日期

        Returns:
            CVE 数据列表
        """
        all_cves = []
        start_index = 0
        results_per_page = 100

        # Format dates according to NVD API requirements (ISO 8601 format with milliseconds)
        # Ensure dates are in the past to prevent HTTP 404 errors
        current_time = datetime.now()
        if start_date > current_time:
            start_date = current_time
        if end_date > current_time:
            end_date = current_time
            
        start_str = start_date.strftime("%Y-%m-%dT%H:%M:%S")
        end_str = end_date.strftime("%Y-%m-%dT%H:%M:%S")

        logger.info(f"正在获取 {start_str} 到 {end_str} 的 CVE 数据...")

        while True:
            params = {
                "pubStartDate": start_str,
                "pubEndDate": end_str,
                "startIndex": start_index,
                "resultsPerPage": results_per_page
            }

            try:
                async with self.session.get(self.base_url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()

                        vulnerabilities = data.get("vulnerabilities", [])
                        total_results = data.get("totalResults", 0)

                        logger.info(
                            f"获取第 {start_index + 1}-{start_index + len(vulnerabilities)} 条，"
                            f"共 {total_results} 条"
                        )

                        if not vulnerabilities:
                            break

                        all_cves.extend(vulnerabilities)

                        # 检查是否还有更多数据
                        if start_index + len(vulnerabilities) >= total_results:
                            break

                        start_index += results_per_page

                        # 避免请求过快（NVD API 限制）
                        if not self.api_key:
                            await asyncio.sleep(6)  # 无 API Key 时限制为 10 请求/分钟
                        else:
                            await asyncio.sleep(0.6)  # 有 API Key 时限制为 100 请求/分钟

                    else:
                        logger.error(f"API 请求失败: HTTP {response.status}")
                        text = await response.text()
                        logger.error(f"响应内容: {text}")
                        break

            except asyncio.TimeoutError:
                logger.error("请求超时")
                break
            except Exception as e:
                logger.error(f"请求出错: {str(e)}")
                break

        return all_cves

    def parse_cve(self, raw_cve: Dict[str, Any]) -> Dict[str, Any]:
        """
        解析单个 CVE 数据

        Args:
            raw_cve: 原始 CVE 数据

        Returns:
            解析后的 CVE 数据
        """
        cve = raw_cve.get("cve", {})

        # 提取 CVE ID
        cve_id = cve.get("id", "")

        # 提取描述
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        # 提取 CVSS 评分
        metrics = cve.get("metrics", {})
        cvss_score = None
        cvss_severity = None
        cvss_vector = None

        # 严重性优先级：CVSS v4.0 → v3.1 → v3.0 → v2.0
        # 每一级只有在实际有 baseScore（且 severity 非 NONE）时才采用
        def _is_valid_severity(sev):
            return sev and str(sev).upper() not in ("NONE", "N/A", "")

        for ver_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            if ver_key in metrics and metrics[ver_key]:
                # 遍历所有条目（NVD Primary + CNA Secondary），取第一个有效评分
                # 优先 Primary（NVD 官方），其次 Secondary（CNA 厂商）
                entries = sorted(metrics[ver_key],
                                 key=lambda e: 0 if e.get("type") == "Primary" else 1)
                for entry in entries:
                    cvss_data = entry.get("cvssData", {})
                    score = cvss_data.get("baseScore")
                    severity = cvss_data.get("baseSeverity")
                    if score is not None and _is_valid_severity(severity):
                        cvss_score = score
                        cvss_severity = severity
                        cvss_vector = cvss_data.get("vectorString")
                        break
                if cvss_severity is not None:
                    break

        # 回退到 CVSS v2.0
        if cvss_severity is None and "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            if score is not None:
                cvss_score = score
                cvss_severity = self.map_cvss_v2_severity(score)
                cvss_vector = cvss_data.get("vectorString")

        # 对于尚未评分的 CVE，根据漏洞状态标注
        vuln_status = cve.get("vulnStatus", "")
        if cvss_severity is None and vuln_status in ("Awaiting Analysis", "Received", "Undergoing Analysis"):
            cvss_severity = "AWAITING"

        # 提取引用链接
        references = []
        for ref in cve.get("references", []):
            references.append({
                "url": ref.get("url", ""),
                "source": ref.get("source", ""),
                "tags": ref.get("tags", [])
            })

        # 提取受影响的产品（CPE）
        affected_products = []
        configurations = cve.get("configurations", [])
        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                cpe_matches = node.get("cpeMatch", [])
                for cpe in cpe_matches:
                    if cpe.get("vulnerable"):
                        cpe_string = cpe.get("criteria", "")
                        # 解析 CPE 字符串
                        parts = cpe_string.split(":")
                        if len(parts) >= 5:
                            affected_products.append({
                                "cpe": cpe_string,
                                "vendor": parts[3] if len(parts) > 3 else "",
                                "product": parts[4] if len(parts) > 4 else "",
                                "version": parts[5] if len(parts) > 5 else "*",
                                "versionEndExcluding": cpe.get("versionEndExcluding"),
                                "versionEndIncluding": cpe.get("versionEndIncluding"),
                                "versionStartExcluding": cpe.get("versionStartExcluding"),
                                "versionStartIncluding": cpe.get("versionStartIncluding")
                            })

        # 提取 CWE
        weaknesses = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    weaknesses.append(desc.get("value", ""))

        parsed_cve = {
            "cve_id": cve_id,
            "description": description,
            "published_date": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
            "vuln_status": cve.get("vulnStatus", ""),
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "cvss_vector": cvss_vector,
            "metrics": metrics,
            "references": references,
            "affected_products": affected_products,
            "weaknesses": weaknesses,
            "source": "NVD"
        }

        return parsed_cve

    def map_cvss_v2_severity(self, score: float) -> str:
        """
        将 CVSS v2 分数映射到严重等级

        Args:
            score: CVSS v2 分数

        Returns:
            严重等级
        """
        if score is None:
            return None
        if score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"

    def save_to_file(self, cves: List[Dict[str, Any]], filename: str = None):
        """
        保存 CVE 数据到文件

        Args:
            cves: CVE 数据列表
            filename: 文件名
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"cves_{timestamp}.json"

        filepath = self.data_dir / filename

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(cves, f, ensure_ascii=False, indent=2, default=str)

        logger.info(f"数据已保存到: {filepath}")
        return filepath

    def print_summary(self, cves: List[Dict[str, Any]]):
        """
        打印 CVE 数据摘要

        Args:
            cves: CVE 数据列表
        """
        print("\n" + "=" * 60)
        print(f"CVE 数据采集摘要")
        print("=" * 60)
        print(f"总计获取 CVE 数量: {len(cves)}")

        if cves:
            # 统计严重等级
            severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
            for cve in cves:
                severity = cve.get("cvss_severity")
                if severity in severity_count:
                    severity_count[severity] += 1

            print("\n严重等级分布:")
            for severity, count in severity_count.items():
                if count > 0:
                    print(f"  {severity:8}: {count:4} 个")

            # 显示最新的几个 CVE
            print("\n最新的 CVE (前5个):")
            for cve in cves[:5]:
                cve_id = cve.get("cve_id", "未知")
                severity = cve.get("cvss_severity", "未知")
                score = cve.get("cvss_score", "N/A")
                # Handle None values to prevent format string errors
                severity_str = str(severity) if severity is not None else "未知"
                score_str = str(score) if score is not None else "N/A"
                print(f"  - {cve_id:20} | 严重性: {severity_str:8} | 评分: {score_str}")

            # 统计受影响最多的厂商
            vendor_count = {}
            for cve in cves:
                for product in cve.get("affected_products", []):
                    vendor = product.get("vendor", "")
                    if vendor and vendor != "*":
                        vendor_count[vendor] = vendor_count.get(vendor, 0) + 1

            if vendor_count:
                print("\n受影响最多的厂商 (前5个):")
                sorted_vendors = sorted(vendor_count.items(), key=lambda x: x[1], reverse=True)
                for vendor, count in sorted_vendors[:5]:
                    print(f"  - {vendor:20}: {count} 个漏洞")

        print("=" * 60 + "\n")


async def main():
    """主函数"""
    print("CVE 数据采集工具")
    print("-" * 40)

    # 设置时间范围（获取最近两年的数据，使用分段查询避免HTTP 404错误）
    # NVD API typically limits date ranges, so we'll collect in 120-day chunks
    end_date = datetime.now().replace(hour=23, minute=59, second=59, microsecond=999999)  # End of today (not future)
    start_date = end_date - timedelta(days=730)  # Two years ago

    print(f"采集时间范围: {start_date.date()} 至 {end_date.date()}")
    print(f"采集范围: 最近两年（730 天）")
    print("注意：由于 NVD API 限制，大量数据采集可能需要较长时间")
    print("预计时间: 有 API Key 约 10-20 分钟，无 API Key 约 2-3 小时")

    # 从环境变量获取 API Key（可选）
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        print("检测到 NVD API Key，将使用更高的请求限制")
        print("API Key已配置，支持更高的请求频率")
    else:
        print("未配置 API Key，使用默认请求限制（较慢）")
        print("提示: 可在 https://nvd.nist.gov/developers/request-an-api-key 申请免费 API Key")

    print("-" * 40)

    try:
        all_raw_cves = []
        
        # Collect data in chunks to avoid API date range limitations
        # NVD API typically works best with date ranges of 120 days or less
        current_start = start_date
        chunk_size = timedelta(days=120)
        
        async with CVECollector(api_key=api_key) as collector:
            while current_start < end_date:
                current_end = min(current_start + chunk_size, end_date)
                
                print(f"正在获取 {current_start.date()} 到 {current_end.date()} 的数据...")
                
                # Get data for this chunk
                chunk_cves = await collector.fetch_cves(current_start, current_end)
                all_raw_cves.extend(chunk_cves)
                
                logger.info(f"已获取 {len(chunk_cves)} 条 CVE 数据 (批次: {current_start.date()} 到 {current_end.date()})")
                
                # Move to next chunk
                current_start = current_end
                
                # Brief pause between chunks to be respectful to the API
                await asyncio.sleep(1)

            if all_raw_cves:
                # Parse data
                parsed_cves = []
                for raw_cve in all_raw_cves:
                    parsed = collector.parse_cve(raw_cve)
                    parsed_cves.append(parsed)

                # Save to file
                filepath = collector.save_to_file(parsed_cves)

                # Print summary
                collector.print_summary(parsed_cves)

                print(f"[SUCCESS] 采集完成！数据已保存到: {filepath}")
                print(f"总计采集: {len(all_raw_cves)} 条 CVE 数据")
            else:
                print("未获取到任何 CVE 数据")

    except Exception as e:
        logger.error(f"采集过程出错: {str(e)}")
        print(f"[ERROR] 采集失败: {str(e)}")


if __name__ == "__main__":
    # Windows 环境下需要设置事件循环策略
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    # 运行主函数
    asyncio.run(main())