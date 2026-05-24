"""
Dell 安全公告爬取器
使用 Exa API、HTTP 请求、Selenium 多策略从 Dell 官网获取安全公告
"""
import os
import asyncio
import aiohttp
from bs4 import BeautifulSoup
import re
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Set, Optional, Callable
import logging

try:
    from i18n import t as _t
except ImportError:
    def _t(key, **kwargs):
        return key

try:
    from cve_utils import clean_cve_ids
except ImportError:
    # 回退：如果 cve_utils 不可用，使用本地实现
    def clean_cve_ids(cve_input):
        """简化版 CVE ID 清洗函数"""
        import re
        if not cve_input:
            return []
        if isinstance(cve_input, str):
            text = cve_input
        elif isinstance(cve_input, (list, set)):
            text = ' '.join(str(item) for item in cve_input if item)
        else:
            return []
        matches = re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)
        seen = set()
        cleaned = []
        for cve_id in matches:
            cve_id_upper = cve_id.upper()
            if cve_id_upper not in seen:
                seen.add(cve_id_upper)
                cleaned.append(cve_id_upper)
        cleaned.sort()
        return cleaned

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DellSecurityScraper:
    """Dell 安全公告爬取器 — Exa API / HTTP / Selenium 多策略"""

    def __init__(self):
        self.base_url = "https://www.dell.com/support/security/en-us/"
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Sec-Ch-Ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Cache-Control': 'max-age=0',
            'DNT': '1',
        }

    async def fetch_security_advisories(
        self,
        days: int = 30,
        existing_dsa_ids: Set[str] = None,
        log_callback: Callable[[str], None] = None,
    ) -> List[Dict[str, Any]]:
        """
        获取 Dell 安全公告 — 主入口

        流程:
          1. 发现公告链接（Exa 搜索 -> 列表页 HTTP -> Selenium）
          2. 过滤数据库中已存在的 DSA
          3. 逐个抓取新公告详情页（Exa contents -> HTTP -> Selenium）
          4. 解析内容，提取 Impact / CVE / 产品 等字段
        """
        if existing_dsa_ids is None:
            existing_dsa_ids = set()

        def log(msg):
            logger.info(msg)
            if log_callback:
                log_callback(msg)

        exa_api_key = os.getenv("EXA_API_KEY")

        # ── Step 1: 发现公告链接 ──
        log(f"正在发现最近 {days} 天的 Dell 安全公告链接...")
        advisory_links = await self._discover_advisory_links(days, exa_api_key, log)

        if not advisory_links:
            log("未能从 Dell 官网发现安全公告链接")
            return []

        log(f"共发现 {len(advisory_links)} 个公告链接")

        # ── Step 2: 过滤已存在的 DSA ──
        existing_upper = {d.upper() for d in existing_dsa_ids}
        new_links = {}
        skipped = 0
        for dsa_id, url in advisory_links.items():
            if dsa_id.upper() in existing_upper:
                skipped += 1
            else:
                new_links[dsa_id] = url

        if skipped:
            log(f"跳过 {skipped} 条已存在的公告")
        if not new_links:
            log("所有发现的公告均已存在于数据库中")
            return []

        log(f"需要抓取 {len(new_links)} 条新公告详情...")

        # ── Step 3: 并发抓取详情页 ──
        advisories = []
        semaphore = asyncio.Semaphore(5)

        async def fetch_one(index, dsa_id, url):
            async with semaphore:
                try:
                    log(f"[{index}/{len(new_links)}] 正在抓取 {dsa_id}...")
                    advisory = await self._fetch_and_parse_detail(dsa_id, url, exa_api_key)
                    await asyncio.sleep(0.5)
                    if advisory:
                        impact_str = advisory.get('impact') or 'N/A'
                        cve_count = len(advisory.get('cve_ids', []))
                        log(f"  -> {dsa_id} — Impact: {impact_str}, CVE: {cve_count}")
                    else:
                        log(f"  -> {dsa_id} — 无法解析页面内容")
                    return advisory
                except Exception as e:
                    log(f"  -> {dsa_id} 抓取失败: {e}")
                    return None

        tasks = [
            fetch_one(i + 1, dsa_id, url)
            for i, (dsa_id, url) in enumerate(new_links.items())
        ]
        results = await asyncio.gather(*tasks)
        advisories = [advisory for advisory in results if advisory]

        log(f"成功抓取 {len(advisories)} 条新安全公告")
        return advisories

    # ================================================================
    #  发现公告链接
    # ================================================================

    async def _discover_advisory_links(self, days, exa_api_key, log):
        """依次尝试 Exa 多 query 搜索 / HTTP 列表页 / Selenium 发现 DSA 链接"""
        links = {}

        # 策略 1: Exa 多 query 搜索（按年份+产品线分多次搜索，覆盖长尾）
        if exa_api_key:
            log("策略 1: 使用 Exa 多 query 搜索 API 发现公告...")
            links = await self._discover_via_exa_multi_query(days, exa_api_key, log)
            if links:
                log(f"Exa 多 query 共发现 {len(links)} 个公告链接")
                return links

        # 策略 2: HTTP 爬取列表页
        log("策略 2: 直接 HTTP 爬取 Dell 安全公告列表页...")
        links = await self._discover_via_listing_page()
        if links:
            return links

        # 策略 3: Selenium（处理 JS 渲染页面）
        log("策略 3: 使用 Selenium 爬取列表页...")
        links = await self._discover_via_selenium()
        return links

    async def _discover_via_exa_multi_query(self, days, api_key, log):
        """Exa 多 query 轮询：按年份×产品线分多次搜索，合并去重"""
        all_links = {}
        start_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000Z")

        queries = [
            "Dell DSA security advisory vulnerability update",
            "Dell security advisory PowerEdge iDRAC BIOS",
            "Dell security advisory PowerStore PowerProtect VxRail",
            "Dell security advisory Latitude Precision OptiPlex XPS",
            "Dell security advisory PowerSwitch Networking firmware",
            "Dell security advisory Avamar NetWorker Data Domain",
        ]

        exa_credits_exhausted = False
        async with aiohttp.ClientSession() as session:
            for query in queries:
                if exa_credits_exhausted:
                    break
                try:
                    payload = {
                        "query": query,
                        "numResults": 100,
                        "includeDomains": ["dell.com"],
                        "startPublishedDate": start_date,
                        "type": "auto",
                    }
                    async with session.post(
                        "https://api.exa.ai/search",
                        headers={
                            "accept": "application/json",
                            "content-type": "application/json",
                            "x-api-key": api_key,
                        },
                        json=payload,
                        timeout=aiohttp.ClientTimeout(total=30),
                    ) as resp:
                        if resp.status == 200:
                            results = (await resp.json()).get("results", [])
                            new_count = 0
                            for r in results:
                                dsa_id = self._extract_dsa_id(r.get("url", ""), r.get("title", ""))
                                if dsa_id and dsa_id not in all_links:
                                    all_links[dsa_id] = r["url"]
                                    new_count += 1
                            log(f"  query [{query[:40]}...]: {len(results)} results, {new_count} new DSA")
                        elif resp.status == 402:
                            error_body = await resp.text()
                            log(f"  query [{query[:40]}...]: HTTP 402 - Exa API 额度已用完")
                            if "NO_MORE_CREDITS" in error_body:
                                log("⚠️  Exa API 额度耗尽，停止后续 Exa 请求，将使用备用策略")
                                exa_credits_exhausted = True
                                break
                        else:
                            log(f"  query [{query[:40]}...]: HTTP {resp.status}")
                    await asyncio.sleep(0.3)
                except Exception as e:
                    log(f"  query [{query[:40]}...]: error {e}")

        if exa_credits_exhausted and not all_links:
            log("Exa API 额度耗尽且未发现任何公告，将跳过策略1")
            return {}

        return all_links

    async def _discover_via_exa_search(self, days, api_key):
        """使用 Exa search API 搜索 Dell 安全公告页面"""
        links = {}
        start_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000Z")

        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "query": "Dell DSA security advisory vulnerability update",
                    "numResults": min(days // 2 + 10, 100),
                    "includeDomains": ["dell.com"],
                    "startPublishedDate": start_date,
                    "type": "auto",
                }
                async with session.post(
                    "https://api.exa.ai/search",
                    headers={
                        "accept": "application/json",
                        "content-type": "application/json",
                        "x-api-key": api_key,
                    },
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 200:
                        results = (await resp.json()).get("results", [])
                        for r in results:
                            dsa_id = self._extract_dsa_id(r.get("url", ""), r.get("title", ""))
                            if dsa_id:
                                links[dsa_id] = r["url"]
                        logger.info(f"Exa search: {len(results)} results -> {len(links)} DSA links")
                    elif resp.status == 402:
                        logger.warning("Exa search HTTP 402 - API 额度已用完，跳过")
                    else:
                        logger.warning(f"Exa search HTTP {resp.status}")
        except Exception as e:
            logger.warning(f"Exa search error: {e}")
        return links

    async def _discover_via_listing_page(self):
        """HTTP 爬取 Dell 安全公告列表页，提取所有 DSA 链接"""
        links = {}
        try:
            async with aiohttp.ClientSession(headers=self.headers) as session:
                async with session.get(
                    self.base_url,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 200:
                        html = await resp.text()
                        soup = BeautifulSoup(html, 'html.parser')

                        for a_tag in soup.find_all('a', href=True):
                            href = a_tag['href']
                            full_url = f"https://www.dell.com{href}" if href.startswith('/') else href
                            text = a_tag.get_text(strip=True)
                            dsa_id = self._extract_dsa_id(full_url, text)
                            if dsa_id and full_url.startswith('http'):
                                links[dsa_id] = full_url

                        logger.info(f"Listing page: {len(links)} DSA links found")
                    else:
                        logger.warning(f"Listing page HTTP {resp.status}")
        except Exception as e:
            logger.warning(f"Listing page scrape error: {e}")
        return links

    async def _discover_via_selenium(self):
        """使用 Selenium 爬取列表页（处理 JS 动态渲染）"""
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._selenium_get_links)
        except ImportError:
            logger.info("Selenium 未安装，跳过")
        except Exception as e:
            logger.warning(f"Selenium discovery error: {e}")
        return {}

    def _selenium_get_links(self):
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC

        links = {}
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')

        driver = webdriver.Chrome(options=options)
        try:
            driver.get(self.base_url)
            WebDriverWait(driver, 15).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            for a in driver.find_elements(By.TAG_NAME, "a"):
                href = a.get_attribute("href") or ""
                text = a.text or ""
                dsa_id = self._extract_dsa_id(href, text)
                if dsa_id and href.startswith('http'):
                    links[dsa_id] = href
            logger.info(f"Selenium: {len(links)} DSA links found")
        finally:
            driver.quit()
        return links

    # ================================================================
    #  抓取并解析单个公告详情页
    # ================================================================

    async def _fetch_and_parse_detail(self, dsa_id, url, exa_api_key=None):
        """抓取单个公告页面内容并解析为结构化数据"""
        text = ""
        html = ""

        # 1. Exa API 获取纯文本（优先）
        if exa_api_key:
            text = await self._fetch_content_exa(url, exa_api_key)

        # 2. HTTP 获取原始 HTML（用于解析表格）+ 文本回退
        raw_html = await self._fetch_raw_html(url)
        if raw_html:
            html = raw_html
            if not text:
                text = self._html_to_text(html)

        # 3. Selenium 兜底
        if not text:
            text = await self._fetch_content_selenium(url)

        if not text:
            return None

        # 过滤错误页面（403/404/CDN 拦截/文档不可用）
        if self._is_error_page(text, dsa_id):
            logger.info(f"{dsa_id}: 检测到错误页面，跳过")
            return None

        return self._parse_advisory_content(dsa_id, url, text, html)

    @staticmethod
    def _is_error_page(content: str, dsa_id: str = "") -> bool:
        """判断内容是否为错误页面（CDN 拦截 / 404 / 文档不可用）"""
        if not content:
            return True
        head = content[:2000].lower()

        error_signatures = [
            "you don't have permission to access",
            "access denied",
            "errors.edgesuite.net",
            "the chosen document is not currently available",
            "page not found",
            "document not found",
            "request blocked",
            "akamai reference",
            "reference #",
        ]
        hit_count = sum(1 for sig in error_signatures if sig in head)
        if hit_count >= 1 and len(content) < 3000:
            return True

        # 极短内容且不含 DSA 标识 → 视为错误
        if len(content) < 500:
            return True

        # 必须包含 DSA ID 或安全公告关键内容
        content_lower = content.lower()
        has_dsa = bool(dsa_id) and dsa_id.lower() in content_lower
        has_advisory_keywords = any(
            kw in content_lower for kw in [
                "summary", "affected products", "remediation",
                "cve-", "impact", "severity"
            ]
        )
        if not has_dsa and not has_advisory_keywords:
            return True

        return False

    async def _fetch_raw_html(self, url):
        """HTTP 请求获取原始 HTML（用于解析表格结构）"""
        try:
            jar = aiohttp.CookieJar()
            async with aiohttp.ClientSession(headers=self.headers, cookie_jar=jar) as session:
                # 先访问主页获取 cookies
                if 'dell.com' in url:
                    try:
                        async with session.get(
                            'https://www.dell.com',
                            timeout=aiohttp.ClientTimeout(total=10),
                        ) as _:
                            pass
                    except Exception:
                        pass
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 200:
                        return await resp.text()
                    elif resp.status == 403:
                        logger.warning(f"HTML fetch 403 Forbidden for {url}")
        except Exception as e:
            logger.warning(f"HTML fetch error for {url}: {e}")
        return ""

    def _html_to_text(self, html):
        """将 HTML 转换为纯文本"""
        soup = BeautifulSoup(html, 'html.parser')
        for tag in soup(['script', 'style', 'nav', 'footer', 'header']):
            tag.decompose()
        return soup.get_text(separator='\n', strip=True)

    async def _fetch_content_exa(self, url, api_key):
        """Exa contents API 获取页面正文"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://api.exa.ai/contents",
                    headers={
                        "accept": "application/json",
                        "content-type": "application/json",
                        "x-api-key": api_key,
                    },
                    json={"ids": [url], "text": True},
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 200:
                        results = (await resp.json()).get("results", [])
                        if results:
                            return results[0].get("text", "")
                    elif resp.status == 402:
                        logger.warning(f"Exa contents HTTP 402 - API 额度已用完")
                    else:
                        logger.warning(f"Exa contents HTTP {resp.status}")
        except Exception as e:
            logger.warning(f"Exa contents error: {e}")
        return ""

    async def _fetch_content_selenium(self, url):
        """Selenium 获取页面文本（处理 JS 渲染）"""
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._selenium_get_content, url)
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"Selenium content error: {e}")
        return ""

    def _selenium_get_content(self, url):
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC

        options = Options()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')

        driver = webdriver.Chrome(options=options)
        try:
            driver.get(url)
            WebDriverWait(driver, 15).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            return driver.find_element(By.TAG_NAME, "body").text
        finally:
            driver.quit()

    # ================================================================
    #  内容解析
    # ================================================================

    def _parse_advisory_content(self, dsa_id, url, content, html=""):
        """将页面文本解析为安全公告字典"""
        # CVE IDs - 使用清洗函数确保格式正确、去重
        cve_ids = clean_cve_ids(content)

        # 标题：前 10 行中含 DSA/Dell/Security 关键词的行
        lines = [l.strip() for l in content.split('\n') if l.strip()]
        title = lines[0][:200] if lines else dsa_id
        for line in lines[:10]:
            if (15 < len(line) < 300
                    and ('DSA' in line.upper() or 'Dell' in line or 'Security' in line)):
                title = line
                break

        # 发布日期：优先取 Article Properties 中的 Last Modified
        published_date = datetime.now().strftime('%Y-%m-%d')

        # 优先匹配 "Last Modified: 22 May 2021" 等格式
        last_modified_patterns = [
            r'[Ll]ast\s+[Mm]odified\s*[:\s]\s*(\d{1,2}\s+\w+\s+\d{4})',
            r'[Ll]ast\s+[Mm]odified\s*[:\s]\s*(\w+\s+\d{1,2},?\s+\d{4})',
            r'[Ll]ast\s+[Mm]odified\s*[:\s]\s*(\d{4}-\d{2}-\d{2})',
            r'[Ll]ast\s+[Mm]odified\s*[:\s]\s*(\d{1,2}/\d{1,2}/\d{4})',
        ]
        last_modified_fmts = [
            '%d %B %Y', '%d %b %Y',
            '%B %d, %Y', '%B %d %Y', '%b %d, %Y', '%b %d %Y',
            '%Y-%m-%d',
            '%m/%d/%Y',
        ]
        found_date = False
        for pat in last_modified_patterns:
            m = re.search(pat, content)
            if m:
                for fmt in last_modified_fmts:
                    try:
                        published_date = datetime.strptime(m.group(1).strip(), fmt).strftime('%Y-%m-%d')
                        found_date = True
                        break
                    except ValueError:
                        continue
                if found_date:
                    break

        # 回退：全文匹配第一个日期
        if not found_date:
            date_patterns = [
                (r'(\w+ \d{1,2},?\s+\d{4})', ['%B %d, %Y', '%B %d %Y']),
                (r'(\d{4}-\d{2}-\d{2})', ['%Y-%m-%d']),
                (r'(\d{1,2}/\d{1,2}/\d{4})', ['%m/%d/%Y']),
            ]
            for pattern, fmts in date_patterns:
                m = re.search(pattern, content)
                if m:
                    for fmt in fmts:
                        try:
                            published_date = datetime.strptime(m.group(1), fmt).strftime('%Y-%m-%d')
                            found_date = True
                            break
                        except ValueError:
                            continue
                    if found_date:
                        break

        # 最终回退：从 DSA ID 提取年份，避免使用当天日期
        if not found_date:
            dsa_year_m = re.match(r'DSA-(\d{4})-', dsa_id)
            if dsa_year_m:
                published_date = f"{dsa_year_m.group(1)}-01-01"
                logger.debug(f"{dsa_id}: 无法提取日期，使用 DSA 年份回退: {published_date}")

        # Impact / Severity
        impact = self._extract_impact(content, html)

        # Summary: 提取 "Summary" 区域内容
        summary = self._extract_summary_section(content)

        # Products + Solution: 从 "Affected Products & Remediation" 表格提取
        products, solution = self._extract_remediation(content, html)

        return {
            'dell_security_advisory': dsa_id,
            'title': title,
            'cve_ids': cve_ids,
            'published_date': published_date,
            'link': url,
            'summary': summary,
            'description': content[:2000],
            'affected_products': products,
            'solution': solution,
            'impact': impact,
            'severity': impact,
            'source': 'Web Scrape',
        }

    def _extract_summary_section(self, content):
        """从页面 'Summary' 区域提取摘要文本"""
        # 匹配 Summary 标题到下一个区域标题之间的文本
        match = re.search(
            r'\bSummary\b\s*\n(.*?)(?=\n\s*\b(?:Impact|Affected Products|Details|Description|CVSS|Proprietary|Revision History)\b)',
            content, re.IGNORECASE | re.DOTALL
        )
        if match:
            text = ' '.join(match.group(1).split()).strip()
            if text:
                return text[:500]
        # 回退：全文压缩取前 500 字符
        return ' '.join(content.split())[:500]

    def _extract_remediation(self, content, html=""):
        """
        从 'Affected Products & Remediation' 提取产品和解决方案

        优先解析 HTML 表格（Product / Affected Versions / Remediated Versions 列），
        回退到纯文本解析。
        """
        # 1. HTML 表格解析（最可靠）
        if html:
            products, solution = self._parse_remediation_table_html(html)
            if products:
                return products, solution

        # 2. 纯文本解析（Exa / Selenium 内容）
        return self._extract_remediation_from_text(content)

    def _parse_remediation_table_html(self, html):
        """从 HTML 中解析 Affected Products & Remediation 表格"""
        soup = BeautifulSoup(html, 'html.parser')
        products = []
        solution_parts = []

        for table in soup.find_all('table'):
            header_row = table.find('tr')
            if not header_row:
                continue
            headers = [cell.get_text(strip=True).lower()
                       for cell in header_row.find_all(['th', 'td'])]

            # 定位列索引
            prod_idx = next((i for i, h in enumerate(headers) if 'product' in h), None)
            affected_idx = next((i for i, h in enumerate(headers)
                                 if 'affected' in h and 'version' in h), None)
            remediated_idx = next((i for i, h in enumerate(headers)
                                   if 'remediat' in h and 'version' in h), None)

            if prod_idx is None:
                continue

            for row in table.find_all('tr')[1:]:
                cells = [cell.get_text(strip=True) for cell in row.find_all(['td', 'th'])]
                if not cells or len(cells) <= prod_idx:
                    continue

                product = cells[prod_idx]
                affected = cells[affected_idx] if affected_idx is not None and affected_idx < len(cells) else ""
                remediated = cells[remediated_idx] if remediated_idx is not None and remediated_idx < len(cells) else ""

                if product:
                    products.append({
                        'name': product,
                        'model': product,
                        'version_range': affected,
                    })
                    if affected or remediated:
                        solution_parts.append(f"{product}: {affected} -> {remediated}")

            if products:
                break  # 找到目标表格即停

        return products, "\n".join(solution_parts)

    def _extract_remediation_from_text(self, content):
        """从纯文本中提取 Affected Products & Remediation 区域的产品和版本"""
        products = []
        solution_parts = []

        # 定位区域
        section_match = re.search(
            r'Affected Products?\s*(?:&|and)?\s*Remediation\b(.*?)(?=\b(?:Workarounds?|Revision History|Acknowledgment|References|Legal Information|Exploitation)\b|$)',
            content, re.IGNORECASE | re.DOTALL
        )
        if not section_match:
            return self.extract_products_from_text(content), self.extract_solution_from_text(content)

        section = section_match.group(1).strip()
        lines = [l.strip() for l in section.split('\n') if l.strip()]

        # 跳过表头行
        data_start = 0
        for i, line in enumerate(lines):
            if re.search(r'\bProduct\b.*\b(?:Affected|Version)', line, re.IGNORECASE):
                data_start = i + 1
                break

        # 已知 Dell 产品关键词
        product_keywords = [
            'Dell', 'PowerEdge', 'OptiPlex', 'Precision', 'Latitude', 'XPS',
            'Inspiron', 'Vostro', 'Alienware', 'PowerVault', 'iDRAC',
            'PowerStore', 'PowerFlex', 'VxRail', 'Data Domain', 'CloudLink',
            'Avamar', 'PowerProtect', 'Unity', 'PowerSwitch', 'Wyse',
        ]

        current_product = ""
        current_affected = ""
        current_remediated = ""

        for line in lines[data_start:]:
            is_product = any(kw.lower() in line.lower() for kw in product_keywords)
            is_version = bool(re.search(
                r'version|prior|before|through|all\s|^\d+\.\d+', line, re.IGNORECASE
            ))

            if is_product and not is_version:
                # 保存上一个产品
                if current_product:
                    products.append({
                        'name': current_product,
                        'model': current_product,
                        'version_range': current_affected,
                    })
                    if current_affected or current_remediated:
                        solution_parts.append(
                            f"{current_product}: {current_affected} -> {current_remediated}"
                        )
                current_product = line
                current_affected = ""
                current_remediated = ""
            elif is_version and current_product:
                if not current_affected:
                    current_affected = line
                else:
                    current_remediated = line

        # 保存最后一个产品
        if current_product:
            products.append({
                'name': current_product,
                'model': current_product,
                'version_range': current_affected,
            })
            if current_affected or current_remediated:
                solution_parts.append(
                    f"{current_product}: {current_affected} -> {current_remediated}"
                )

        if not products:
            return self.extract_products_from_text(content), self.extract_solution_from_text(content)

        return products, "\n".join(solution_parts)

    def _extract_impact(self, content, html=""):
        """
        从页面内容提取 Impact / Severity 等级

        匹配 Dell 安全公告页面中的多种格式:
          - Impact\\nCritical
          - Impact: High
          - Critical severity
          - Severity: Medium
          - CVSS ... High
          - CVSS 分数转换（9.0-10.0=Critical, 7.0-8.9=High, 4.0-6.9=Medium, 0.1-3.9=Low）
        """
        # 第一轮：直接文本匹配等级关键词
        patterns = [
            r'Impact\s*[\n:]\s*(Critical|High|Medium|Low)',
            r'影响\s*[\n:]\s*(Critical|High|Medium|Low)',
            r'\b(Critical|High|Medium|Low)\b\s+severity',
            r'[Ss]everity\s*[:\s]\s*(Critical|High|Medium|Low)',
            r'CVSS.*?\b(Critical|High|Medium|Low)\b',
            r'[Oo]verall\s+[Ss]everity\s*[:\s]\s*(Critical|High|Medium|Low)',
            r'[Rr]ating\s*[:\s]\s*(Critical|High|Medium|Low)',
        ]
        for pat in patterns:
            m = re.search(pat, content, re.IGNORECASE)
            if m:
                return m.group(1).capitalize()

        # 第二轮：从 HTML 属性/类名中提取（Dell 页面常用 data-severity 等属性）
        if html:
            html_patterns = [
                r'data-severity="(Critical|High|Medium|Low)"',
                r'class="[^"]*\b(critical|high|medium|low)\b[^"]*severity[^"]*"',
                r'class="[^"]*severity[^"]*\b(critical|high|medium|low)\b[^"]*"',
                r'<span[^>]*>\s*(Critical|High|Medium|Low)\s*</span>\s*(?:severity|impact)',
                r'(?:severity|impact)\s*<span[^>]*>\s*(Critical|High|Medium|Low)\s*</span>',
            ]
            for pat in html_patterns:
                m = re.search(pat, html, re.IGNORECASE)
                if m:
                    return m.group(1).capitalize()

        # 第三轮：从 CVSS 分数推断等级
        cvss_patterns = [
            r'CVSS\s*(?:v?\d[\d.]*\s*)?(?:Base\s*)?[Ss]core\s*[:\s]\s*(\d+\.?\d*)',
            r'CVSS\s*[:\s]\s*(\d+\.?\d*)',
            r'[Bb]ase\s*[Ss]core\s*[:\s]\s*(\d+\.?\d*)',
            r'(\d+\.\d+)\s*/\s*10(?:\.0)?',
            r'Score\s*[:\s]\s*(\d+\.?\d*)\s*(?:\(|/|$)',
        ]
        for pat in cvss_patterns:
            m = re.search(pat, content)
            if m:
                try:
                    score = float(m.group(1))
                    if 0.0 < score <= 10.0:
                        return self._cvss_to_severity(score)
                except (ValueError, IndexError):
                    continue

        # 第四轮：从 HTML 中提取 CVSS 分数
        if html:
            for pat in cvss_patterns:
                m = re.search(pat, html)
                if m:
                    try:
                        score = float(m.group(1))
                        if 0.0 < score <= 10.0:
                            return self._cvss_to_severity(score)
                    except (ValueError, IndexError):
                        continue

        return ""

    @staticmethod
    def _cvss_to_severity(score: float) -> str:
        """CVSS 分数转换为严重等级（CVSS v3.x 标准）"""
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score > 0.0:
            return "Low"
        return ""

    def _extract_dsa_id(self, url, text=""):
        """从 URL 或文本中提取 DSA ID"""
        m = re.search(r'(DSA-\d{4}-\d+)', f"{url} {text}", re.IGNORECASE)
        return m.group(1).upper() if m else ""

    # ================================================================
    #  辅助方法
    # ================================================================

    def extract_cve_ids(self, text: str) -> List[str]:
        """提取 CVE ID（使用清洗函数确保格式正确、去重）"""
        return clean_cve_ids(text)

    def extract_products_from_text(self, text: str) -> List[Dict[str, Any]]:
        """从文本中提取产品信息"""
        products = []
        product_keywords = [
            'PowerEdge', 'OptiPlex', 'Precision', 'Latitude', 'XPS',
            'Inspiron', 'Vostro', 'Alienware', 'PowerVault', 'EqualLogic',
        ]
        for keyword in product_keywords:
            if keyword.lower() in text.lower():
                products.append({
                    'name': f'Dell {keyword}',
                    'model': keyword,
                    'version_range': '',
                })
        return products

    def extract_solution_from_text(self, text: str) -> str:
        """从文本中提取解决方案"""
        solution_keywords = ['update', 'patch', 'upgrade', 'fix', 'download']
        for keyword in solution_keywords:
            if keyword.lower() in text.lower():
                sentences = re.split(r'[.!?]', text)
                for sentence in sentences:
                    if keyword.lower() in sentence.lower():
                        return sentence.strip()
        return "Please refer to Dell security advisory for detailed solution."

    def filter_by_days(self, advisories: List[Dict[str, Any]], days: int) -> List[Dict[str, Any]]:
        """根据天数过滤安全公告"""
        cutoff_date = datetime.now() - timedelta(days=days)
        filtered = []
        for advisory in advisories:
            pub_date_str = advisory.get('published_date', '')
            if pub_date_str:
                try:
                    pub_date = datetime.fromisoformat(pub_date_str.replace('Z', '+00:00'))
                    if pub_date >= cutoff_date:
                        filtered.append(advisory)
                except ValueError:
                    filtered.append(advisory)
        return filtered

    async def backfill_missing_dsa_ids(
        self,
        existing_dsa_ids: Set[str],
        year_range: tuple = (2019, 2026),
        log_callback: Callable[[str], None] = None,
    ) -> List[Dict[str, Any]]:
        """
        历史 DSA ID 缝隙补全 - 按年份枚举缺失编号

        Args:
            existing_dsa_ids: 数据库中已有的 DSA ID 集合
            year_range: 年份范围 (start_year, end_year)，默认 2019-2026
            log_callback: 日志回调函数

        Returns:
            成功补全的公告列表
        """
        def log(msg):
            logger.info(msg)
            if log_callback:
                log_callback(msg)

        exa_api_key = os.getenv("EXA_API_KEY")
        start_year, end_year = year_range
        current_year = datetime.now().year

        # 分析每年的缺失编号
        log(f"分析 {start_year}-{end_year} 年的 DSA ID 缺失情况...")
        missing_ids = []
        existing_upper = {d.upper() for d in existing_dsa_ids}

        for year in range(start_year, min(end_year + 1, current_year + 1)):
            year_ids = [d for d in existing_upper if d.startswith(f"DSA-{year}-")]
            if not year_ids:
                log(f"  {year} 年: 无数据，跳过")
                continue

            # 提取已有编号
            year_nums = set()
            for dsa_id in year_ids:
                m = re.match(r'DSA-\d{4}-(\d+)', dsa_id)
                if m:
                    year_nums.add(int(m.group(1)))

            if not year_nums:
                continue

            max_num = max(year_nums)
            # 找出缺失的编号（1 到 max_num 之间）
            full_range = set(range(1, max_num + 1))
            missing_nums = sorted(full_range - year_nums)

            if missing_nums:
                log(f"  {year} 年: 已有 {len(year_nums)} 条，最大编号 {max_num}，缺失 {len(missing_nums)} 条")
                for num in missing_nums:
                    missing_ids.append(f"DSA-{year}-{num:03d}")

        if not missing_ids:
            log("未发现缺失的 DSA ID")
            return []

        log(f"共发现 {len(missing_ids)} 个缺失的 DSA ID，开始补全...")

        # 并发补全缺失的 DSA
        advisories = []
        semaphore = asyncio.Semaphore(5)
        exa_exhausted = False

        async def fetch_missing_one(index, dsa_id):
            nonlocal exa_exhausted
            async with semaphore:
                if exa_exhausted:
                    return None
                try:
                    url = None
                    if exa_api_key:
                        url = await self._search_dsa_via_exa(dsa_id, exa_api_key)

                    if url == "__EXA_402__":
                        if not exa_exhausted:
                            exa_exhausted = True
                            log("⚠️  Exa API 额度耗尽，停止历史缝隙补全（请充值 Exa 额度后重试）")
                        return None

                    if not url:
                        return None

                    log(f"[{index}/{len(missing_ids)}] 补全 {dsa_id}...")
                    advisory = await self._fetch_and_parse_detail(dsa_id, url, exa_api_key)
                    await asyncio.sleep(0.5)

                    if advisory:
                        impact_str = advisory.get('impact') or 'N/A'
                        cve_count = len(advisory.get('cve_ids', []))
                        log(f"  -> {dsa_id} OK — Impact: {impact_str}, CVE: {cve_count}")
                        return advisory
                    else:
                        return None
                except Exception as e:
                    log(f"  -> {dsa_id} 失败: {e}")
                    return None

        tasks = [
            fetch_missing_one(i + 1, dsa_id)
            for i, dsa_id in enumerate(missing_ids)
        ]
        results = await asyncio.gather(*tasks)
        advisories = [advisory for advisory in results if advisory]

        log(f"成功补全 {len(advisories)}/{len(missing_ids)} 条历史公告")
        return advisories

    async def _search_dsa_via_exa(self, dsa_id: str, api_key: str) -> Optional[str]:
        """使用 Exa 搜索单个 DSA ID 的真实 URL

        Returns:
            URL 字符串, "__EXA_402__" 表示额度耗尽, None 表示未找到
        """
        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "query": f"{dsa_id} Dell security advisory",
                    "numResults": 3,
                    "includeDomains": ["dell.com"],
                }
                async with session.post(
                    "https://api.exa.ai/search",
                    headers={
                        "accept": "application/json",
                        "content-type": "application/json",
                        "x-api-key": api_key,
                    },
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        results = (await resp.json()).get("results", [])
                        for r in results:
                            url = r.get("url", "")
                            if dsa_id.lower() in url.lower() or dsa_id.upper() in r.get("title", "").upper():
                                return url
                    elif resp.status == 402:
                        return "__EXA_402__"
        except Exception as e:
            logger.warning(f"Exa search for {dsa_id} failed: {e}")
        return None


    async def requery_published_dates(
        self,
        advisories: list,
        log_callback=None,
    ) -> list:
        """
        重新获取 Dell 安全公告的发布日期。
        对每条记录尝试直接 HTTP 获取页面，提取 Article Properties 中的 Last Modified。
        如果失败则使用 Exa contents API 获取内容再提取。
        最终回退到 DSA ID 年份。

        Args:
            advisories: [{'dsa_id': ..., 'link': ..., 'published_date': ...}, ...]
            log_callback: 日志回调

        Returns:
            [{'dsa_id': ..., 'new_date': ...}, ...] 成功更新的记录
        """
        def _log(msg):
            if log_callback:
                log_callback(msg)
            logger.info(msg)

        exa_key = os.getenv("EXA_API_KEY", "")
        updated = []
        sem = asyncio.Semaphore(3)

        async def _requery_one(dsa_id, link):
            async with sem:
                # 1) 直接 HTTP 获取
                html = await self._fetch_raw_html(link)
                content = self._html_to_text(html) if html else ""

                new_date = self._extract_date_from_content(content, dsa_id)
                if new_date:
                    return new_date

                # 2) Exa contents API
                if exa_key and link:
                    exa_text = await self._fetch_content_exa(link, exa_key)
                    if exa_text:
                        new_date = self._extract_date_from_content(exa_text, dsa_id)
                        if new_date:
                            return new_date

                # 3) DSA 年份回退
                m = re.match(r'DSA-(\d{4})-', dsa_id)
                if m:
                    return f"{m.group(1)}-01-01"
                return None

        total = len(advisories)
        _log(_t("dell_fix_requery_start", total=total))

        for i, adv in enumerate(advisories):
            dsa_id = adv['dsa_id']
            link = adv.get('link', '')
            old_date = adv.get('published_date', '')

            new_date = await _requery_one(dsa_id, link)
            if new_date and new_date != old_date:
                updated.append({'dsa_id': dsa_id, 'new_date': new_date, 'old_date': old_date})

            if (i + 1) % 10 == 0 or i == total - 1:
                _log(_t("dell_fix_progress", done=i+1, total=total, updated=len(updated)))

            await asyncio.sleep(0.5)

        _log(_t("dell_fix_done", count=len(updated)))
        return updated

    def _extract_date_from_content(self, content: str, dsa_id: str) -> str:
        """从内容中提取发布日期，返回 YYYY-MM-DD 或 None"""
        if not content:
            return None

        # 优先匹配 Last Modified
        last_modified_patterns = [
            r'[Ll]ast\s+[Mm]odified\s*[:\s]\s*(\d{1,2}\s+\w+\s+\d{4})',
            r'[Ll]ast\s+[Mm]odified\s*[:\s]\s*(\w+\s+\d{1,2},?\s+\d{4})',
            r'[Ll]ast\s+[Mm]odified\s*[:\s]\s*(\d{4}-\d{2}-\d{2})',
            r'[Ll]ast\s+[Mm]odified\s*[:\s]\s*(\d{1,2}/\d{1,2}/\d{4})',
        ]
        fmts = [
            '%d %B %Y', '%d %b %Y',
            '%B %d, %Y', '%B %d %Y', '%b %d, %Y', '%b %d %Y',
            '%Y-%m-%d', '%m/%d/%Y',
        ]
        for pat in last_modified_patterns:
            m = re.search(pat, content)
            if m:
                for fmt in fmts:
                    try:
                        return datetime.strptime(m.group(1).strip(), fmt).strftime('%Y-%m-%d')
                    except ValueError:
                        continue

        # 回退：全文日期
        date_patterns = [
            (r'(\w+ \d{1,2},?\s+\d{4})', ['%B %d, %Y', '%B %d %Y']),
            (r'(\d{4}-\d{2}-\d{2})', ['%Y-%m-%d']),
        ]
        for pattern, pfmts in date_patterns:
            m = re.search(pattern, content)
            if m:
                for fmt in pfmts:
                    try:
                        d = datetime.strptime(m.group(1), fmt)
                        if d.year < 2026:
                            return d.strftime('%Y-%m-%d')
                    except ValueError:
                        continue
        return None


async def main():
    """测试入口"""
    print("=" * 80)
    print("Dell 安全公告爬取器测试")
    print("=" * 80)

    scraper = DellSecurityScraper()

    print("正在从 Dell 官网获取安全公告...")
    advisories = await scraper.fetch_security_advisories(
        days=30,
        log_callback=lambda msg: print(f"  {msg}"),
    )

    print(f"\n成功获取 {len(advisories)} 条安全公告\n")
    print("=" * 80)

    for i, advisory in enumerate(advisories[:5], 1):
        print(f"\n公告 {i}:")
        print(f"  公告 ID: {advisory.get('dell_security_advisory', 'N/A')}")
        print(f"  标题: {advisory.get('title', 'N/A')}")
        print(f"  Impact: {advisory.get('impact', 'N/A')}")
        print(f"  CVE IDs: {', '.join(advisory.get('cve_ids', []))}")
        print(f"  发布日期: {advisory.get('published_date', 'N/A')}")
        print(f"  链接: {advisory.get('link', 'N/A')}")
        print("-" * 80)

    if advisories:
        from pathlib import Path
        data_dir = Path("cve_data")
        data_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = data_dir / f"dell_advisories_{timestamp}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(advisories, f, ensure_ascii=False, indent=2)
        print(f"\n数据已保存到: {filename}")

    print("\n" + "=" * 80)


if __name__ == "__main__":
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
