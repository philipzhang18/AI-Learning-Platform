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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DellSecurityScraper:
    """Dell 安全公告爬取器 — Exa API / HTTP / Selenium 多策略"""

    def __init__(self):
        self.base_url = "https://www.dell.com/support/security/en-us/"
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
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

        # ── Step 3: 逐个抓取详情页 ──
        advisories = []
        for i, (dsa_id, url) in enumerate(new_links.items()):
            try:
                log(f"[{i + 1}/{len(new_links)}] 正在抓取 {dsa_id}...")
                advisory = await self._fetch_and_parse_detail(dsa_id, url, exa_api_key)
                if advisory:
                    advisories.append(advisory)
                    impact_str = advisory.get('impact') or 'N/A'
                    cve_count = len(advisory.get('cve_ids', []))
                    log(f"  -> {dsa_id} — Impact: {impact_str}, CVE: {cve_count}")
                else:
                    log(f"  -> {dsa_id} — 无法解析页面内容")
                # 请求间隔
                await asyncio.sleep(1.5)
            except Exception as e:
                log(f"  -> {dsa_id} 抓取失败: {e}")

        log(f"成功抓取 {len(advisories)} 条新安全公告")
        return advisories

    # ================================================================
    #  发现公告链接
    # ================================================================

    async def _discover_advisory_links(self, days, exa_api_key, log):
        """依次尝试 Exa 搜索 / HTTP 列表页 / Selenium 发现 DSA 链接"""
        links = {}

        # 策略 1: Exa 搜索 API
        if exa_api_key:
            log("策略 1: 使用 Exa 搜索 API 发现公告...")
            links = await self._discover_via_exa_search(days, exa_api_key)
            if links:
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

        return self._parse_advisory_content(dsa_id, url, text, html)

    async def _fetch_raw_html(self, url):
        """HTTP 请求获取原始 HTML（用于解析表格结构）"""
        try:
            async with aiohttp.ClientSession(headers=self.headers) as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 200:
                        return await resp.text()
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
        # CVE IDs
        cve_ids = list(set(
            c.upper() for c in re.findall(r'CVE-\d{4}-\d{4,7}', content, re.IGNORECASE)
        ))

        # 标题：前 10 行中含 DSA/Dell/Security 关键词的行
        lines = [l.strip() for l in content.split('\n') if l.strip()]
        title = lines[0][:200] if lines else dsa_id
        for line in lines[:10]:
            if (15 < len(line) < 300
                    and ('DSA' in line.upper() or 'Dell' in line or 'Security' in line)):
                title = line
                break

        # 发布日期（仅日期，不含时分）
        published_date = datetime.now().strftime('%Y-%m-%d')
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
                        break
                    except ValueError:
                        continue
                break

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
        """提取 CVE ID"""
        return list(set(re.findall(r'CVE-\d{4}-\d{4,7}', text.upper())))

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
