"""
Dell Security Advisory (DSA) 爬虫脚本
从 Dell 官方网站爬取安全公告信息（DSA）

功能：
- 爬取 2023-01-01 至 2025-11-30 期间的 DSA 公告
- 最多获取 100 条最新记录
- 提取：DSA编号、标题、发布日期、链接
- 保存为 CSV 文件

注意：
- 如果 Dell 网站使用 JavaScript 动态加载内容，可能需要使用 Selenium
- 请遵守网站的 robots.txt 和使用条款
"""

import requests
from bs4 import BeautifulSoup
import re
import time
import csv
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DellDSAScraper:
    """Dell Security Advisory 爬虫类"""

    def __init__(self):
        """初始化爬虫配置"""
        # Dell DSA 页面 URL 模板（按年份）
        self.base_urls = {
            2023: "https://www.dell.com/support/kbdoc/en-us/000177325/dsa-published-in-2023",
            2024: "https://www.dell.com/support/kbdoc/en-us/000177325/dsa-published-in-2024",
            2025: "https://www.dell.com/support/kbdoc/en-us/000177325/dsa-published-in-2025"
        }
        
        # 请求头（模拟浏览器）- 更完整的头部信息
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
            'Referer': 'https://www.dell.com/',
        }
        
        # 请求延迟（秒）- 避免被封禁
        self.request_delay = 2
        
        # 日期范围
        self.start_date = datetime(2023, 1, 1)
        self.end_date = datetime(2025, 11, 30)
        
        # 最大记录数
        self.max_records = 100

    def fetch_page(self, url: str) -> Optional[str]:
        """
        获取网页内容
        
        Args:
            url: 目标URL
            
        Returns:
            HTML内容，失败返回None
        """
        try:
            logger.info(f"正在访问: {url}")
            
            # 使用Session以保持cookies
            session = requests.Session()
            session.headers.update(self.headers)
            
            response = session.get(url, timeout=30, allow_redirects=True)
            
            # 检查是否是403错误（反爬虫）
            if response.status_code == 403:
                logger.warning("⚠ 收到403错误 - Dell网站可能启用了反爬虫保护")
                logger.warning("⚠ 建议：")
                logger.warning("   1. 检查是否需要使用Selenium等浏览器自动化工具")
                logger.warning("   2. 尝试添加更多请求头（如Referer）")
                logger.warning("   3. 使用代理服务器")
                logger.warning("   4. 手动访问页面确认是否需要登录或验证")
                
                # 保存错误页面用于调试
                with open("dell_403_error.html", "w", encoding="utf-8") as f:
                    f.write(response.text)
                logger.warning("   错误页面已保存到: dell_403_error.html")
                return None
            
            response.raise_for_status()
            
            # 检查响应编码
            if response.encoding is None or response.encoding.lower() == 'iso-8859-1':
                response.encoding = 'utf-8'
            
            logger.info(f"✓ 成功获取页面 (状态码: {response.status_code})")
            return response.text
            
        except requests.exceptions.HTTPError as e:
            status_code = getattr(response, 'status_code', 'N/A') if 'response' in locals() else 'N/A'
            logger.error(f"✗ HTTP错误: {e} (状态码: {status_code})")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"✗ 请求失败: {e}")
            return None

    def parse_dsa_from_html(self, html: str, year: int) -> List[Dict[str, str]]:
        """
        从HTML中解析DSA信息
        
        Args:
            html: HTML内容
            year: 年份（用于验证DSA编号）
            
        Returns:
            DSA公告列表
        """
        advisories = []
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # 方法1: 查找表格（table）
            tables = soup.find_all('table')
            if tables:
                logger.info(f"找到 {len(tables)} 个表格")
                for table in tables:
                    rows = table.find_all('tr')
                    for row in rows[1:]:  # 跳过表头
                        advisory = self.extract_from_table_row(row, year)
                        if advisory:
                            advisories.append(advisory)
            
            # 方法2: 查找列表（ul/ol）
            if not advisories:
                lists = soup.find_all(['ul', 'ol'])
                logger.info(f"查找列表元素，找到 {len(lists)} 个")
                for list_elem in lists:
                    items = list_elem.find_all('li')
                    for item in items:
                        advisory = self.extract_from_list_item(item, year)
                        if advisory:
                            advisories.append(advisory)
            
            # 方法3: 查找包含DSA编号的链接
            if not advisories:
                logger.info("尝试从链接中提取DSA信息")
                links = soup.find_all('a', href=True)
                for link in links:
                    advisory = self.extract_from_link(link, year)
                    if advisory:
                        advisories.append(advisory)
            
            # 方法4: 在整个页面中搜索DSA模式
            if not advisories:
                logger.info("在整个页面中搜索DSA模式")
                page_text = soup.get_text()
                dsa_pattern = re.compile(r'DSA-(\d{4})-(\d{3})', re.IGNORECASE)
                matches = dsa_pattern.finditer(page_text)
                
                seen_dsas = set()
                for match in matches:
                    dsa_id = match.group(0).upper()
                    if dsa_id not in seen_dsas:
                        seen_dsas.add(dsa_id)
                        # 尝试找到包含此DSA的上下文
                        start = max(0, match.start() - 200)
                        end = min(len(page_text), match.end() + 200)
                        context = page_text[start:end]
                        
                        advisory = {
                            'dsa_number': dsa_id,
                            'title': self.extract_title_from_context(context, dsa_id),
                            'publication_date': self.extract_date_from_context(context),
                            'link': self.find_dsa_link(soup, dsa_id)
                        }
                        if advisory['title']:
                            advisories.append(advisory)
            
            logger.info(f"从页面解析到 {len(advisories)} 条DSA公告")
            
        except Exception as e:
            logger.error(f"解析HTML失败: {e}")
        
        return advisories

    def extract_from_table_row(self, row, year: int) -> Optional[Dict[str, str]]:
        """从表格行中提取DSA信息"""
        try:
            cells = row.find_all(['td', 'th'])
            if len(cells) < 2:
                return None
            
            # 获取所有文本
            text = ' '.join([cell.get_text(strip=True) for cell in cells])
            
            # 提取DSA编号
            dsa_match = re.search(r'DSA-(\d{4})-(\d{3})', text, re.IGNORECASE)
            if not dsa_match:
                return None
            
            dsa_id = dsa_match.group(0).upper()
            dsa_year = int(dsa_match.group(1))
            
            # 验证年份
            if dsa_year != year:
                return None
            
            # 提取链接
            link_tag = row.find('a', href=True)
            link = ""
            if link_tag:
                link = link_tag['href']
                if link and not link.startswith('http'):
                    link = f"https://www.dell.com{link}"
            
            # 提取标题（通常是第一列或链接文本）
            title = ""
            if link_tag:
                title = link_tag.get_text(strip=True)
            if not title and cells:
                title = cells[0].get_text(strip=True)
            
            # 提取日期
            pub_date = self.extract_date_from_text(text)
            
            return {
                'dsa_number': dsa_id,
                'title': title or f"Dell Security Advisory {dsa_id}",
                'publication_date': pub_date,
                'link': link
            }
            
        except Exception as e:
            logger.debug(f"提取表格行数据失败: {e}")
            return None

    def extract_from_list_item(self, item, year: int) -> Optional[Dict[str, str]]:
        """从列表项中提取DSA信息"""
        try:
            text = item.get_text(strip=True)
            
            # 查找DSA编号
            dsa_match = re.search(r'DSA-(\d{4})-(\d{3})', text, re.IGNORECASE)
            if not dsa_match:
                return None
            
            dsa_id = dsa_match.group(0).upper()
            dsa_year = int(dsa_match.group(1))
            
            if dsa_year != year:
                return None
            
            # 查找链接
            link_tag = item.find('a', href=True)
            link = ""
            if link_tag:
                link = link_tag['href']
                if link and not link.startswith('http'):
                    link = f"https://www.dell.com{link}"
            
            # 提取标题
            title = text
            if link_tag:
                link_text = link_tag.get_text(strip=True)
                if link_text:
                    title = link_text
            
            # 提取日期
            pub_date = self.extract_date_from_text(text)
            
            return {
                'dsa_number': dsa_id,
                'title': title or f"Dell Security Advisory {dsa_id}",
                'publication_date': pub_date,
                'link': link
            }
            
        except Exception:
            return None

    def extract_from_link(self, link, year: int) -> Optional[Dict[str, str]]:
        """从链接中提取DSA信息"""
        try:
            href = str(link.get('href', '')) if hasattr(link, 'get') else ''
            text = link.get_text(strip=True) if hasattr(link, 'get_text') else ''
            
            # 检查链接或文本中是否包含DSA编号
            search_text = str(href) + ' ' + str(text)
            dsa_match = re.search(r'DSA-(\d{4})-(\d{3})', search_text, re.IGNORECASE)
            if not dsa_match:
                return None
            
            dsa_id = dsa_match.group(0).upper()
            dsa_year = int(dsa_match.group(1))
            
            if dsa_year != year:
                return None
            
            # 构建完整链接
            full_link = str(href)
            if full_link and not full_link.startswith('http'):
                full_link = f"https://www.dell.com{full_link}"
            
            # 提取日期
            pub_date = self.extract_date_from_text(str(text) + ' ' + str(href))
            
            return {
                'dsa_number': dsa_id,
                'title': str(text) or f"Dell Security Advisory {dsa_id}",
                'publication_date': pub_date,
                'link': full_link
            }
            
        except Exception:
            return None

    def extract_title_from_context(self, context: str, dsa_id: str) -> str:
        """从上下文中提取标题"""
        # 尝试找到标题模式
        lines = context.split('\n')
        for line in lines:
            if dsa_id.upper() in line.upper() and len(line.strip()) > 10:
                # 清理标题
                title = re.sub(r'\s+', ' ', line.strip())
                return title[:200]  # 限制长度
        return f"Dell Security Advisory {dsa_id}"

    def extract_date_from_context(self, context: str) -> str:
        """从上下文中提取日期"""
        return self.extract_date_from_text(context)

    def find_dsa_link(self, soup: BeautifulSoup, dsa_id: str) -> str:
        """查找DSA相关的链接"""
        links = soup.find_all('a', href=True)
        for link in links:
            href = link.get('href', '')
            text = link.get_text(strip=True)
            if dsa_id.upper() in (href + ' ' + text).upper():
                full_link = href
                if full_link and not full_link.startswith('http'):
                    full_link = f"https://www.dell.com{full_link}"
                return full_link
        return ""

    def extract_date_from_text(self, text: str) -> str:
        """
        从文本中提取日期
        
        支持多种日期格式：
        - YYYY-MM-DD
        - MM/DD/YYYY
        - Month DD, YYYY
        - DD Month YYYY
        """
        # 日期模式
        date_patterns = [
            (r'(\d{4})-(\d{2})-(\d{2})', '%Y-%m-%d'),  # 2024-01-15
            (r'(\d{2})/(\d{2})/(\d{4})', '%m/%d/%Y'),  # 01/15/2024
            (r'(\d{4})/(\d{2})/(\d{2})', '%Y/%m/%d'),  # 2024/01/15
            (r'(\d{1,2})\s+(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{4})', '%d %B %Y'),  # 15 January 2024
            (r'(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{1,2}),\s+(\d{4})', '%B %d, %Y'),  # January 15, 2024
        ]
        
        for pattern, date_format in date_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                try:
                    date_str = match.group(0)
                    date_obj = datetime.strptime(date_str, date_format)
                    return date_obj.strftime('%Y-%m-%d')
                except ValueError:
                    continue
        
        # 如果找不到日期，返回空字符串
        return ""

    def filter_by_date_range(self, advisories: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """根据日期范围过滤公告"""
        filtered = []
        
        for advisory in advisories:
            pub_date_str = advisory.get('publication_date', '')
            if not pub_date_str:
                # 如果没有日期，尝试从DSA编号中推断年份
                dsa_id = advisory.get('dsa_number', '')
                year_match = re.search(r'DSA-(\d{4})', dsa_id)
                if year_match:
                    year = int(year_match.group(1))
                    # 假设是年中日期
                    pub_date_str = f"{year}-06-15"
                    advisory['publication_date'] = pub_date_str
            
            if pub_date_str:
                try:
                    pub_date = datetime.strptime(pub_date_str, '%Y-%m-%d')
                    if self.start_date <= pub_date <= self.end_date:
                        filtered.append(advisory)
                except ValueError:
                    # 日期格式错误，保留该记录
                    filtered.append(advisory)
            else:
                # 没有日期，保留该记录
                filtered.append(advisory)
        
        return filtered

    def scrape_all_dsas(self) -> List[Dict[str, str]]:
        """
        爬取所有年份的DSA公告
        
        Returns:
            所有符合条件的DSA公告列表
        """
        all_advisories = []
        
        # 按年份从新到旧爬取（2025 -> 2024 -> 2023）
        for year in sorted(self.base_urls.keys(), reverse=True):
            if len(all_advisories) >= self.max_records:
                logger.info(f"已达到最大记录数限制 ({self.max_records})，停止爬取")
                break
            
            url = self.base_urls[year]
            logger.info(f"\n{'='*60}")
            logger.info(f"开始爬取 {year} 年的DSA公告")
            logger.info(f"{'='*60}")
            
            html = self.fetch_page(url)
            if html:
                advisories = self.parse_dsa_from_html(html, year)
                all_advisories.extend(advisories)
                logger.info(f"{year}年共获取 {len(advisories)} 条公告")
            else:
                logger.warning(f"无法获取 {year} 年的页面内容")
            
            # 请求延迟
            if year != min(self.base_urls.keys()):  # 最后一年不需要延迟
                time.sleep(self.request_delay)
        
        # 去重（基于DSA编号）
        seen = set()
        unique_advisories = []
        for advisory in all_advisories:
            dsa_id = advisory.get('dsa_number', '')
            if dsa_id and dsa_id not in seen:
                seen.add(dsa_id)
                unique_advisories.append(advisory)
        
        logger.info(f"\n去重前: {len(all_advisories)} 条，去重后: {len(unique_advisories)} 条")
        
        # 按日期过滤
        filtered_advisories = self.filter_by_date_range(unique_advisories)
        logger.info(f"日期过滤后: {len(filtered_advisories)} 条")
        
        # 按日期排序（最新的在前）
        filtered_advisories.sort(
            key=lambda x: x.get('publication_date', ''),
            reverse=True
        )
        
        # 限制数量
        if len(filtered_advisories) > self.max_records:
            filtered_advisories = filtered_advisories[:self.max_records]
            logger.info(f"限制为最多 {self.max_records} 条记录")
        
        return filtered_advisories

    def save_to_csv(self, advisories: List[Dict[str, str]], filename: str = "dell_dsa_advisories.csv"):
        """
        保存数据到CSV文件
        
        Args:
            advisories: DSA公告列表
            filename: 输出文件名
        """
        if not advisories:
            logger.warning("没有数据可保存")
            return
        
        try:
            with open(filename, 'w', newline='', encoding='utf-8-sig') as f:
                fieldnames = ['dsa_number', 'title', 'publication_date', 'link']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                
                writer.writeheader()
                for advisory in advisories:
                    writer.writerow({
                        'dsa_number': advisory.get('dsa_number', ''),
                        'title': advisory.get('title', ''),
                        'publication_date': advisory.get('publication_date', ''),
                        'link': advisory.get('link', '')
                    })
            
            logger.info(f"✓ 成功保存 {len(advisories)} 条记录到 {filename}")
            
        except Exception as e:
            logger.error(f"✗ 保存CSV文件失败: {e}")


def main():
    """主函数"""
    print("=" * 80)
    print("Dell Security Advisory (DSA) 爬虫")
    print("=" * 80)
    print(f"时间范围: 2023-01-01 至 2025-11-30")
    print(f"最大记录数: 100")
    print("=" * 80)
    print()
    print("⚠️  注意: 如果遇到403错误，Dell网站可能启用了反爬虫保护")
    print("   此时可能需要使用Selenium等浏览器自动化工具")
    print("=" * 80)
    print()
    
    scraper = DellDSAScraper()
    
    # 开始爬取
    advisories = scraper.scrape_all_dsas()
    
    # 显示结果摘要
    print("\n" + "=" * 80)
    print("爬取结果摘要")
    print("=" * 80)
    print(f"总共获取: {len(advisories)} 条DSA公告")
    
    if advisories:
        print("\n前5条记录预览:")
        for i, advisory in enumerate(advisories[:5], 1):
            print(f"\n{i}. {advisory.get('dsa_number', 'N/A')}")
            print(f"   标题: {advisory.get('title', 'N/A')[:60]}...")
            print(f"   日期: {advisory.get('publication_date', 'N/A')}")
            print(f"   链接: {advisory.get('link', 'N/A')[:60]}...")
    else:
        print("\n⚠️  未获取到数据，可能的原因：")
        print("   1. Dell网站启用了反爬虫保护（403错误）")
        print("   2. 网站结构已改变")
        print("   3. 网站使用JavaScript动态加载内容")
        print("\n建议：")
        print("   - 检查错误日志")
        print("   - 手动访问Dell DSA页面确认结构")
        print("   - 考虑使用Selenium等浏览器自动化工具")
        print("   - 查看DELL_DSA_SCRAPER_README.md获取更多帮助")
    
    # 保存到CSV
    if advisories:
        scraper.save_to_csv(advisories)
    
    print("\n" + "=" * 80)
    print("完成！")
    print("=" * 80)


if __name__ == "__main__":
    main()

