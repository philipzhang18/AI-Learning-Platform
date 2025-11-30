"""
Dell Security Advisory (DSA) 爬虫脚本 - Selenium版本
使用Selenium浏览器自动化工具绕过反爬虫保护

功能：
- 爬取 2023-01-01 至 2025-11-30 期间的 DSA 公告
- 最多获取 100 条最新记录
- 提取：DSA编号、标题、发布日期、链接
- 保存为 CSV 文件

依赖：
- selenium
- webdriver-manager (自动管理ChromeDriver)
"""

import time
import csv
import re
from datetime import datetime
from typing import List, Dict, Optional
import logging

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, NoSuchElementException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    print("⚠️  Selenium未安装，请运行: pip install selenium webdriver-manager")

try:
    from webdriver_manager.chrome import ChromeDriverManager
    WEBDRIVER_MANAGER_AVAILABLE = True
except ImportError:
    WEBDRIVER_MANAGER_AVAILABLE = False
    print("⚠️  webdriver-manager未安装，请运行: pip install webdriver-manager")

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DellDSAScraperSelenium:
    """Dell Security Advisory 爬虫类 - Selenium版本"""

    def __init__(self, headless: bool = True, wait_timeout: int = 30):
        """
        初始化爬虫配置
        
        Args:
            headless: 是否使用无头模式（不显示浏览器窗口）
            wait_timeout: 页面加载等待超时时间（秒）
        """
        if not SELENIUM_AVAILABLE:
            raise ImportError("Selenium未安装，请运行: pip install selenium")
        
        # Dell DSA 页面 URL 模板（按年份）
        self.base_urls = {
            2023: "https://www.dell.com/support/kbdoc/en-us/000177325/dsa-published-in-2023",
            2024: "https://www.dell.com/support/kbdoc/en-us/000177325/dsa-published-in-2024",
            2025: "https://www.dell.com/support/kbdoc/en-us/000177325/dsa-published-in-2025"
        }
        
        # 日期范围
        self.start_date = datetime(2023, 1, 1)
        self.end_date = datetime(2025, 11, 30)
        
        # 最大记录数
        self.max_records = 100
        
        # Selenium配置
        self.headless = headless
        self.wait_timeout = wait_timeout
        self.driver = None

    def setup_driver(self) -> webdriver.Chrome:
        """
        设置Chrome WebDriver
        
        Returns:
            Chrome WebDriver实例
        """
        chrome_options = Options()
        
        if self.headless:
            chrome_options.add_argument('--headless')
            logger.info("使用无头模式（不显示浏览器窗口）")
        
        # 反爬虫规避选项
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-blink-features=AutomationControlled')
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_experimental_option('useAutomationExtension', False)
        
        # 用户代理
        chrome_options.add_argument('user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
        
        # 窗口大小
        chrome_options.add_argument('--window-size=1920,1080')
        
        # 自动管理ChromeDriver
        if WEBDRIVER_MANAGER_AVAILABLE:
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=chrome_options)
        else:
            # 如果没有webdriver-manager，使用系统PATH中的chromedriver
            driver = webdriver.Chrome(options=chrome_options)
        
        # 执行脚本以隐藏webdriver特征
        driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
            'source': '''
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined
                })
            '''
        })
        
        # 设置隐式等待
        driver.implicitly_wait(10)
        
        logger.info("✓ Chrome WebDriver 初始化成功")
        return driver

    def wait_for_page_load(self, timeout: Optional[int] = None):
        """
        等待页面加载完成
        
        Args:
            timeout: 超时时间（秒），默认使用self.wait_timeout
        """
        if timeout is None:
            timeout = self.wait_timeout
        
        try:
            # 等待页面基本元素加载
            WebDriverWait(self.driver, timeout).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # 等待JavaScript执行完成
            WebDriverWait(self.driver, timeout).until(
                lambda driver: driver.execute_script("return document.readyState") == "complete"
            )
            
            # 额外等待一下，确保动态内容加载
            time.sleep(2)
            
        except TimeoutException:
            logger.warning("⚠ 页面加载超时，但继续尝试解析")

    def fetch_page_with_selenium(self, url: str) -> Optional[str]:
        """
        使用Selenium获取网页内容
        
        Args:
            url: 目标URL
            
        Returns:
            HTML内容，失败返回None
        """
        try:
            logger.info(f"正在访问: {url}")
            
            if not self.driver:
                self.driver = self.setup_driver()
            
            self.driver.get(url)
            
            # 等待页面加载
            self.wait_for_page_load()
            
            # 获取页面源码
            html = self.driver.page_source
            
            logger.info(f"✓ 成功获取页面 (页面大小: {len(html)} 字符)")
            return html
            
        except Exception as e:
            logger.error(f"✗ Selenium获取页面失败: {e}")
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
        from bs4 import BeautifulSoup
        
        advisories = []
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # 方法1: 使用Selenium直接查找元素（更可靠）
            if self.driver:
                advisories.extend(self.extract_from_selenium_elements(year))
            
            # 方法2: 使用BeautifulSoup解析HTML
            if not advisories:
                advisories.extend(self.extract_from_beautifulsoup(soup, year))
            
            # 方法3: 在整个页面中搜索DSA模式
            if not advisories:
                page_text = soup.get_text()
                advisories.extend(self.extract_from_text_search(page_text, soup, year))
            
            logger.info(f"从页面解析到 {len(advisories)} 条DSA公告")
            
        except Exception as e:
            logger.error(f"解析HTML失败: {e}")
        
        return advisories

    def extract_from_selenium_elements(self, year: int) -> List[Dict[str, str]]:
        """使用Selenium直接查找页面元素"""
        advisories = []
        
        try:
            # 查找包含DSA编号的链接
            links = self.driver.find_elements(By.TAG_NAME, "a")
            
            for link in links:
                try:
                    href = link.get_attribute('href') or ''
                    text = link.text or ''
                    full_text = f"{href} {text}"
                    
                    # 查找DSA编号
                    dsa_match = re.search(r'DSA-(\d{4})-(\d{3})', full_text, re.IGNORECASE)
                    if dsa_match:
                        dsa_id = dsa_match.group(0).upper()
                        dsa_year = int(dsa_match.group(1))
                        
                        if dsa_year == year:
                            advisory = {
                                'dsa_number': dsa_id,
                                'title': text.strip() or f"Dell Security Advisory {dsa_id}",
                                'publication_date': self.extract_date_from_text(full_text),
                                'link': href if href.startswith('http') else f"https://www.dell.com{href}"
                            }
                            advisories.append(advisory)
                except Exception:
                    continue
            
            # 查找表格
            try:
                tables = self.driver.find_elements(By.TAG_NAME, "table")
                for table in tables:
                    rows = table.find_elements(By.TAG_NAME, "tr")
                    for row in rows[1:]:  # 跳过表头
                        try:
                            cells = row.find_elements(By.TAG_NAME, "td")
                            if len(cells) >= 2:
                                row_text = ' '.join([cell.text for cell in cells])
                                advisory = self.extract_from_row_text(row_text, row, year)
                                if advisory:
                                    advisories.append(advisory)
                        except Exception:
                            continue
            except Exception:
                pass
            
        except Exception as e:
            logger.debug(f"Selenium元素提取失败: {e}")
        
        return advisories

    def extract_from_beautifulsoup(self, soup, year: int) -> List[Dict[str, str]]:
        """使用BeautifulSoup解析HTML"""
        advisories = []
        
        # 查找表格
        tables = soup.find_all('table')
        for table in tables:
            rows = table.find_all('tr')
            for row in rows[1:]:
                cells = row.find_all(['td', 'th'])
                if len(cells) >= 2:
                    text = ' '.join([cell.get_text(strip=True) for cell in cells])
                    advisory = self.extract_from_row_text(text, row, year)
                    if advisory:
                        advisories.append(advisory)
        
        # 查找链接
        links = soup.find_all('a', href=True)
        for link in links:
            href = link.get('href', '')
            text = link.get_text(strip=True)
            full_text = f"{href} {text}"
            
            dsa_match = re.search(r'DSA-(\d{4})-(\d{3})', full_text, re.IGNORECASE)
            if dsa_match:
                dsa_id = dsa_match.group(0).upper()
                dsa_year = int(dsa_match.group(1))
                
                if dsa_year == year:
                    advisory = {
                        'dsa_number': dsa_id,
                        'title': text or f"Dell Security Advisory {dsa_id}",
                        'publication_date': self.extract_date_from_text(full_text),
                        'link': href if href.startswith('http') else f"https://www.dell.com{href}"
                    }
                    advisories.append(advisory)
        
        return advisories

    def extract_from_text_search(self, page_text: str, soup, year: int) -> List[Dict[str, str]]:
        """在整个页面文本中搜索DSA模式"""
        advisories = []
        seen_dsas = set()
        
        dsa_pattern = re.compile(r'DSA-(\d{4})-(\d{3})', re.IGNORECASE)
        matches = dsa_pattern.finditer(page_text)
        
        for match in matches:
            dsa_id = match.group(0).upper()
            dsa_year = int(match.group(1))
            
            if dsa_year == year and dsa_id not in seen_dsas:
                seen_dsas.add(dsa_id)
                
                # 获取上下文
                start = max(0, match.start() - 200)
                end = min(len(page_text), match.end() + 200)
                context = page_text[start:end]
                
                # 查找链接
                link = self.find_dsa_link_in_soup(soup, dsa_id)
                
                advisory = {
                    'dsa_number': dsa_id,
                    'title': self.extract_title_from_context(context, dsa_id),
                    'publication_date': self.extract_date_from_text(context),
                    'link': link
                }
                advisories.append(advisory)
        
        return advisories

    def extract_from_row_text(self, text: str, row_element, year: int) -> Optional[Dict[str, str]]:
        """从表格行文本中提取DSA信息"""
        dsa_match = re.search(r'DSA-(\d{4})-(\d{3})', text, re.IGNORECASE)
        if not dsa_match:
            return None
        
        dsa_id = dsa_match.group(0).upper()
        dsa_year = int(dsa_match.group(1))
        
        if dsa_year != year:
            return None
        
        # 提取链接
        link = ""
        try:
            if hasattr(row_element, 'find'):
                link_tag = row_element.find('a', href=True)
                if link_tag:
                    link = link_tag.get('href', '') if hasattr(link_tag, 'get') else ''
                    if link and not link.startswith('http'):
                        link = f"https://www.dell.com{link}"
        except Exception:
            pass
        
        # 提取标题
        title = text.split('\n')[0].strip()[:200] if text else f"Dell Security Advisory {dsa_id}"
        
        return {
            'dsa_number': dsa_id,
            'title': title,
            'publication_date': self.extract_date_from_text(text),
            'link': link
        }

    def find_dsa_link_in_soup(self, soup, dsa_id: str) -> str:
        """在BeautifulSoup对象中查找DSA链接"""
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

    def extract_title_from_context(self, context: str, dsa_id: str) -> str:
        """从上下文中提取标题"""
        lines = context.split('\n')
        for line in lines:
            if dsa_id.upper() in line.upper() and len(line.strip()) > 10:
                title = re.sub(r'\s+', ' ', line.strip())
                return title[:200]
        return f"Dell Security Advisory {dsa_id}"

    def extract_date_from_text(self, text: str) -> str:
        """从文本中提取日期"""
        date_patterns = [
            (r'(\d{4})-(\d{2})-(\d{2})', '%Y-%m-%d'),
            (r'(\d{2})/(\d{2})/(\d{4})', '%m/%d/%Y'),
            (r'(\d{4})/(\d{2})/(\d{2})', '%Y/%m/%d'),
            (r'(\d{1,2})\s+(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{4})', '%d %B %Y'),
            (r'(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{1,2}),\s+(\d{4})', '%B %d, %Y'),
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
        
        return ""

    def filter_by_date_range(self, advisories: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """根据日期范围过滤公告"""
        filtered = []
        
        for advisory in advisories:
            pub_date_str = advisory.get('publication_date', '')
            if not pub_date_str:
                dsa_id = advisory.get('dsa_number', '')
                year_match = re.search(r'DSA-(\d{4})', dsa_id)
                if year_match:
                    year = int(year_match.group(1))
                    pub_date_str = f"{year}-06-15"
                    advisory['publication_date'] = pub_date_str
            
            if pub_date_str:
                try:
                    pub_date = datetime.strptime(pub_date_str, '%Y-%m-%d')
                    if self.start_date <= pub_date <= self.end_date:
                        filtered.append(advisory)
                except ValueError:
                    filtered.append(advisory)
            else:
                filtered.append(advisory)
        
        return filtered

    def scrape_all_dsas(self) -> List[Dict[str, str]]:
        """爬取所有年份的DSA公告"""
        all_advisories = []
        
        try:
            # 初始化WebDriver
            if not self.driver:
                self.driver = self.setup_driver()
            
            # 按年份从新到旧爬取
            for year in sorted(self.base_urls.keys(), reverse=True):
                if len(all_advisories) >= self.max_records:
                    logger.info(f"已达到最大记录数限制 ({self.max_records})，停止爬取")
                    break
                
                url = self.base_urls[year]
                logger.info(f"\n{'='*60}")
                logger.info(f"开始爬取 {year} 年的DSA公告")
                logger.info(f"{'='*60}")
                
                html = self.fetch_page_with_selenium(url)
                if html:
                    advisories = self.parse_dsa_from_html(html, year)
                    all_advisories.extend(advisories)
                    logger.info(f"{year}年共获取 {len(advisories)} 条公告")
                else:
                    logger.warning(f"无法获取 {year} 年的页面内容")
                
                # 请求延迟
                if year != min(self.base_urls.keys()):
                    time.sleep(2)
            
        finally:
            # 关闭浏览器
            if self.driver:
                self.driver.quit()
                logger.info("✓ 浏览器已关闭")
        
        # 去重
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
        
        # 按日期排序
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
        """保存数据到CSV文件"""
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
    print("Dell Security Advisory (DSA) 爬虫 - Selenium版本")
    print("=" * 80)
    print(f"时间范围: 2023-01-01 至 2025-11-30")
    print(f"最大记录数: 100")
    print("=" * 80)
    print()
    
    if not SELENIUM_AVAILABLE:
        print("❌ 错误: Selenium未安装")
        print("请运行: pip install selenium webdriver-manager")
        return
    
    # 创建爬虫实例（headless=True表示无头模式，不显示浏览器窗口）
    scraper = DellDSAScraperSelenium(headless=True, wait_timeout=30)
    
    try:
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
            print("\n⚠️  未获取到数据")
            print("可能的原因：")
            print("   1. 网站结构已改变")
            print("   2. 需要更长的等待时间")
            print("   3. 尝试设置 headless=False 查看浏览器行为")
        
        # 保存到CSV
        if advisories:
            scraper.save_to_csv(advisories)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  用户中断")
    except Exception as e:
        logger.error(f"发生错误: {e}", exc_info=True)
    finally:
        if scraper.driver:
            scraper.driver.quit()
    
    print("\n" + "=" * 80)
    print("完成！")
    print("=" * 80)


if __name__ == "__main__":
    main()

