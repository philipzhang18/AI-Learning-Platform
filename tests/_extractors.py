"""提取的纯逻辑函数（无 GUI 依赖）用于测试"""
import re
from datetime import datetime


def extract_products_from_dell_title(title: str) -> list:
    """从 Dell 安全公告标题中提取受影响产品名称（增强版）"""
    if not title:
        return []

    # 先去除 DSA ID 前缀（如果有）
    title_clean = re.sub(r'^DSA-\d{4}-\d+:\s*', '', title, flags=re.IGNORECASE)

    products = []

    # 新增规则 1: Dell EMC [产品] [漏洞类型]（支持括号）
    pattern_1 = r'^(Dell EMC [A-Za-z0-9\s\(\)]+?)\s+(?:Improper|Buffer|Hard|Unauthorized|Plaintext|OS Command|Open Redirect|XML|Reflected|Deserialization|Java RMI|Cross-Site|Denial of Service|Intel|Tar File)'
    match = re.search(pattern_1, title_clean, re.IGNORECASE)
    if match:
        product_text = match.group(1).strip()
        products.append({'name': product_text, 'model': product_text, 'version_range': ''})
        return products

    # 新增规则 2: Dell [产品] [漏洞类型]
    pattern_2 = r'^(Dell [A-Za-z0-9\s]+?)\s+(?:Improper|Buffer|Hard|Unauthorized|Plaintext|OS Command|Open Redirect|XML|Reflected|Deserialization|Configuration|Authentication)'
    match = re.search(pattern_2, title_clean, re.IGNORECASE)
    if match:
        product_text = match.group(1).strip()
        products.append({'name': product_text, 'model': product_text, 'version_range': ''})
        return products

    # 模式A: "Security Update for [产品名] for/Multiple..."
    pattern_a = r'Security Update for\s+(.+?)\s+(?:for|Multiple|Vulnerabilit)'
    match = re.search(pattern_a, title_clean, re.IGNORECASE)
    if match:
        product_text = match.group(1).strip()
        if ' and ' in product_text:
            for p in product_text.split(' and '):
                p = p.strip()
                if p:
                    products.append({'name': p, 'model': p, 'version_range': ''})
        else:
            products.append({'name': product_text, 'model': product_text, 'version_range': ''})
        return products

    # 模式B: "[产品1], [产品2], ... Security Update"
    pattern_b = r'^(.+?)\s+Security Update'
    match = re.search(pattern_b, title_clean, re.IGNORECASE)
    if match:
        product_text = match.group(1).strip()
        if ',' in product_text:
            for p in product_text.split(','):
                p = p.strip()
                if p and len(p) > 3:
                    products.append({'name': p, 'model': p, 'version_range': ''})
            return products
        else:
            products.append({'name': product_text, 'model': product_text, 'version_range': ''})
            return products

    # 新增规则 3: Security Update [Dell产品] [漏洞类型]
    pattern_3 = r'Security Update\s+(Dell\s+[A-Za-z0-9\s]+?)\s+(?:Vulnerabilit|Plaintext|Buffer)'
    match = re.search(pattern_3, title_clean, re.IGNORECASE)
    if match:
        product_text = match.group(1).strip()
        products.append({'name': product_text, 'model': product_text, 'version_range': ''})
        return products

    # 新增规则 4: Security Update for an/the [产品] Advisory
    pattern_4 = r'Security Update for (?:an|the)\s+(.+?)\s+Advisory'
    match = re.search(pattern_4, title_clean, re.IGNORECASE)
    if match:
        product_text = match.group(1).strip()
        products.append({'name': product_text, 'model': product_text, 'version_range': ''})
        return products

    # 回退：如果标题中包含 "Dell" 关键词
    if 'Dell' in title_clean:
        for keyword in [' for ', ' Security', ' Multiple']:
            if keyword in title_clean:
                product_text = title_clean.split(keyword)[0].strip()
                if product_text:
                    products.append({'name': product_text, 'model': product_text, 'version_range': ''})
                    return products
    return []


def is_invalid_product_name(name: str) -> bool:
    """判断产品名称是否无效"""
    if not name or len(name) < 2:
        return True
    if name in ("如标题", "详见公告", "NA", "N/A"):
        return True
    invalid_keywords = [
        "Provide Feedback", "提供反馈", "Summary:", "Link to",
        "Customers can", "The following", "Multiple components",
        "Affected products:", "Registered Dell", "[Dell Vulnerability",
        "Product Security Information", "This article applies",
        "View More View Less",
    ]
    for keyword in invalid_keywords:
        if keyword in name:
            return True
    if len(name) > 150:
        return True
    return False


def parse_dell_date(date_str: str) -> str:
    """解析Dell日期格式 (例如: OCT 29 2025) 为ISO格式"""
    if not date_str:
        return datetime.now().isoformat()
    try:
        months = {
            'JAN': 1, 'FEB': 2, 'MAR': 3, 'APR': 4,
            'MAY': 5, 'JUN': 6, 'JUL': 7, 'AUG': 8,
            'SEP': 9, 'OCT': 10, 'NOV': 11, 'DEC': 12
        }
        parts = date_str.split()
        if len(parts) == 3:
            month_str, day_str, year_str = parts
            month = months.get(month_str.upper(), 1)
            day = int(day_str)
            year = int(year_str)
            dt = datetime(year, month, day)
            return dt.isoformat()
    except (ValueError, KeyError, IndexError) as e:
        # 记录具体异常类型，便于调试
        pass
    return datetime.now().isoformat()


def extract_dsa_id_from_url(url: str) -> str:
    """从URL中提取DSA ID"""
    if not url:
        return ""
    match = re.search(r'dsa[-_](\d{4}[-_]\d+)', url, re.IGNORECASE)
    if match:
        return "DSA-" + match.group(1).replace('_', '-')
    match = re.search(r'/(\d{9})', url)
    if match:
        return f"KB-{match.group(1)}"
    return ""
