"""提取的纯逻辑函数（无 GUI 依赖）用于测试"""
import re
from datetime import datetime


def extract_products_from_dell_title(title: str) -> list:
    """从 Dell 安全公告标题中提取受影响产品名称"""
    if not title:
        return []
    products = []
    pattern_a = r'Security Update for\s+(.+?)\s+(?:for|Multiple|Vulnerabilit)'
    match = re.search(pattern_a, title, re.IGNORECASE)
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
    pattern_b = r'^(.+?)\s+Security Update'
    match = re.search(pattern_b, title, re.IGNORECASE)
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
    if 'Dell' in title:
        for keyword in [' for ', ' Security', ' Multiple']:
            if keyword in title:
                product_text = title.split(keyword)[0].strip()
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
