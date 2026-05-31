"""
版本信息提取器 (risk/version_extractor.py)

从 Dell DSA 数据中提取产品版本信息，支持：
- 产品名清洗（过滤噪声条目）
- 产品名与版本号分离
- 版本范围解析（prior to / and earlier）
- 多种版本格式识别
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class VersionInfo:
    """版本信息数据类"""
    product_line: str       # 产品线（如 "PowerEdge (服务器)"）
    product_name: str       # 清洗后的产品名（如 "Dell ObjectScale"）
    version_type: str       # 版本类型（SOFTWARE/HARDWARE/FIRMWARE/UNKNOWN）
    version_string: str     # 原始版本字符串（如 "OneFS 8.1.2.0"）
    version_number: str     # 规范化版本号（如 "8.1.2.0"）
    version_qualifier: str  # 版本限定符（""/"<"/"<="）
    confidence: float       # 置信度 [0.0, 1.0]

    @property
    def display_name(self) -> str:
        """UI 显示用名称：产品名 + 版本号"""
        qualifier = self.version_qualifier
        if qualifier:
            return f"{self.product_name} {qualifier} {self.version_number}"
        return f"{self.product_name} {self.version_number}"

    def __hash__(self):
        return hash((self.product_line, self.product_name, self.version_number))

    def __eq__(self, other):
        if not isinstance(other, VersionInfo):
            return False
        return (self.product_line == other.product_line and
                self.product_name == other.product_name and
                self.version_number == other.version_number)


# ────────────────────────────────────────────────────────────────────────────
# 产品名清洗规则
# ────────────────────────────────────────────────────────────────────────────

# 噪声关键词：包含这些词的 name/model 条目直接丢弃
_NOISE_KEYWORDS = [
    "summary:", "article type", "find answers", "#####",
    "remediation", "visit community", "link to remed",
    "customers can", "the following", "dell security advisories",
    "security update for", "vulnerability response",
    "cvss scoring", "for more details", "refer to",
    "dell technologies recommends", "dell recommends",
    "dell emc recommends", "multiple components within",
    "insertion of sensitive", "information into log",
]

# 版本限定符模式：从产品名中分离出版本范围
_VERSION_QUALIFIER_PATTERNS = [
    (re.compile(r'^(.+?)\s+prior\s+to\s+v?(\d+\.\d+(?:\.\d+)*)', re.I), "<"),
    (re.compile(r'^(.+?)\s+(?:and\s+)?earlier\s+(?:than\s+)?v?(\d+\.\d+(?:\.\d+)*)', re.I), "<="),
    (re.compile(r'^(.+?)\s+before\s+(?:version\s+)?v?(\d+\.\d+(?:\.\d+)*)', re.I), "<"),
    (re.compile(r'^(.+?)\s+v?(\d+\.\d+(?:\.\d+)*)\s+and\s+(?:earlier|prior)', re.I), "<="),
]

# 通用产品名前缀（不是真产品名，而是描述性短语）
_GENERIC_NAME_PATTERNS = [
    re.compile(r'^firmware\s+versions?', re.I),
    re.compile(r'^software\s+versions?', re.I),
    re.compile(r'^products?\s+versions?', re.I),
    re.compile(r'^version[s]?$', re.I),
]

# 从产品名中分离版本号的模式
_PRODUCT_VERSION_SPLIT = re.compile(
    r'^(.*?(?:Dell\s+(?:EMC\s+)?)?[A-Za-z]+(?:\s+[A-Za-z]+)*)\s+'
    r'v?(\d+\.\d+(?:\.\d+)*(?:\.\d+)?(?:\s*P\d+)?)\s*$',
    re.I
)


def is_noise_entry(text: str) -> bool:
    """判断是否为噪声条目（非产品名）"""
    if not text or len(text.strip()) < 4:
        return True
    t = text.lower().strip()
    if t.startswith(('*', '-', '#', '[', 'http')):
        return True
    if any(kw in t for kw in _NOISE_KEYWORDS):
        return True
    # 纯数字开头 + 非产品描述
    if re.match(r'^\d+\.\d+.*(?:insertion|vulnerability|update|security)', t, re.I):
        return True
    return False


def is_generic_name(name: str) -> bool:
    """判断产品名是否为通用描述（如 'Firmware versions'）"""
    if not name:
        return True
    text = name.strip().lower()
    # 不包含 Dell/EMC/任何已知产品线关键词 → 视为通用名
    if not re.search(r'\b(dell|emc|isilon|onefs|unity|vnx|powerstore|powermax|'
                     r'poweredge|powerprotect|powerflex|powerscale|vxrail|'
                     r'recoverpoint|networker|avamar|data\s+domain|ddos|'
                     r'objectscale|ecs|vplex|cloudiq|idrac|openmanage|'
                     r'compellent|xtremio|connectrix|networking|geosynchrony)\b',
                     text):
        return True
    for p in _GENERIC_NAME_PATTERNS:
        if p.match(text):
            return True
    return False


def matches_product_line(product_name: str, product_line: str) -> bool:
    """
    检查清洗后的产品名是否真的属于指定产品线。
    用于过滤跨产品线串扰（一条 DSA 影响多产品线时）。
    """
    from risk.dsa_prediction import _COMPILED_PATTERNS
    patterns = _COMPILED_PATTERNS.get(product_line, [])
    return any(p.search(product_name) for p in patterns)


def clean_product_name(raw_name: str) -> Tuple[str, str, str]:
    """
    清洗产品名，分离出产品名、版本号、限定符

    :param raw_name: 原始 name/model 字段
    :return: (clean_product_name, version_number, qualifier)
             qualifier: ""/"<"/"<="

    示例:
        "Dell ObjectScale prior to 4.1.0.3"
            → ("Dell ObjectScale", "4.1.0.3", "<")
        "Dell EMC Isilon OneFS 8.1.2.0"
            → ("Dell EMC Isilon OneFS", "8.1.2.0", "")
        "PowerEdge R640 BIOS 2.10.0"
            → ("PowerEdge R640", "2.10.0", "")
    """
    if not raw_name:
        return ("", "", "")

    text = raw_name.strip()

    # 去除常见的描述性前缀
    text = re.sub(r'^(?:Security\s+)?Update(?:\s+for)?\s+', '', text, flags=re.I)
    text = re.sub(r'^Affected\s+(?:product|version)s?:\s*', '', text, flags=re.I)

    # 先尝试匹配版本限定符模式
    for pattern, qualifier in _VERSION_QUALIFIER_PATTERNS:
        m = pattern.match(text)
        if m:
            product = m.group(1).strip()
            version = m.group(2).strip()
            return (product, version, qualifier)

    # 尝试分离产品名 + 版本号
    m = _PRODUCT_VERSION_SPLIT.match(text)
    if m:
        product = m.group(1).strip()
        version = m.group(2).strip()
        # 过滤掉过短的产品名（可能是误匹配）
        if len(product) >= 3:
            return (product, version, "")

    # 无版本号，原样返回
    return (text, "", "")


# ────────────────────────────────────────────────────────────────────────────
# 产品名规范化（用于聚合相似产品）
# ────────────────────────────────────────────────────────────────────────────

# 产品名规范化映射：将不同写法统一
_PRODUCT_NAME_NORMALIZE = [
    # (匹配模式, 规范化名称)
    (re.compile(r'Dell\s+EMC\s+Isilon\s+OneFS', re.I), "Dell EMC Isilon OneFS"),
    (re.compile(r'Dell\s+EMC\s+IsilonSD\s+Edge', re.I), "Dell EMC IsilonSD Edge"),
    (re.compile(r'Dell\s+EMC\s+PowerScale\s+OneFS', re.I), "Dell EMC PowerScale OneFS"),
    (re.compile(r'Dell\s+EMC\s+Unity(?:\s+XT)?', re.I), "Dell EMC Unity"),
    (re.compile(r'Dell\s+EMC\s+UnityVSA', re.I), "Dell EMC UnityVSA"),
    (re.compile(r'Dell\s+EMC\s+VNX2?', re.I), "Dell EMC VNX2"),
    (re.compile(r'Dell\s+EMC\s+VPLEX(?:\s+(?:Software|GeoSynchrony))?', re.I), "Dell EMC VPLEX"),
    (re.compile(r'Dell\s+EMC\s+Data\s+Domain', re.I), "Dell EMC Data Domain"),
    (re.compile(r'Dell\s+EMC\s+Avamar', re.I), "Dell EMC Avamar"),
    (re.compile(r'Dell\s+EMC\s+NetWorker', re.I), "Dell EMC NetWorker"),
    (re.compile(r'Dell\s+EMC\s+RecoverPoint', re.I), "Dell EMC RecoverPoint"),
    (re.compile(r'Dell\s+EMC\s+PowerStore', re.I), "Dell EMC PowerStore"),
    (re.compile(r'Dell\s+EMC\s+PowerMax', re.I), "Dell EMC PowerMax"),
    (re.compile(r'Dell\s+EMC\s+PowerProtect', re.I), "Dell EMC PowerProtect"),
    (re.compile(r'Dell\s+EMC\s+PowerFlex', re.I), "Dell EMC PowerFlex"),
    (re.compile(r'Dell\s+EMC\s+VxRail', re.I), "Dell EMC VxRail"),
    (re.compile(r'Dell\s+EMC\s+ECS', re.I), "Dell EMC ECS"),
    (re.compile(r'Dell\s+ObjectScale', re.I), "Dell ObjectScale"),
    (re.compile(r'Dell\s+PowerEdge', re.I), "Dell PowerEdge"),
    (re.compile(r'Dell\s+iDRAC', re.I), "Dell iDRAC"),
    (re.compile(r'Dell\s+OpenManage', re.I), "Dell OpenManage"),
    (re.compile(r'Dell\s+Networking', re.I), "Dell Networking"),
    (re.compile(r'Dell\s+CloudIQ', re.I), "Dell CloudIQ"),
    (re.compile(r'Dell\s+Connectrix', re.I), "Dell Connectrix"),
]


def normalize_product_name(name: str) -> str:
    """规范化产品名，便于聚合"""
    if not name:
        return ""
    text = name.strip()
    for pattern, canonical in _PRODUCT_NAME_NORMALIZE:
        if pattern.search(text):
            return canonical
    # 未匹配则返回去除前缀后的原始名
    text = re.sub(r'^\*\s+', '', text)  # 去除列表标记
    text = re.sub(r'^-\s+', '', text)
    return text[:60]  # 限制长度


# ────────────────────────────────────────────────────────────────────────────
# 版本提取正则模式（用于无结构化产品名时的兜底匹配）
# ────────────────────────────────────────────────────────────────────────────

VERSION_PATTERNS = [
    (r'OneFS\s+v?(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)', 'SOFTWARE', 0.95),
    (r'BIOS\s+(?:version\s+)?v?(\d+\.\d+(?:\.\d+)?)', 'SOFTWARE', 0.95),
    (r'(?:Firmware|FW)\s+(?:version\s+)?v?(\d+\.\d+(?:\.\d+)?)', 'FIRMWARE', 0.90),
    (r'iDRAC\s+(\d+)', 'HARDWARE', 0.95),
    (r'VxRail\s+v?(\d+\.\d+(?:\.\d+)?)', 'SOFTWARE', 0.95),
    (r'PowerStore\s+v?(\d+\.\d+(?:\.\d+)?)', 'SOFTWARE', 0.95),
    (r'PowerMax\s+v?(\d+\.\d+(?:\.\d+)?)', 'SOFTWARE', 0.95),
    (r'PowerProtect\s+(?:DP|DD)?\s*v?(\d+\.\d+(?:\.\d+)?)', 'SOFTWARE', 0.90),
    (r'NetWorker\s+v?(\d+\.\d+(?:\.\d+)?)', 'SOFTWARE', 0.90),
    (r'Avamar\s+v?(\d+\.\d+(?:\.\d+)?)', 'SOFTWARE', 0.90),
    (r'RecoverPoint\s+v?(\d+\.\d+(?:\.\d+)?)', 'SOFTWARE', 0.90),
    (r'CloudIQ\s+v?(\d+\.\d+(?:\.\d+)?)', 'SOFTWARE', 0.90),
    (r'GeoSynchrony\s+v?(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)', 'SOFTWARE', 0.90),
    (r'ObjectScale\s+v?(\d+\.\d+(?:\.\d+)?)', 'SOFTWARE', 0.95),
    (r'Operating\s+Environment\s+\(OE\)\s+v?(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)', 'SOFTWARE', 0.90),
    (r'\bOE\s+v?(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)', 'SOFTWARE', 0.85),
    (r'(?:version|ver|v)\s+(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)', 'SOFTWARE', 0.70),
    (r'PowerEdge\s+([A-Z]\d{3,4})', 'HARDWARE', 0.90),
    (r'\b(R\d{3,4}|T\d{3,4}|M\d{3,4}|C\d{3,4})\b', 'HARDWARE', 0.85),
]

_COMPILED_VERSION_PATTERNS = [
    (re.compile(pattern, re.IGNORECASE), vtype, conf)
    for pattern, vtype, conf in VERSION_PATTERNS
]


def infer_version_type(product_name: str, version_string: str) -> str:
    """根据产品名和版本字符串推断版本类型"""
    text = f"{product_name} {version_string}".lower()
    if "bios" in text:
        return "SOFTWARE"
    if "firmware" in text or " fw " in text:
        return "FIRMWARE"
    if "idrac" in text:
        return "HARDWARE"
    if re.search(r'\b(r|t|m|c)\d{3,4}\b', text, re.I) and "poweredge" in text:
        return "HARDWARE"
    return "SOFTWARE"


def _product_line_to_name(product_line: str) -> str:
    """从产品线 key 推断默认产品名"""
    name = product_line.split("(")[0].strip()
    name = name.split("/")[0].strip()
    if not name.lower().startswith("dell"):
        name = f"Dell {name}"
    return name


def extract_version_from_product_entry(
    raw_name: str,
    product_line: str
) -> Optional[VersionInfo]:
    """
    从单条 affected_products 条目中提取版本信息

    返回 None 的情况：
    - 噪声条目（Summary、Article Type 等）
    - 通用名（"Firmware versions" 等）
    - 无版本号
    - 产品名与产品线不匹配（防止跨产品线串扰）
    """
    if is_noise_entry(raw_name):
        return None

    product_name, version_number, qualifier = clean_product_name(raw_name)
    if not version_number:
        return None

    # 过滤通用名（如 "Firmware versions prior to version"）
    if is_generic_name(product_name):
        return None

    canonical_name = normalize_product_name(product_name)
    if not canonical_name or len(canonical_name) < 3:
        return None

    # 关键：清洗后的产品名必须真的匹配该产品线，否则丢弃（防止串扰）
    if not matches_product_line(canonical_name, product_line):
        return None

    version_type = infer_version_type(canonical_name, version_number)

    return VersionInfo(
        product_line=product_line,
        product_name=canonical_name,
        version_type=version_type,
        version_string=raw_name.strip()[:80],
        version_number=version_number,
        version_qualifier=qualifier,
        confidence=0.95,
    )


def extract_versions_from_text(text: str, product_line: str) -> List[VersionInfo]:
    """
    从纯文本（如 DSA title）中提取版本信息（兜底方法）

    只接受高置信度（≥0.90）的产品特定模式，避免泛化的 "version X.Y" 误匹配。
    """
    if not text or is_noise_entry(text):
        return []

    versions = []
    seen = set()
    canonical = _product_line_to_name(product_line)

    for pattern, vtype, confidence in _COMPILED_VERSION_PATTERNS:
        # 兜底只接受高置信度模式，避免 "version 1.4" 这类误匹配
        if confidence < 0.90:
            continue
        for match in pattern.finditer(text):
            version_num = match.group(1) if match.lastindex else match.group(0)
            version_str = match.group(0)

            key = (product_line, version_num)
            if key in seen:
                continue
            seen.add(key)

            # 兜底也要做产品线匹配验证
            if not matches_product_line(canonical, product_line):
                continue

            versions.append(VersionInfo(
                product_line=product_line,
                product_name=canonical,
                version_type=vtype,
                version_string=version_str,
                version_number=version_num,
                version_qualifier="",
                confidence=confidence
            ))

    return versions


def extract_versions_from_dsa(
    title: str,
    affected_products: List[dict],
    product_lines: List[str]
) -> List[VersionInfo]:
    """
    从 DSA 记录中提取版本信息

    优先级：
    1. affected_products 结构化字段（最高优先级）
    2. title 文本兜底（仅在 affected_products 无版本时使用）
    """
    all_versions: List[VersionInfo] = []

    for prod in affected_products:
        if not isinstance(prod, dict):
            continue
        for field_name in ('name', 'model'):
            raw = prod.get(field_name, '')
            if not raw:
                continue
            for line in product_lines:
                v = extract_version_from_product_entry(raw, line)
                if v:
                    all_versions.append(v)

    if not all_versions and title:
        for line in product_lines:
            all_versions.extend(extract_versions_from_text(title, line))

    unique_versions = {}
    for v in all_versions:
        key = (v.product_line, v.product_name, v.version_number)
        if key not in unique_versions or v.confidence > unique_versions[key].confidence:
            unique_versions[key] = v

    return list(unique_versions.values())


def normalize_version_key(version_info: VersionInfo) -> str:
    """
    生成版本的规范化 key（用于分组聚合）

    格式：{产品线}::{产品名}::{版本号}
    示例：ECS / ObjectScale (对象存储)::Dell ObjectScale::4.1.0.3
    """
    return f"{version_info.product_line}::{version_info.product_name}::{version_info.version_number}"


def parse_version_key(key: str) -> Tuple[str, str, str]:
    """
    解析版本 key

    :return: (产品线, 产品名, 版本号)
    """
    parts = key.split("::")
    if len(parts) != 3:
        return ("UNKNOWN", "UNKNOWN", "UNKNOWN")
    return (parts[0], parts[1], parts[2])


__all__ = [
    "VersionInfo",
    "is_noise_entry",
    "clean_product_name",
    "normalize_product_name",
    "extract_version_from_product_entry",
    "extract_versions_from_text",
    "extract_versions_from_dsa",
    "normalize_version_key",
    "parse_version_key",
]
