"""
Dell DSA 数据加载共享工具 (risk/_dsa_base.py)

三个 DSA 预测器（产品线 / 版本 / 微码）共用的低层解析逻辑。
不强制统一字段集——子类各自决定 record 包含哪些键，但共用：

- 日期解析（多格式回退）
- CVE-ID 列表解析
- DSA `data` JSON 解析（容错）
- cves.cvss_score 反查表加载
- 严重度文本 → CVSS 兜底映射

设计原则
--------
- **薄工具层**：仅提供函数，不强制类继承
- **零依赖外部**：所有逻辑可被单元测试独立验证
- **现状无副作用**：替换三个 _load_dsa_records 时只改实现，不改调用方
"""
from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


# Dell DSA severity 文本 → CVSS 数值兜底映射（原微码模块定义）
SEVERITY_TO_CVSS: Dict[str, float] = {
    "CRITICAL": 9.5,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "MODERATE": 5.0,
    "LOW": 3.0,
}

_DATE_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d",
    "%d %B %Y",
    "%B %d, %Y",
)

_CVE_TOKEN = re.compile(r"CVE-\d{4}-\d+")


def parse_date(raw: str) -> Optional[datetime]:
    """多格式回退解析；任意一种成功即返回，全部失败返回 None"""
    if not raw:
        return None
    raw = raw.strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(raw[: len(fmt) + 4], fmt)
        except (ValueError, TypeError):
            continue
    # ISO 8601 with timezone offset
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).replace(tzinfo=None)
    except (ValueError, AttributeError):
        return None


def parse_cve_ids(s: Optional[str]) -> List[str]:
    """从逗号/空白分隔的字符串中提取所有规范 CVE-ID"""
    if not s:
        return []
    return _CVE_TOKEN.findall(s)


def parse_advisory_data(data_str: Optional[str]) -> Dict[str, Any]:
    """
    解析 dell_advisories.data JSON。失败返回空 dict（不抛异常）。

    返回 {} 而非 None，方便链式 .get() 访问。
    """
    if not data_str:
        return {}
    try:
        d = json.loads(data_str)
        return d if isinstance(d, dict) else {}
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}


def affected_text_of(advisory_data: Dict[str, Any], include_version_range: bool = True) -> str:
    """
    把 affected_products 里的 name/model/version_range 拼接成单一文本，
    供产品线分类器与版本提取器使用。
    """
    ap = advisory_data.get("affected_products") or []
    parts: List[str] = []
    for p in ap:
        if not isinstance(p, dict):
            continue
        name = p.get("name", "")
        model = p.get("model", "")
        chunk = f"{name} {model}"
        if include_version_range:
            chunk += " " + (p.get("version_range") or "")
        parts.append(chunk)
    return " ".join(parts)


def severity_text_of(advisory_data: Dict[str, Any]) -> str:
    """规范化 severity 文本（大写、去前后空白）"""
    return (advisory_data.get("severity") or "").upper().strip()


def load_cve_score_map(db_path: str) -> Dict[str, float]:
    """
    从 cves 表一次性加载 cve_id → cvss_score 映射。

    优先用 data.cvss_score（双源修复后命中 100%），未命中的 cve_id 不进 map。
    """
    score_map: Dict[str, float] = {}
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT cve_id, data FROM cves")
        for cve_id, data_str in cur.fetchall():
            if not data_str:
                continue
            try:
                d = json.loads(data_str)
                s = d.get("cvss_score")
                if s is not None:
                    score_map[cve_id] = float(s)
            except (json.JSONDecodeError, TypeError, ValueError):
                continue
    finally:
        conn.close()
    return score_map


def fetch_advisory_rows(db_path: str) -> List[Tuple[str, str, str, str]]:
    """SELECT title, cve_ids, published_date, data FROM dell_advisories"""
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT title, cve_ids, published_date, data FROM dell_advisories")
        return cur.fetchall()
    finally:
        conn.close()


def resolve_cvss(
    cve_ids: List[str],
    cve_score_map: Dict[str, float],
    severity_text: str,
) -> Tuple[float, str]:
    """
    双源 CVSS 解析：
    1. 优先取 cve_ids 在 cve_score_map 中的最大分（"nvd"）
    2. 兜底用 severity_text 映射（"severity_fallback"）
    3. 都没有返回 (0.0, "none")
    """
    hit_scores = [cve_score_map[c] for c in cve_ids if c in cve_score_map]
    if hit_scores:
        return max(hit_scores), "nvd"
    fallback = SEVERITY_TO_CVSS.get(severity_text, 0.0)
    if fallback > 0:
        return fallback, "severity_fallback"
    return 0.0, "none"


__all__ = [
    "SEVERITY_TO_CVSS",
    "parse_date",
    "parse_cve_ids",
    "parse_advisory_data",
    "affected_text_of",
    "severity_text_of",
    "load_cve_score_map",
    "fetch_advisory_rows",
    "resolve_cvss",
]
