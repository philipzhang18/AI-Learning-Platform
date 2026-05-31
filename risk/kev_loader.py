"""
CISA Known Exploited Vulnerabilities Catalog 加载器 (risk/kev_loader.py)

CISA KEV 是美国网络安全机构发布的"已被实际利用的 CVE"清单。
被收录的 CVE 表示有真实攻击证据，风险显著高于"理论上 CVSS 高分但无利用"的 CVE。

来源：https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
本地缓存：cve_data/kev_catalog.json，TTL 7 天

用法
----
    from risk.kev_loader import load_kev_cves
    kev_set = load_kev_cves()
    if "CVE-2021-34527" in kev_set:
        print("This CVE is actively exploited")
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from pathlib import Path
from typing import Set

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
CACHE_FILENAME = "kev_catalog.json"
CACHE_TTL_DAYS = 7
DOWNLOAD_TIMEOUT = 20


def load_kev_cves(
    cache_dir: str = "cve_data",
    force_refresh: bool = False,
) -> Set[str]:
    """
    加载 CISA KEV CVE-ID 集合（本地 7 天缓存）。

    :param cache_dir: 缓存目录（相对路径或绝对路径）
    :param force_refresh: True 时强制重新下载
    :return: CVE-ID 集合，下载失败时返回旧缓存或空集
    """
    cache_path = Path(cache_dir) / CACHE_FILENAME

    # 缓存命中
    if not force_refresh and cache_path.exists():
        age = datetime.now() - datetime.fromtimestamp(cache_path.stat().st_mtime)
        if age < timedelta(days=CACHE_TTL_DAYS):
            cached = _try_read_cache(cache_path)
            if cached is not None:
                return cached

    # 下载新数据
    try:
        req = urllib.request.Request(
            KEV_URL,
            headers={"User-Agent": "Mozilla/5.0 (CVE-Research-Tool)"},
        )
        with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT) as resp:
            raw = resp.read()
        data = json.loads(raw)
        # 写缓存
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_path, "wb") as f:
            f.write(raw)
        return {v["cveID"] for v in data.get("vulnerabilities", []) if "cveID" in v}
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError):
        # 网络失败，回退到旧缓存
        if cache_path.exists():
            cached = _try_read_cache(cache_path)
            if cached is not None:
                return cached
        return set()


def _try_read_cache(path: Path) -> Set[str] | None:
    """尝试从缓存文件读取 KEV 集合，失败返回 None"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {v["cveID"] for v in data.get("vulnerabilities", []) if "cveID" in v}
    except (json.JSONDecodeError, KeyError, OSError):
        return None


def kev_metadata(cache_dir: str = "cve_data") -> dict:
    """返回 KEV 缓存的元数据（用于 GUI 显示状态）"""
    cache_path = Path(cache_dir) / CACHE_FILENAME
    if not cache_path.exists():
        return {"cached": False}
    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {
            "cached": True,
            "title": data.get("title", "CISA KEV Catalog"),
            "catalog_version": data.get("catalogVersion", ""),
            "date_released": data.get("dateReleased", ""),
            "count": data.get("count", len(data.get("vulnerabilities", []))),
            "cache_mtime": datetime.fromtimestamp(cache_path.stat().st_mtime).isoformat(),
        }
    except (json.JSONDecodeError, OSError):
        return {"cached": False}


__all__ = ["load_kev_cves", "kev_metadata"]
