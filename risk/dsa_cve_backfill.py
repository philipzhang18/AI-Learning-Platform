"""
DSA-CVE 反查率提升工具 (risk/dsa_cve_backfill.py)

诊断与可选回填本地 cves 表中缺失的、被 DSA 引用的 CVE。

为什么需要
----------
当前命中率 48.3%（10567 / 21894）。缺口集中在 2014-2023 年，每年缺失 ~1000-2000 条。
缺失原因：本地 NVD 抓取按时间窗拉取，未针对 DSA 引用的 CVE 反向回填。

影响
----
- 微码评分 severity_score 因 NVD CVSS 反查失败，回退到 DSA severity 文本（精度降低）
- 反向查询返回的 DSA 关联 CVE 详情不完整

用法
----
    # 仅诊断（默认）
    python -m risk.dsa_cve_backfill

    # 输出缺失列表到文件
    python -m risk.dsa_cve_backfill --dump cve_data/missing_cves.txt

    # 实际拉取（需 NVD API Key 提速；不带 key 也能跑但限速 5 req/30s）
    python -m risk.dsa_cve_backfill --fetch --limit 200 --api-key YOUR_KEY
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
import time
import urllib.request
import urllib.error
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Set

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"


def diagnose(db_path: str) -> dict:
    """诊断 DSA-CVE 反查率，返回缺失统计"""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT cve_ids FROM dell_advisories WHERE cve_ids IS NOT NULL")
    all_dsa_cves: Set[str] = set()
    for (s,) in cur.fetchall():
        if s:
            for c in re.split(r"[,\s]+", s.strip()):
                if c.startswith("CVE-"):
                    all_dsa_cves.add(c)

    cur.execute("SELECT cve_id FROM cves")
    cves_in_db: Set[str] = {r[0] for r in cur.fetchall()}
    conn.close()

    missing = all_dsa_cves - cves_in_db
    year_counts: Counter = Counter()
    for c in missing:
        m = re.match(r"CVE-(\d{4})-", c)
        if m:
            year_counts[int(m.group(1))] += 1

    return {
        "total_dsa_cves": len(all_dsa_cves),
        "in_local_db": len(all_dsa_cves & cves_in_db),
        "missing": missing,
        "missing_count": len(missing),
        "year_dist": dict(sorted(year_counts.items())),
    }


def fetch_one(cve_id: str, api_key: str | None = None, timeout: int = 15):
    """从 NVD API 拉取单条 CVE，返回 dict 或 None"""
    url = NVD_API.format(cve_id=cve_id)
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "Mozilla/5.0 (CVE-Research-Tool)")
    if api_key:
        req.add_header("apiKey", api_key)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        items = data.get("vulnerabilities", [])
        if not items:
            return None
        return items[0]["cve"]
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError):
        return None


def backfill(db_path: str, missing: Iterable[str], limit: int,
             api_key: str | None) -> dict:
    """
    将缺失 CVE 从 NVD 拉取并写入 cves 表。
    NVD 限流：无 key 5 req/30s（每 6 秒一次）；有 key 50 req/30s（每 0.6 秒）。
    """
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    interval = 0.7 if api_key else 6.5
    inserted = 0
    failed = 0
    rows = list(missing)[:limit]
    for i, cve_id in enumerate(rows, 1):
        item = fetch_one(cve_id, api_key)
        if item is None:
            failed += 1
        else:
            try:
                cvss = _extract_cvss(item)
                severity = _extract_severity(item)
                published = item.get("published", "")
                description = _extract_description(item)
                cur.execute(
                    """INSERT OR IGNORE INTO cves
                    (cve_id, cvss_score, severity, published_date, description, data)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                    (cve_id, cvss, severity, published, description,
                     json.dumps(item, ensure_ascii=False)),
                )
                conn.commit()
                inserted += 1
            except sqlite3.Error as e:
                print(f"  [DB ERROR] {cve_id}: {e}", file=sys.stderr)
                failed += 1
        if i % 10 == 0:
            print(f"  Progress: {i}/{len(rows)} (inserted={inserted}, "
                  f"failed={failed})")
        time.sleep(interval)
    conn.close()
    return {"inserted": inserted, "failed": failed, "attempted": len(rows)}


def _extract_cvss(cve: dict) -> float:
    """从 NVD 嵌套结构提取最高 CVSS 分数"""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key, [])
        if items:
            try:
                return float(items[0]["cvssData"]["baseScore"])
            except (KeyError, ValueError, TypeError):
                continue
    return 0.0


def _extract_severity(cve: dict) -> str:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        items = metrics.get(key, [])
        if items:
            try:
                return items[0]["cvssData"].get("baseSeverity", "")
            except (KeyError, TypeError):
                continue
    return ""


def _extract_description(cve: dict) -> str:
    descs = cve.get("descriptions", [])
    for d in descs:
        if d.get("lang") == "en":
            return d.get("value", "")
    return descs[0].get("value", "") if descs else ""


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", default="cve_data/cve_database.db")
    parser.add_argument("--dump", help="将缺失 CVE 列表写入文件")
    parser.add_argument("--fetch", action="store_true",
                        help="实际从 NVD API 拉取并回填（默认仅诊断）")
    parser.add_argument("--limit", type=int, default=100,
                        help="单次回填最多 N 条（默认 100）")
    parser.add_argument("--api-key", help="NVD API Key（可选，提速 10 倍）")
    args = parser.parse_args()

    if not Path(args.db).exists():
        print(f"[ERROR] Database not found: {args.db}", file=sys.stderr)
        return 1

    diag = diagnose(args.db)
    pct = diag["in_local_db"] / diag["total_dsa_cves"] * 100
    print(f"DSA 引用 CVE 总数: {diag['total_dsa_cves']}")
    print(f"本地 cves 表已有: {diag['in_local_db']} ({pct:.1f}%)")
    print(f"缺失: {diag['missing_count']}")
    print()
    print("按年份分布:")
    for year, cnt in diag["year_dist"].items():
        bar = "█" * min(40, cnt // 50)
        print(f"  CVE-{year}: {cnt:>5} {bar}")

    if args.dump:
        with open(args.dump, "w", encoding="utf-8") as f:
            for cve in sorted(diag["missing"]):
                f.write(cve + "\n")
        print(f"\n缺失列表已写入: {args.dump}")

    if args.fetch:
        print(f"\n开始从 NVD 拉取（limit={args.limit}, "
              f"间隔={'0.7' if args.api_key else '6.5'}s）...")
        # 优先回填年份较新的（影响面更大）
        sorted_missing = sorted(diag["missing"], reverse=True)
        result = backfill(args.db, sorted_missing, args.limit, args.api_key)
        print(f"\n完成: 成功 {result['inserted']}, 失败 {result['failed']}, "
              f"尝试 {result['attempted']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
