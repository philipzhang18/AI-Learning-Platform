"""
Dell 微码级 DSA 风险评估原型 (risk/dsa_prediction_microcode.py)

针对 BIOS / Firmware / iDRAC / OS / 软件的版本×机型粒度，
输出**相对暴露分**（exposure_score），不输出绝对概率。

为什么不用 Poisson？
--------------------
微码级单 key 历史 DSA 通常只有 1–3 条，月度计数高度零膨胀，
VMR 几乎一定 ≫ 1.5，泊松假设失效；强行套绝对概率会大幅失真。
本原型聚焦在"哪些 (机型, 微码版本) 组合最值得运维优先关注"
这一更实用的相对排序问题。

四元组 key
----------
    product_line :: model :: firmware_type :: version
    例: "PowerEdge (服务器) :: R640 :: BIOS :: 2.10.0"

`<` / `<=` 范围展开
--------------------
DSA 描述常见 "BIOS prior to 2.11.0"，本模块在已知版本集合内做保守展开：
该公告会同时计入所有满足 version < 2.11.0 的同机型同类型 key。
没有外部全量版本清单时，"已知版本"= 数据库其他 DSA 里出现过的版本号。

exposure_score (0~100) 公式
----------------------------
    exposure_score
        = 50 × normalize(affected_dsa_count, by_line)         # 历史频次
        + 25 × (avg_cvss / 10)                                # 严重度
        + 25 × recency_factor                                 # 时效
    recency_factor = clip(1 - months_since_last/24, 0, 1)
"""
from __future__ import annotations

import json
import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from risk.dsa_prediction import classify_dsa, _COMPILED_PATTERNS
from risk._dsa_base import parse_date as _shared_parse_date

# DSA 没有 CVSS 数值字段时，按 severity 文本兜底为典型分数
_SEVERITY_TO_CVSS = {
    "CRITICAL": 9.5,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 3.0,
}

# ────────────────────────────────────────────────────────────────────────────
# 机型与微码类型识别
# ────────────────────────────────────────────────────────────────────────────

# 机型正则：覆盖 PowerEdge / Precision / Latitude / iDRAC 等常见命名
_MODEL_PATTERNS: List[re.Pattern] = [
    re.compile(r"\b(MX\d{3,4}[a-z]?)\b", re.I),       # MX740c
    re.compile(r"\b(XE\d{3,4})\b", re.I),             # XE9680
    re.compile(r"\b(XR\d{4})\b", re.I),               # XR4000
    re.compile(r"\b(R\d{3,4}[a-z]{0,3})\b", re.I),    # R640, R740xd
    re.compile(r"\b(T\d{2,4})\b", re.I),              # T40, T640
    re.compile(r"\b(M\d{3,4})\b", re.I),              # M640 blade
    re.compile(r"\b(C\d{3,4})\b", re.I),              # C6420
    re.compile(r"\biDRAC\s*(\d{1,2})\b", re.I),       # iDRAC 9 / iDRAC9
    # 客户端 PC 系列（Client BIOS DSA 常用，按系列名作为"机型"维度）
    re.compile(r"\b(OptiPlex)\b", re.I),
    re.compile(r"\b(Precision)\b", re.I),
    re.compile(r"\b(Latitude)\b", re.I),
    re.compile(r"\b(Inspiron)\b", re.I),
    re.compile(r"\b(Vostro)\b", re.I),
    re.compile(r"\bDell\s+(XPS)\b", re.I),
    # PowerScale / Isilon 节点型号（A300、A3000、H700、H7000 格式）
    re.compile(r"\bPowerScale\s+([AHFB]\d{3,4})\b", re.I),
    re.compile(r"\bIsilon\s+([AHFXS]\d{3,4})\b", re.I),
]

_VERSION_RE = re.compile(r"\b(?:v(?:ersion)?\s*)?(\d+(?:\.\d+){1,3})\b", re.I)
_QUALIFIER_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"prior\s+to\s+v?(\d+(?:\.\d+){1,3})", re.I), "<"),
    (re.compile(r"(?:before|earlier\s+than)\s+v?(\d+(?:\.\d+){1,3})", re.I), "<"),
    (re.compile(r"v?(\d+(?:\.\d+){1,3})\s+and\s+(?:earlier|prior)", re.I), "<="),
]

# 闭区间范围："X.Y.Z to A.B.C" / "between X and Y" / "from X to Y"
_RANGE_PATTERNS: List[re.Pattern] = [
    re.compile(r"v?(\d+(?:\.\d+){1,3})\s+to\s+v?(\d+(?:\.\d+){1,3})", re.I),
    re.compile(r"between\s+v?(\d+(?:\.\d+){1,3})\s+and\s+v?(\d+(?:\.\d+){1,3})", re.I),
    re.compile(r"from\s+v?(\d+(?:\.\d+){1,3})\s+to\s+v?(\d+(?:\.\d+){1,3})", re.I),
]

# 下界开放："X and later" / "X.Y and above" / "X onwards"
_GTE_PATTERNS: List[re.Pattern] = [
    re.compile(r"v?(\d+(?:\.\d+){1,3})\s+and\s+(?:later|above|newer)", re.I),
    re.compile(r"from\s+v?(\d+(?:\.\d+){1,3})\s+onwards?", re.I),
    re.compile(r"v?(\d+(?:\.\d+){1,3})\s+or\s+(?:later|above|newer)", re.I),
]


def detect_models(text: str) -> List[str]:
    """从 title / affected_products 中识别 Dell 机型"""
    if not text:
        return []
    seen = set()
    out: List[str] = []
    for pat in _MODEL_PATTERNS:
        for m in pat.finditer(text):
            raw = m.group(1)
            if pat.pattern.startswith(r"\biDRAC"):
                display = f"iDRAC{raw}"
            elif any(ch.isdigit() for ch in raw):
                display = raw.upper()  # R640, MX740C
            else:
                # 客户端 PC 系列保持首字母大写（OptiPlex / Precision / Latitude）
                display = raw[0].upper() + raw[1:].lower() if len(raw) > 1 else raw
                if display.upper() == "XPS":
                    display = "XPS"
            key = display.upper()
            if key not in seen:
                seen.add(key)
                out.append(display)
    return out


def detect_firmware_type(text: str) -> str:
    """识别微码类型，单一返回（按优先级）"""
    if not text:
        return "Software"
    t = text.lower()
    # OS 类优先级最高（OneFS / Operating Environment 等专属 OS 名）
    if "onefs" in t or "operating environment" in t or re.search(r"\boe\b", t, re.I):
        return "OS"
    if "bios" in t:
        return "BIOS"
    if "idrac" in t:
        return "iDRAC"
    if "firmware" in t or re.search(r"\bfw\b", t, re.I):
        return "Firmware"
    return "Software"


# 版本号合法性下限：硬件/微码类要求至少 3 段，OS/软件可放宽到 2 段
_MIN_VERSION_PARTS = {
    "BIOS": 3,
    "Firmware": 3,
    "iDRAC": 3,
    "OS": 2,
    "Software": 2,
}


def _is_valid_version(version: str, firmware_type: str) -> bool:
    """
    过滤明显误识别的版本号：
    - 至少包含 1 个点
    - 段数满足 firmware_type 的下限（避免 "1.2" 这种从机型号旁误抓的短串）
    - major 部分不能是 0（"0.x" 通常是误匹配）
    """
    if not version or "." not in version:
        return False
    parts = version.split(".")
    min_parts = _MIN_VERSION_PARTS.get(firmware_type, 2)
    if len(parts) < min_parts:
        return False
    try:
        major = int(parts[0])
    except ValueError:
        return False
    if major < 1:
        return False
    return True


def parse_version_tuple(v: str) -> Tuple[int, ...]:
    """将版本号转为可比较的元组（缺失位补 0）"""
    parts = []
    for x in v.split("."):
        try:
            parts.append(int(x))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def version_lt(a: str, b: str) -> bool:
    return parse_version_tuple(a) < parse_version_tuple(b)


def version_le(a: str, b: str) -> bool:
    return parse_version_tuple(a) <= parse_version_tuple(b)


# ────────────────────────────────────────────────────────────────────────────
# 数据结构
# ────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class MicrocodeKey:
    product_line: str
    model: str           # "" 表示该 DSA 没有具体机型
    firmware_type: str   # BIOS / Firmware / iDRAC / OS / Software
    version: str

    def display(self) -> str:
        parts = [self.product_line]
        if self.model:
            parts.append(self.model)
        parts.append(self.firmware_type)
        # "unversioned" 是数据源未公开具体版本号时的占位，显示得更明确
        if self.version == "unversioned":
            parts.append("全版本(未公开具体版本)")
        else:
            parts.append(self.version)
        return " | ".join(parts)


@dataclass
class MicrocodeRiskScore:
    key: MicrocodeKey
    qualifier: str               # "" | "<" | "<="
    direct_dsa_count: int        # 直接命中（精确版本）
    expanded_dsa_count: int      # 经 `<` 范围展开后总命中（含直接）
    severity_avg_cvss: float
    months_since_last: int       # 最后一次出现距今几个月（999 表示无数据）
    exposure_score: float        # 0~100
    risk_band: str               # EXTREME / HIGH / MEDIUM / LOW / MINIMAL
    explanation: List[str] = field(default_factory=list)
    kev_hit_count: int = 0       # 命中 CVE 中属于 CISA KEV 的数量

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["key"] = self.key.display()
        return d


# ────────────────────────────────────────────────────────────────────────────
# 微码级风险评估器
# ────────────────────────────────────────────────────────────────────────────

class MicrocodeRiskAssessor:
    """
    用法:
        ass = MicrocodeRiskAssessor("cve_data/cve_database.db")
        scores = ass.assess_all(top=20)
        for s in scores:
            print(s.key.display(), s.exposure_score, s.risk_band)
    """

    def __init__(self, db_path: str, now: Optional[datetime] = None) -> None:
        self.db_path = db_path
        self.now = now or datetime.now()
        self._dsa_records: Optional[List[Dict[str, Any]]] = None
        # 倒排索引: key -> {"direct": [dsa,...], "anchors": [(qualifier, version), ...]}
        self._microcode_index: Optional[Dict[MicrocodeKey, Dict[str, Any]]] = None
        # (line, model, firmware_type) -> set(version) 已知版本集
        self._known_versions: Optional[Dict[Tuple[str, str, str], set]] = None
        # 性能：每个 key 的 expanded 统计缓存（assess_all 时反复用到）
        self._expanded_cache: Dict[MicrocodeKey, Tuple[int, int, float, datetime, int]] = {}
        # 全局最大 expanded（用于 exposure_score 归一化）
        self._global_max_expanded: Optional[int] = None
        # CISA KEV CVE 集合（lazy 加载）
        self._kev_set: Optional[set] = None

    def _get_kev_set(self) -> set:
        """Lazy 加载 CISA KEV CVE 集合（含本地 7 天缓存，离线也能用旧缓存）"""
        if self._kev_set is None:
            try:
                from risk.kev_loader import load_kev_cves
                # 用数据库所在目录作为缓存目录，复用 cve_data
                cache_dir = str(Path(self.db_path).parent)
                self._kev_set = load_kev_cves(cache_dir=cache_dir)
            except Exception:
                self._kev_set = set()
        return self._kev_set

    # ── 数据加载 ────────────────────────────────────────────────────────

    def _load_dsa_records(self) -> List[Dict[str, Any]]:
        if self._dsa_records is not None:
            return self._dsa_records

        from risk._dsa_base import (
            affected_text_of,
            fetch_advisory_rows,
            load_cve_score_map,
            parse_advisory_data,
            parse_cve_ids,
            resolve_cvss,
            severity_text_of,
        )

        # 第一步：cves 表 cvss_score 一次性读进内存
        cve_score_map = load_cve_score_map(self.db_path)

        records: List[Dict[str, Any]] = []
        for title, cve_ids_str, pub, data_str in fetch_advisory_rows(self.db_path):
            if not pub:
                continue
            pub_dt = self._parse_date(pub)
            if pub_dt is None:
                continue
            cve_ids = parse_cve_ids(cve_ids_str)
            d = parse_advisory_data(data_str)
            affected_text = affected_text_of(d, include_version_range=True)
            severity_text = severity_text_of(d)
            avg_cvss, cvss_source = resolve_cvss(cve_ids, cve_score_map, severity_text)

            lines = classify_dsa(title or "", affected_text)
            records.append({
                "title": title or "",
                "affected_text": affected_text,
                "published": pub_dt,
                "product_lines": lines,
                "avg_cvss": avg_cvss,
                "cvss_source": cvss_source,
                "cve_ids": cve_ids,
                "severity": severity_text,
            })

        self._dsa_records = records
        return records

    # ── 微码 key 抽取 ───────────────────────────────────────────────────

    def _extract_keys_from_dsa(
        self, dsa: Dict[str, Any]
    ) -> List[Tuple[MicrocodeKey, str]]:
        """
        从一条 DSA 中抽取 (MicrocodeKey, qualifier) 列表。
        qualifier ∈ {"", "<", "<="}
        """
        title = dsa["title"]
        text = f"{title}\n{dsa['affected_text']}"
        product_lines = dsa["product_lines"]
        if not product_lines:
            return []

        models = detect_models(text)
        if not models:
            models = [""]   # 无机型 → 占位空串

        firmware_type = detect_firmware_type(text)

        # 提取版本号 + qualifier
        version_anchors: List[Tuple[str, str]] = []  # (qualifier, version)

        # 优先识别"X to Y"闭区间范围 → 拆为两个 anchor: ("<=", Y) + (">=", X)
        for pat in _RANGE_PATTERNS:
            for m in pat.finditer(text):
                start_v, end_v = m.group(1), m.group(2)
                # 保证 start <= end，否则可能是误识别
                if not version_lt(end_v, start_v):
                    version_anchors.append((">=", start_v))
                    version_anchors.append(("<=", end_v))

        # 下界开放："X and later"
        for pat in _GTE_PATTERNS:
            for m in pat.finditer(text):
                version_anchors.append((">=", m.group(1)))

        # 上界开放（保留原有）
        for pat, q in _QUALIFIER_PATTERNS:
            for m in pat.finditer(text):
                version_anchors.append((q, m.group(1)))

        # 如果以上模式都没命中，退化为普通版本号匹配
        if not version_anchors:
            for m in _VERSION_RE.finditer(text):
                v = m.group(1)
                if "." in v:
                    version_anchors.append(("", v))

        # 按 firmware_type 过滤掉非法/误识别的版本号
        version_anchors = [
            (q, v) for q, v in version_anchors
            if _is_valid_version(v, firmware_type)
        ]

        # 无版本号但 firmware_type 是硬件/微码类 → 生成 "unversioned" key
        # （PowerEdge BIOS DSA 通常只写 "Dell PowerEdge Server" 没有版本号）
        if not version_anchors:
            if firmware_type in ("BIOS", "Firmware", "iDRAC", "OS"):
                version_anchors = [("", "unversioned")]
            else:
                return []

        keys: List[Tuple[MicrocodeKey, str]] = []
        seen = set()
        for line in product_lines:
            for model in models:
                for q, v in version_anchors:
                    k = MicrocodeKey(line, model, firmware_type, v)
                    sig = (k, q)
                    if sig not in seen:
                        seen.add(sig)
                        keys.append(sig)
        return keys

    def _build_index(self) -> Dict[MicrocodeKey, Dict[str, Any]]:
        if self._microcode_index is not None:
            return self._microcode_index

        index: Dict[MicrocodeKey, Dict[str, Any]] = defaultdict(
            lambda: {"direct": [], "anchors": [], "qualifier": ""}
        )
        known: Dict[Tuple[str, str, str], set] = defaultdict(set)

        for dsa in self._load_dsa_records():
            for key, qualifier in self._extract_keys_from_dsa(dsa):
                if qualifier == "":
                    index[key]["direct"].append(dsa)
                else:
                    index[key]["anchors"].append((qualifier, dsa))
                # 维持最新 qualifier 信息（仅取第一条）
                if not index[key]["qualifier"]:
                    index[key]["qualifier"] = qualifier
                known[(key.product_line, key.model, key.firmware_type)].add(key.version)

        self._microcode_index = dict(index)
        self._known_versions = {k: v for k, v in known.items()}
        return self._microcode_index

    # ── 范围展开 ────────────────────────────────────────────────────────

    def _expanded_dsa_count(
        self, key: MicrocodeKey
    ) -> Tuple[int, int, float, datetime, int]:
        """
        计算 key 的展开后命中 DSA 数。
        返回 (direct_count, expanded_count, avg_cvss, latest_pub_dt, kev_hit_count)
        kev_hit_count: 命中 DSA 引用的 CVE 中属于 CISA KEV 的去重数量
        """
        cached = self._expanded_cache.get(key)
        if cached is not None:
            return cached

        index = self._build_index()
        bucket = index.get(key, {"direct": [], "anchors": [], "qualifier": ""})

        hit_dsas: Dict[int, Dict[str, Any]] = {}
        # 直接命中
        for dsa in bucket["direct"]:
            hit_dsas[id(dsa)] = dsa
        for q, dsa in bucket["anchors"]:
            hit_dsas[id(dsa)] = dsa

        # 用 `<` / `<=` / `>=` 锚点扫描其他同 (line, model, firmware_type) 的 key
        target_triple = (key.product_line, key.model, key.firmware_type)
        # 找该三元组下所有有 anchor 的 key（含本 key）
        for other_key, other_bucket in index.items():
            if (other_key.product_line, other_key.model, other_key.firmware_type) != target_triple:
                continue
            if other_key.version == key.version:
                continue
            for q, dsa in other_bucket["anchors"]:
                if q == "<" and version_lt(key.version, other_key.version):
                    hit_dsas[id(dsa)] = dsa
                elif q == "<=" and version_le(key.version, other_key.version):
                    hit_dsas[id(dsa)] = dsa
                elif q == ">=" and version_le(other_key.version, key.version):
                    # other_key 标了 ">=" 表示该 DSA 影响所有 ≥ other_key.version 的版本
                    hit_dsas[id(dsa)] = dsa

        direct_count = len(bucket["direct"]) + len(bucket["anchors"])
        expanded_count = len(hit_dsas)

        if hit_dsas:
            cvss_list = [d["avg_cvss"] for d in hit_dsas.values() if d["avg_cvss"] > 0]
            avg_cvss = sum(cvss_list) / len(cvss_list) if cvss_list else 0.0
            latest_pub = max(d["published"] for d in hit_dsas.values())
            # KEV 命中：去重收集所有 hit DSA 的 cve_ids，与 KEV 集合求交
            kev_set = self._get_kev_set()
            cve_union: set = set()
            for d in hit_dsas.values():
                cve_union.update(d.get("cve_ids", []))
            kev_hit_count = len(cve_union & kev_set) if kev_set else 0
        else:
            avg_cvss = 0.0
            latest_pub = self.now - timedelta(days=999 * 30)
            kev_hit_count = 0

        result = (direct_count, expanded_count, avg_cvss, latest_pub, kev_hit_count)
        self._expanded_cache[key] = result
        return result

    def _ensure_global_max_expanded(self) -> int:
        """计算所有 key 中最大 expanded 命中数（用于跨产品线归一化），缓存。"""
        if self._global_max_expanded is not None:
            return self._global_max_expanded
        index = self._build_index()
        gmax = 1
        for k in index.keys():
            _, exp, _, _, _ = self._expanded_dsa_count(k)
            if exp > gmax:
                gmax = exp
        self._global_max_expanded = gmax
        return gmax

    # ── 评分主流程 ──────────────────────────────────────────────────────

    def assess_key(self, key: MicrocodeKey) -> MicrocodeRiskScore:
        index = self._build_index()
        bucket = index.get(key, {"direct": [], "anchors": [], "qualifier": ""})
        qualifier = bucket["qualifier"]

        direct, expanded, avg_cvss, latest, kev_hits = self._expanded_dsa_count(key)
        months_since_last = max(0, (self.now - latest).days // 30)
        if expanded == 0:
            months_since_last = 999

        # 全局最大 expanded 用于跨产品线归一化（缓存，O(N) 摊销）
        global_max = self._ensure_global_max_expanded()
        freq_score = (expanded / global_max) * 50 if global_max > 0 else 0.0

        # severity_score：CVSS 基线 (avg/10×20) + KEV 加成 (每个 +5)，上限 25
        severity_base = (avg_cvss / 10.0) * 20 if avg_cvss > 0 else 0.0
        kev_bonus = min(15.0, kev_hits * 5.0)
        severity_score = min(25.0, severity_base + kev_bonus)

        recency_factor = max(0.0, 1.0 - months_since_last / 24.0) if months_since_last < 999 else 0.0
        recency_score = recency_factor * 25

        exposure_score = round(freq_score + severity_score + recency_score, 2)
        risk_band = self._band_from_score(exposure_score)

        kev_tag = f"  ⚠ CISA KEV: {kev_hits} 个 CVE 已被野外利用" if kev_hits else ""

        explanation = [
            f"{key.display()}",
            f"qualifier: '{qualifier}' (空/`<`/`<=`/`>=`)",
            f"直接命中 DSA: {direct}，范围展开后: {expanded}",
            f"严重度均值 CVSS: {avg_cvss:.2f}",
            f"最近一次出现: {months_since_last} 月前",
        ]
        if kev_tag:
            explanation.append(kev_tag)
        explanation.extend([
            "",
            f"  freq_score    = {freq_score:.1f}/50 (全局归一: {expanded}/{global_max})",
            f"  severity_score = {severity_score:.1f}/25 (CVSS×{severity_base:.1f} + KEV×{kev_bonus:.0f})",
            f"  recency_score = {recency_score:.1f}/25 (1 - 月数/24)",
            f"  exposure_score = {exposure_score} → {risk_band}",
        ])

        # P2-12: 近 12 月趋势 sparkline
        if expanded > 0:
            monthly = self._monthly_counts(key, months=12)
            spark = self.ascii_sparkline(monthly)
            explanation.append("")
            explanation.append(f"  近12月趋势: {spark}  (最旧 → 最新, 共 {sum(monthly)} 条)")

        return MicrocodeRiskScore(
            key=key,
            qualifier=qualifier,
            direct_dsa_count=direct,
            expanded_dsa_count=expanded,
            severity_avg_cvss=round(avg_cvss, 2),
            months_since_last=months_since_last,
            exposure_score=exposure_score,
            risk_band=risk_band,
            explanation=explanation,
            kev_hit_count=kev_hits,
        )

    def assess_all(
        self,
        product_line_filter: Optional[str] = None,
        firmware_type_filter: Optional[str] = None,
        top: Optional[int] = None,
    ) -> List[MicrocodeRiskScore]:
        index = self._build_index()
        results: List[MicrocodeRiskScore] = []
        for key in index.keys():
            if product_line_filter and key.product_line != product_line_filter:
                continue
            if firmware_type_filter and key.firmware_type != firmware_type_filter:
                continue
            results.append(self.assess_key(key))
        results.sort(key=lambda s: s.exposure_score, reverse=True)
        if top:
            results = results[:top]
        return results

    # ── P1-7：反向查询 ──────────────────────────────────────────────────

    def query_by_microcode(
        self,
        model: str = "",
        firmware_type: Optional[str] = None,
        version: Optional[str] = None,
        product_line: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        反向查询：给定 (机型, 微码类型, 版本)，返回影响该组合的所有 DSA。

        支持的查询模式：
        - 仅给 model="R640" → 该机型所有相关 DSA
        - model="R640" + firmware_type="BIOS" → R640 BIOS 所有 DSA
        - model="R640" + firmware_type="BIOS" + version="2.10.0" → 命中 2.10.0 的 DSA
          （含 < 2.11.0 / <= 2.10.0 / >= 2.0.0 / 直接 == 2.10.0 等所有路径）

        :return: DSA 字典列表，按 published 倒序，每条含
                 dsa_id / title / published / severity / avg_cvss /
                 cve_ids / kev_cves（命中 KEV 的 cve 子集）
        """
        index = self._build_index()
        kev_set = self._get_kev_set()
        matched: Dict[int, Dict[str, Any]] = {}

        model_upper = (model or "").upper()
        version = version or None

        for key, bucket in index.items():
            # 过滤维度
            if model_upper and key.model.upper() != model_upper:
                continue
            if firmware_type and key.firmware_type != firmware_type:
                continue
            if product_line and key.product_line != product_line:
                continue

            # 1) 直接命中（精确版本号或忽略版本）
            if version is None or key.version == version:
                for dsa in bucket["direct"]:
                    matched[id(dsa)] = dsa

            # 2) 锚点扩散
            for q, dsa in bucket["anchors"]:
                if version is None:
                    matched[id(dsa)] = dsa
                    continue
                # 输入版本是否落在 anchor 描述的范围内
                if q == "<" and version_lt(version, key.version):
                    matched[id(dsa)] = dsa
                elif q == "<=" and version_le(version, key.version):
                    matched[id(dsa)] = dsa
                elif q == ">=" and version_le(key.version, version):
                    matched[id(dsa)] = dsa

        # 整理结果
        out = []
        for dsa in matched.values():
            cve_ids = list(dsa.get("cve_ids") or [])
            kev_cves = [c for c in cve_ids if c in kev_set] if kev_set else []
            out.append({
                "title": dsa.get("title", ""),
                "published": dsa["published"],
                "severity": dsa.get("severity", ""),
                "avg_cvss": dsa.get("avg_cvss", 0.0),
                "cvss_source": dsa.get("cvss_source", "none"),
                "cve_ids": cve_ids,
                "kev_cves": kev_cves,
            })
        out.sort(key=lambda d: d["published"], reverse=True)
        return out

    # ── P2-12：月度趋势 ─────────────────────────────────────────────────

    def monthly_hits(
        self,
        key: MicrocodeKey,
        months: int = 12,
    ) -> List[Tuple[str, int]]:
        """
        返回该 key 近 N 个月的 DSA 命中数序列（按月升序）。

        :param key: 微码 key（产品线 × 机型 × 类型 × 版本）
        :param months: 回溯月数（默认 12）
        :return: [(YYYY-MM, count), ...] 长度为 months，缺月填 0
        """
        index = self._build_index()
        bucket = index.get(key, {"direct": [], "anchors": [], "qualifier": ""})

        # 收集该 key 经范围展开后的所有命中 DSA
        hit_dsas: Dict[int, Dict[str, Any]] = {}
        for dsa in bucket["direct"]:
            hit_dsas[id(dsa)] = dsa
        for q, dsa in bucket["anchors"]:
            hit_dsas[id(dsa)] = dsa

        # 跨 key 范围扩散
        target_triple = (key.product_line, key.model, key.firmware_type)
        for other_key, other_bucket in index.items():
            if (other_key.product_line, other_key.model, other_key.firmware_type) != target_triple:
                continue
            if other_key.version == key.version:
                continue
            for q, dsa in other_bucket["anchors"]:
                if q == "<" and version_lt(key.version, other_key.version):
                    hit_dsas[id(dsa)] = dsa
                elif q == "<=" and version_le(key.version, other_key.version):
                    hit_dsas[id(dsa)] = dsa
                elif q == ">=" and version_le(other_key.version, key.version):
                    hit_dsas[id(dsa)] = dsa

        # 月度桶
        from collections import OrderedDict
        bucket_map: "OrderedDict[str, int]" = OrderedDict()
        # 初始化最近 N 月（升序）
        cur_year, cur_month = self.now.year, self.now.month
        keys_in_order: List[str] = []
        for offset in range(months - 1, -1, -1):
            y, m = cur_year, cur_month - offset
            while m <= 0:
                m += 12
                y -= 1
            label = f"{y:04d}-{m:02d}"
            keys_in_order.append(label)
            bucket_map[label] = 0

        for dsa in hit_dsas.values():
            pub: datetime = dsa.get("published")
            if not pub:
                continue
            label = f"{pub.year:04d}-{pub.month:02d}"
            if label in bucket_map:
                bucket_map[label] += 1

        return list(bucket_map.items())

    def coverage_summary(self) -> Dict[str, Any]:
        """统计抽取覆盖率（用于评估原型可用性）"""
        index = self._build_index()
        records = self._load_dsa_records()
        line_keys: Dict[str, set] = defaultdict(set)
        ftype_keys: Dict[str, set] = defaultdict(set)
        with_model = 0
        for key in index.keys():
            line_keys[key.product_line].add(key)
            ftype_keys[key.firmware_type].add(key)
            if key.model:
                with_model += 1
        return {
            "total_dsa": len(records),
            "total_microcode_keys": len(index),
            "keys_with_model": with_model,
            "keys_with_model_pct": round(100 * with_model / max(1, len(index)), 1),
            "keys_per_product_line": {k: len(v) for k, v in line_keys.items()},
            "keys_per_firmware_type": {k: len(v) for k, v in ftype_keys.items()},
        }

    # ── P2-12：月度趋势 ─────────────────────────────────────────────────

    def _monthly_counts(self, key: MicrocodeKey, months: int = 12) -> List[int]:
        """
        获取该 key 近 N 个月（按 30 天分桶）的展开命中 DSA 数。
        返回长度为 months 的列表，counts[0] 是最远月份，counts[-1] 是最近月份。
        """
        # 复用 _expanded_dsa_count 内部的 hit_dsas 逻辑（去重）
        index = self._build_index()
        bucket = index.get(key, {"direct": [], "anchors": [], "qualifier": ""})

        hit_dsas: Dict[int, Dict[str, Any]] = {}
        for dsa in bucket["direct"]:
            hit_dsas[id(dsa)] = dsa
        for q, dsa in bucket["anchors"]:
            hit_dsas[id(dsa)] = dsa

        target_triple = (key.product_line, key.model, key.firmware_type)
        for other_key, other_bucket in index.items():
            if (other_key.product_line, other_key.model, other_key.firmware_type) != target_triple:
                continue
            if other_key.version == key.version:
                continue
            for q, dsa in other_bucket["anchors"]:
                if q == "<" and version_lt(key.version, other_key.version):
                    hit_dsas[id(dsa)] = dsa
                elif q == "<=" and version_le(key.version, other_key.version):
                    hit_dsas[id(dsa)] = dsa
                elif q == ">=" and version_le(other_key.version, key.version):
                    hit_dsas[id(dsa)] = dsa

        # 按 30 天分桶
        counts = [0] * months
        cutoff = self.now - timedelta(days=30 * months)
        for dsa in hit_dsas.values():
            pub = dsa["published"]
            if pub < cutoff or pub > self.now:
                continue
            month_idx = (self.now - pub).days // 30
            if 0 <= month_idx < months:
                counts[months - 1 - month_idx] += 1   # 反转：旧 → 新
        return counts

    @staticmethod
    def ascii_sparkline(counts: List[int]) -> str:
        """把月度计数转成 Unicode block 字符 sparkline（最旧→最新）"""
        if not counts:
            return ""
        chars = "▁▂▃▄▅▆▇█"
        mx = max(counts)
        if mx == 0:
            return "▁" * len(counts)
        out = []
        for v in counts:
            idx = min(len(chars) - 1, int(v / mx * (len(chars) - 1)))
            out.append(chars[idx])
        return "".join(out)

    @staticmethod
    def _parse_date(s: str) -> Optional[datetime]:
        """[已迁移至 risk._dsa_base.parse_date] 保留薄包装"""
        return _shared_parse_date(s)

    @staticmethod
    def _band_from_score(s: float) -> str:
        if s >= 75:
            return "EXTREME"
        if s >= 55:
            return "HIGH"
        if s >= 35:
            return "MEDIUM"
        if s >= 15:
            return "LOW"
        return "MINIMAL"


__all__ = [
    "MicrocodeKey",
    "MicrocodeRiskScore",
    "MicrocodeRiskAssessor",
    "detect_models",
    "detect_firmware_type",
    "version_lt",
    "version_le",
]
