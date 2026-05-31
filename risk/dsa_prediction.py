"""
Dell 产品线 DSA 概率预测 (risk/dsa_prediction.py)

围绕 Dell EMC 产品线家族，预测未来 N 天内某产品线出现 Dell DSA（安全公告）的概率。

数据源
------
- `dell_advisories` 表：历史 DSA（含 title, affected_products, cve_ids, published_date, severity）
- `cves` 表：NVD CVE（含 description, published, cvss, cwe）

算法（Poisson 速率模型，可解释）
--------------------------------
对每条产品线 L，按以下步骤计算未来 D 天的概率：

1. **历史月度基线 λ_base**
   - 取过去 12 个月匹配该产品线的 DSA 数 ÷ 12 个月
   - 反映该产品线长期 DSA 发布节奏

2. **近期月度速率 λ_recent**
   - 取过去 3 个月 DSA 数 ÷ 3
   - 反映短期态势变化

3. **趋势倍数 trend_multiplier**
   - = clip(λ_recent / max(λ_base, 0.1), 0.5, 3.0)
   - 0.5–3.0 之间裁剪，避免短期噪声主导

4. **严重度因子 severity_factor**
   - 取该产品线相关 CVE（最近 90 天）平均 CVSS 分
   - = 1 + 0.5 × (avg_cvss / 10)，范围 [1.0, 1.5]

5. **未覆盖 CVE 压力 open_cve_pressure**
   - 最近 90 天 NVD CVE 中：描述/产品名匹配该产品线，但 CVE-ID **不在**任何 DSA 中
   - 表示"待发布 DSA"的潜在数量
   - 贡献：+0.04 × pressure（每 25 条未覆盖 CVE → 月预期增加 1）

6. **有效速率 λ_effective**
   - = λ_base × trend_multiplier × severity_factor + 0.04 × open_cve_pressure

7. **期望 DSA 数 + 概率**
   - expected = λ_effective × (D / 30)
   - P(≥1 DSA in D 天) = 1 − exp(−expected)
   - 80% 置信区间使用 Poisson 标准差近似：±1.282 × sqrt(expected)

可解释性
--------
- 每个产品线返回 explanation 字段，分行说明各因子贡献
- factors 字典记录数值用于 UI 展示
- 概率与期望值同时输出，避免误读

依赖
----
- 仅依赖标准库 + sqlite3，不引入 scipy/statsmodels
"""
from __future__ import annotations

import json
import math
import re
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple


# ────────────────────────────────────────────────────────────────────────────
# Dell EMC 产品线分类法
# ────────────────────────────────────────────────────────────────────────────

# 每个产品线对应一组正则 + 中文别名，用于在 DSA title 与 affected_products 中匹配。
# key 为简短中文名（用于 UI 展示），value 为 (英文标识, [正则模式])
DELL_PRODUCT_LINES: Dict[str, Tuple[str, List[str]]] = {
    "PowerStore (主存储)":          ("PowerStore",        [r"\bPowerStore\b"]),
    "PowerMax/VMAX (主存储)":        ("PowerMax",          [r"\bPowerMax\b", r"\bVMAX\b", r"\bSymmetrix\b"]),
    "Unity / Unity XT (主存储)":     ("Unity",             [r"\bUnity\s*XT\b", r"(?<!Comm)\bUnity\b"]),
    "VNX/VNXe (主存储)":             ("VNX",               [r"\bVNXe?\b"]),
    "SC / Compellent (主存储)":      ("Compellent",        [r"\bCompellent\b", r"\bSC\s*\d{3,4}\b"]),
    "ME (主存储)":                   ("ME-Series",         [r"\bME\s*4\d{3}\b", r"\bME\s*5\d{3}\b"]),
    "XtremIO (主存储)":              ("XtremIO",           [r"\bXtremIO\b"]),
    "PowerFlex / VxFlex (主存储)":   ("PowerFlex",         [r"\bPowerFlex\b", r"\bScaleIO\b", r"\bVxFlex\b"]),
    "PowerScale / Isilon (NAS)":     ("PowerScale",        [r"\bPowerScale\b", r"\bIsilon\b", r"\bOneFS\b"]),
    "Celerra / VNX File (NAS)":      ("Celerra",           [r"\bCelerra\b"]),
    "ECS / ObjectScale (对象存储)":  ("ECS",               [r"\bECS\b(?!\s*Storage)", r"\bObjectScale\b"]),
    "Data Domain (备份)":            ("DataDomain",        [r"\bData\s*Domain\b", r"\bDDOS\b", r"\bDDVE\b"]),
    "Avamar (备份)":                 ("Avamar",            [r"\bAvamar\b"]),
    "NetWorker (备份)":              ("NetWorker",         [r"\bNetWorker\b"]),
    "PowerProtect (备份)":           ("PowerProtect",      [r"\bPowerProtect\b"]),
    "RecoverPoint (备份)":           ("RecoverPoint",      [r"\bRecoverPoint\b"]),
    "Centera / DLm (归档)":          ("Centera",           [r"\bCentera\b", r"\bDisk\s*Library\b", r"\bDLm\b"]),
    "Connectrix (FC SAN)":           ("Connectrix",        [r"\bConnectrix\b"]),
    "VPLEX (网络)":                  ("VPLEX",             [r"\bVPLEX\b"]),
    "Networking OS10 / SONiC (网络)": ("Networking",       [r"\bOS10\b", r"\bSONiC\b", r"\bDell\s*Networking\b", r"\bEnterprise\s*SONiC\b"]),
    "VxRail (超融合)":               ("VxRail",            [r"\bVxRail\b"]),
    "APEX Cloud Platform (超融合)":  ("APEX",              [r"\bAPEX\s*Cloud\b", r"\bDell\s*APEX\b"]),
    "Integrated System (超融合)":    ("IntegratedSystem",  [r"\bIntegrated\s*System\b", r"\bAX\s*System\b"]),
    "CloudIQ / DataIQ (管理)":       ("CloudIQ",           [r"\bCloudIQ\b", r"\bDataIQ\b"]),
    "PowerPath / SRM (管理)":        ("PowerPath",         [r"\bPowerPath\b", r"\bSRM\b(?![A-Za-z])"]),
    "OpenManage / iDRAC (管理)":     ("OpenManage",        [r"\bOpenManage\b", r"\biDRAC\b", r"\bIntegrated\s*Dell\s*Remote\s*Access\b"]),
    "Command|Update (管理)":         ("CommandUpdate",     [r"\bCommand\s*\|?\s*Update\b", r"\bSupportAssist\b"]),
    "PowerEdge (服务器)":            ("PowerEdge",         [r"\bPowerEdge\b", r"\bAMD-based\s*PowerEdge\b"]),
    "Client BIOS / Precision / Latitude (客户端)": ("ClientPlatform",
                                                            [r"\bClient\s*BIOS\b", r"\bClient\s*Platform\b",
                                                             r"\bPrecision\b", r"\bLatitude\b",
                                                             r"\bOptiPlex\b", r"\bThinOS\b",
                                                             r"\bClient\s*Consumer\b"]),
}


def _compile_patterns() -> Dict[str, List[re.Pattern]]:
    """编译所有正则（一次性初始化，加速匹配）"""
    return {
        name: [re.compile(p, re.IGNORECASE) for p in patterns]
        for name, (_, patterns) in DELL_PRODUCT_LINES.items()
    }


_COMPILED_PATTERNS = _compile_patterns()


def classify_dsa(title: str, affected_products_text: str = "") -> List[str]:
    """
    将一条 DSA 分类到一个或多个产品线。

    匹配策略：title + affected_products 中任一字段命中模式即归属该产品线。
    一条 DSA 可同时归属多个产品线（如同时影响 VxRail 和 PowerEdge）。

    :return: 命中的产品线 key 列表（可能为空）
    """
    haystack = f"{title or ''}\n{affected_products_text or ''}"
    matched: List[str] = []
    for line_name, patterns in _COMPILED_PATTERNS.items():
        if any(p.search(haystack) for p in patterns):
            matched.append(line_name)
    return matched


def classify_cve_text(text: str) -> List[str]:
    """对 CVE 描述文本做产品线分类（用于 open_cve_pressure 计算）"""
    if not text:
        return []
    matched: List[str] = []
    for line_name, patterns in _COMPILED_PATTERNS.items():
        if any(p.search(text) for p in patterns):
            matched.append(line_name)
    return matched


# ────────────────────────────────────────────────────────────────────────────
# 数据结构
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class DSAProductLineForecast:
    """单条产品线的 DSA 概率预测结果"""
    product_line: str
    forecast_days: int

    # 历史数据
    historical_dsa_total: int       # 全量历史 DSA 数
    historical_dsa_12m: int         # 过去 12 个月
    historical_dsa_3m: int          # 过去 3 个月

    # 速率因子
    base_rate_per_month: float      # λ_base
    recent_rate_per_month: float    # λ_recent
    trend_multiplier: float         # = clip(λ_recent / λ_base, 0.5, 3.0)

    # 增益因子
    severity_factor: float          # 1.0 ~ 1.5
    open_cve_pressure: int          # 待覆盖 CVE 数

    # 输出
    expected_dsa_count: float       # 期望 DSA 数（连续值）
    probability: float              # P(≥1 DSA in D 天)，∈ [0, 1]
    probability_ci: Tuple[float, float]  # 80% 置信区间
    risk_level: str                 # CRITICAL / HIGH / MEDIUM / LOW / MINIMAL
    explanation: List[str] = field(default_factory=list)

    forecast_date: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["forecast_date"] = self.forecast_date.isoformat()
        d["probability_ci"] = list(self.probability_ci)
        return d


# ────────────────────────────────────────────────────────────────────────────
# 预测器
# ────────────────────────────────────────────────────────────────────────────

class DSAProductLinePredictor:
    """
    Dell 产品线 DSA 概率预测器。

    用法：
        predictor = DSAProductLinePredictor("cve_data/cve_database.db")
        results = predictor.forecast_all(forecast_days=30)
        for f in results:
            print(f.product_line, f.probability, f.risk_level)
    """

    def __init__(self, db_path: str, now: Optional[datetime] = None) -> None:
        self.db_path = db_path
        self.now = now or datetime.now()
        # 缓存：避免对每个产品线重复扫描全表
        self._dsa_records: Optional[List[Dict[str, Any]]] = None
        self._recent_cves: Optional[List[Dict[str, Any]]] = None
        self._dsa_cve_set: Optional[set] = None
        # 预聚合：每条产品线的 CVE 列表（避免对每个产品线重复线性扫描）
        self._line_cve_index: Optional[Dict[str, List[Dict[str, Any]]]] = None

    # ── 数据加载 ────────────────────────────────────────────────────────

    def _load_dsa_records(self) -> List[Dict[str, Any]]:
        """加载所有 DSA 记录（含产品线分类结果，缓存）"""
        if self._dsa_records is not None:
            return self._dsa_records

        records: List[Dict[str, Any]] = []
        conn = sqlite3.connect(self.db_path)
        try:
            cur = conn.cursor()
            cur.execute("SELECT title, cve_ids, published_date, data FROM dell_advisories")
            for title, cve_ids_str, pub, data_str in cur.fetchall():
                if not pub:
                    continue
                pub_dt = self._parse_date(pub)
                if pub_dt is None:
                    continue
                affected_text = ""
                severity = ""
                if data_str:
                    try:
                        d = json.loads(data_str)
                        ap = d.get("affected_products", []) or []
                        affected_text = " ".join(
                            (p.get("name", "") + " " + p.get("model", ""))
                            for p in ap if isinstance(p, dict)
                        )
                        severity = (d.get("severity") or "").upper()
                    except (json.JSONDecodeError, TypeError):
                        pass
                lines = classify_dsa(title or "", affected_text)
                records.append({
                    "title": title or "",
                    "cve_ids": [c for c in re.split(r"[,\s]+", (cve_ids_str or "").strip()) if c.startswith("CVE-")],
                    "published": pub_dt,
                    "severity": severity,
                    "product_lines": lines,
                })
        finally:
            conn.close()

        self._dsa_records = records
        return records

    def _load_recent_cves(self, days: int = 90) -> List[Dict[str, Any]]:
        """加载最近 N 天 CVE（用于压力 + 严重度因子计算）

        CVE 完整信息存储在 `cves.data` 列（JSON），需在 Python 侧解析
        description 与 CVSS 分数。

        优化：使用 SQL LIKE 预筛选含 Dell/EMC/PowerXxx 等关键词的 CVE，
        避免对每条 CVE 都做 JSON 解析（13K+ 条 → 通常剩几百条）。
        """
        if self._recent_cves is not None:
            return self._recent_cves

        cutoff = self.now - timedelta(days=days)
        cutoff_str = cutoff.strftime("%Y-%m-%d")

        # 预筛选关键词（覆盖所有产品线常见标识）。在 SQL 层完成 → 大幅减少 JSON 解析量
        prefilter_keywords = [
            "dell", "emc", "powerstore", "powermax", "vmax", "symmetrix",
            "unity", "vnx", "compellent", "xtremio", "powerflex", "scaleio", "vxflex",
            "powerscale", "isilon", "onefs", "celerra", "ecs", "objectscale",
            "data domain", "ddos", "ddve", "avamar", "networker", "powerprotect",
            "recoverpoint", "centera", "connectrix", "vplex", "os10", "sonic",
            "vxrail", "apex", "cloudiq", "dataiq", "powerpath", "openmanage",
            "idrac", "supportassist", "command|update", "poweredge",
            "precision", "latitude", "optiplex", "thinos", "client bios",
        ]
        like_clauses = " OR ".join(["LOWER(data) LIKE ?"] * len(prefilter_keywords))
        params = [cutoff_str] + [f"%{kw}%" for kw in prefilter_keywords]

        records: List[Dict[str, Any]] = []
        conn = sqlite3.connect(self.db_path)
        try:
            cur = conn.cursor()
            cur.execute(
                f"""SELECT cve_id, published_date, data
                    FROM cves
                    WHERE published_date >= ?
                      AND ({like_clauses})""",
                params,
            )
            for cve_id, pub, data_str in cur.fetchall():
                pub_dt = self._parse_date(pub)
                if pub_dt is None or pub_dt < cutoff:
                    continue

                desc = ""
                cvss = 0.0
                if data_str:
                    try:
                        d = json.loads(data_str)
                        # 本项目 cves 表 data 是预解析过的扁平结构
                        desc = d.get("description", "") or ""
                        if not desc:
                            cve_obj = d.get("cve", d)
                            for item in cve_obj.get("descriptions", []) or []:
                                if isinstance(item, dict) and item.get("lang") == "en":
                                    desc = item.get("value", "")
                                    break
                        s = d.get("cvss_score")
                        if s is not None:
                            try:
                                cvss = float(s)
                            except (TypeError, ValueError):
                                cvss = 0.0
                        # 兜底：NVD 嵌套（兼容遗留数据）
                        if cvss <= 0:
                            cve_obj = d.get("cve", d)
                            metrics = cve_obj.get("metrics", {}) or {}
                            for ver_key in ("cvssMetricV40", "cvssMetricV31",
                                            "cvssMetricV30", "cvssMetricV2"):
                                entries = metrics.get(ver_key) or []
                                if entries and isinstance(entries, list):
                                    cd = entries[0].get("cvssData", {}) if isinstance(entries[0], dict) else {}
                                    score = cd.get("baseScore")
                                    if score is not None:
                                        try:
                                            cvss = float(score)
                                            break
                                        except (TypeError, ValueError):
                                            pass
                    except (json.JSONDecodeError, TypeError, AttributeError):
                        pass

                records.append({
                    "cve_id": cve_id,
                    "description": desc,
                    "published": pub_dt,
                    "cvss": cvss,
                })
        finally:
            conn.close()

        self._recent_cves = records
        return records

    def _load_dsa_cve_set(self) -> set:
        """加载所有已被 DSA 引用的 CVE-ID 集合（用于 open_cve_pressure 排除）"""
        if self._dsa_cve_set is not None:
            return self._dsa_cve_set
        cve_set: set = set()
        for r in self._load_dsa_records():
            for c in r["cve_ids"]:
                cve_set.add(c)
        self._dsa_cve_set = cve_set
        return cve_set

    def _build_line_cve_index(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        构建 {产品线: [CVE 记录]} 倒排索引（一次性）。

        相比每个产品线独立线性扫描全部 CVE 记录（O(L × N)），
        这里只扫一遍 CVE，对每条 CVE 跑一次分类，得到 O(N) 复杂度。
        """
        if self._line_cve_index is not None:
            return self._line_cve_index

        index: Dict[str, List[Dict[str, Any]]] = {line: [] for line in DELL_PRODUCT_LINES.keys()}
        for cve in self._load_recent_cves(days=90):
            for line in classify_cve_text(cve["description"]):
                index[line].append(cve)
        self._line_cve_index = index
        return index

    # ── 预测主流程 ──────────────────────────────────────────────────────

    def forecast_line(self, product_line: str, forecast_days: int = 30) -> DSAProductLineForecast:
        """对单条产品线做预测"""
        if product_line not in DELL_PRODUCT_LINES:
            raise ValueError(f"未知产品线: {product_line}")

        records = self._load_dsa_records()
        # 仅取该产品线的 DSA
        line_records = [r for r in records if product_line in r["product_lines"]]

        # 时间窗口
        cutoff_12m = self.now - timedelta(days=365)
        cutoff_3m = self.now - timedelta(days=90)

        dsa_12m = [r for r in line_records if r["published"] >= cutoff_12m]
        dsa_3m = [r for r in line_records if r["published"] >= cutoff_3m]

        # 1. 基线月度速率（过去 12 个月平均）
        base_rate = len(dsa_12m) / 12.0

        # 2. 近期月度速率（过去 3 个月平均）
        recent_rate = len(dsa_3m) / 3.0

        # 3. 趋势倍数
        if base_rate < 0.05:
            # 几乎没有历史数据，使用近期速率作为兜底（避免除零放大）
            trend_multiplier = 1.0
        else:
            raw_ratio = recent_rate / base_rate
            trend_multiplier = max(0.5, min(3.0, raw_ratio))

        # 4. 严重度因子（基于近 90 天匹配该产品线的 CVE 平均 CVSS）
        line_cve_index = self._build_line_cve_index()
        line_cve_records = line_cve_index.get(product_line, [])
        if line_cve_records:
            avg_cvss = sum(c["cvss"] for c in line_cve_records) / len(line_cve_records)
            severity_factor = 1.0 + 0.5 * (avg_cvss / 10.0)  # ∈ [1.0, 1.5]
            severity_factor = max(1.0, min(1.5, severity_factor))
        else:
            avg_cvss = 0.0
            severity_factor = 1.0

        # 5. 未覆盖 CVE 压力
        dsa_cve_set = self._load_dsa_cve_set()
        open_cves = [c for c in line_cve_records if c["cve_id"] not in dsa_cve_set]
        open_cve_pressure = len(open_cves)

        # 6. 有效月度速率
        lambda_effective = (
            base_rate * trend_multiplier * severity_factor
            + 0.04 * open_cve_pressure
        )

        # 7. 期望 DSA 数 + Poisson 概率
        expected = lambda_effective * (forecast_days / 30.0)
        # 概率 P(≥1) = 1 - exp(-λ)
        probability = 1.0 - math.exp(-expected) if expected > 0 else 0.0

        # 80% Poisson CI（标准差近似）
        std = math.sqrt(expected) if expected > 0 else 0.0
        exp_low = max(0.0, expected - 1.282 * std)
        exp_high = expected + 1.282 * std
        prob_low = 1.0 - math.exp(-exp_low) if exp_low > 0 else 0.0
        prob_high = 1.0 - math.exp(-exp_high) if exp_high > 0 else 0.0

        # 风险等级映射（基于概率）
        risk_level = self._level_from_probability(probability)

        # 解释
        explanation = self._build_explanation(
            product_line=product_line,
            forecast_days=forecast_days,
            historical_total=len(line_records),
            historical_12m=len(dsa_12m),
            historical_3m=len(dsa_3m),
            base_rate=base_rate,
            recent_rate=recent_rate,
            trend_multiplier=trend_multiplier,
            avg_cvss=avg_cvss,
            severity_factor=severity_factor,
            open_cve_pressure=open_cve_pressure,
            expected=expected,
            probability=probability,
        )

        return DSAProductLineForecast(
            product_line=product_line,
            forecast_days=forecast_days,
            historical_dsa_total=len(line_records),
            historical_dsa_12m=len(dsa_12m),
            historical_dsa_3m=len(dsa_3m),
            base_rate_per_month=round(base_rate, 3),
            recent_rate_per_month=round(recent_rate, 3),
            trend_multiplier=round(trend_multiplier, 3),
            severity_factor=round(severity_factor, 3),
            open_cve_pressure=open_cve_pressure,
            expected_dsa_count=round(expected, 3),
            probability=round(probability, 4),
            probability_ci=(round(prob_low, 4), round(prob_high, 4)),
            risk_level=risk_level,
            explanation=explanation,
            forecast_date=self.now,
        )

    def forecast_all(self, forecast_days: int = 30) -> List[DSAProductLineForecast]:
        """预测所有产品线，按概率降序返回"""
        results = [self.forecast_line(line, forecast_days) for line in DELL_PRODUCT_LINES.keys()]
        results.sort(key=lambda f: f.probability, reverse=True)
        return results

    # ── 工具方法 ────────────────────────────────────────────────────────

    @staticmethod
    def _parse_date(s: str) -> Optional[datetime]:
        if not s:
            return None
        s = s[:19].split(".")[0].replace("T", " ")
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(s[:len(fmt)], fmt)
            except ValueError:
                continue
        # 仅 YYYY-MM-DD 部分
        try:
            return datetime.strptime(s[:10], "%Y-%m-%d")
        except ValueError:
            return None

    @staticmethod
    def _level_from_probability(p: float) -> str:
        if p >= 0.80:
            return "CRITICAL"   # 几乎确定会有 DSA
        if p >= 0.50:
            return "HIGH"       # 大概率
        if p >= 0.20:
            return "MEDIUM"     # 中等概率
        if p >= 0.05:
            return "LOW"        # 偶发
        return "MINIMAL"        # 几乎无风险

    @staticmethod
    def _build_explanation(**kw) -> List[str]:
        lines = [
            f"产品线: {kw['product_line']}",
            f"预测周期: 未来 {kw['forecast_days']} 天",
            "",
            "─ 历史数据 ─",
            f"  全量 DSA 数: {kw['historical_total']}",
            f"  过去 12 个月: {kw['historical_12m']} 条 → 月均 {kw['base_rate']:.2f}",
            f"  过去  3 个月: {kw['historical_3m']} 条 → 月均 {kw['recent_rate']:.2f}",
            "",
            "─ 速率因子 ─",
            f"  基线速率 λ_base       = {kw['base_rate']:.3f} /月",
            f"  近期速率 λ_recent     = {kw['recent_rate']:.3f} /月",
            f"  趋势倍数 trend_mult   = {kw['trend_multiplier']:.2f}",
            f"    (近期 / 基线，裁剪到 [0.5, 3.0])",
            "",
            "─ 增益因子 ─",
            f"  近 90 天平均 CVSS    = {kw['avg_cvss']:.2f}",
            f"  严重度因子 severity   = {kw['severity_factor']:.3f}",
            f"  未覆盖 CVE 压力       = {kw['open_cve_pressure']} 条",
            f"    (近 90 天匹配该产品线但尚未进入 DSA 的 CVE)",
            "",
            "─ 输出 ─",
            f"  λ_effective = {kw['base_rate']:.2f} × {kw['trend_multiplier']:.2f} × {kw['severity_factor']:.2f}"
            f" + 0.04 × {kw['open_cve_pressure']}",
            f"  期望 DSA 数 = {kw['expected']:.3f}",
            f"  P(≥1 DSA 在未来 {kw['forecast_days']} 天) = 1 − exp(−{kw['expected']:.3f}) "
            f"= {kw['probability']:.1%}",
        ]
        return lines


__all__ = [
    "DELL_PRODUCT_LINES",
    "classify_dsa",
    "classify_cve_text",
    "DSAProductLineForecast",
    "DSAProductLinePredictor",
]
