"""
Dell 产品线×版本 DSA 概率预测 (risk/dsa_prediction_version.py)

扩展产品线级预测到版本级颗粒度，支持：
- 产品线×版本组合分类
- 版本级 Poisson 速率模型
- 版本级 CVE 压力计算
- 数据稀疏时回退到产品线级速率

数据源
------
- `dell_advisories` 表：历史 DSA（含 title, affected_products, cve_ids, published_date, severity）
- `cves` 表：NVD CVE（含 description, published, cvss, cwe）

算法（版本级 Poisson 速率模型）
--------------------------------
对每个 (产品线, 版本) 组合，计算未来 D 天的概率：

1. **版本级历史速率 λ_version**
   - 取该版本过去 12 个月的 DSA 数 ÷ 12
   - 若数据不足（< 3 条），回退到产品线级速率 × 版本权重

2. **版本级趋势倍数**
   - 近 3 个月速率 / 基线速率
   - 裁剪范围 [0.3, 5.0]（版本级波动更大）

3. **版本级严重度因子**
   - 该版本相关 CVE 平均 CVSS 分

4. **版本级未覆盖 CVE 压力**
   - 匹配该版本但未进入 DSA 的 CVE 数

5. **有效速率 + 概率**
   - λ_effective = λ_version × trend × severity + 0.04 × pressure
   - P(≥1 DSA) = 1 − exp(−λ_effective × D/30)
"""
from __future__ import annotations

import json
import math
import random
import re
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

# 导入产品线分类器和版本提取器
from risk.dsa_prediction import (
    DELL_PRODUCT_LINES,
    classify_dsa,
    classify_cve_text,
    _COMPILED_PATTERNS,
)
from risk.version_extractor import (
    VersionInfo,
    extract_versions_from_dsa,
    normalize_version_key,
    parse_version_key,
)


# ────────────────────────────────────────────────────────────────────────────
# 数据结构
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class DSAVersionForecast:
    """单个产品×版本的 DSA 概率预测结果"""
    product_line: str
    product_name: str           # 清洗后的产品名（如 "Dell ObjectScale"）
    version_key: str            # 规范化版本 key（产品线::产品名::版本号）
    version_display: str        # 显示用：产品名 + 版本号（如 "Dell ObjectScale < 4.1.0.3"）
    version_number: str         # 纯版本号（如 "4.1.0.3"）
    version_qualifier: str      # 版本限定符（""/"<"/"<="）
    forecast_days: int

    # 历史数据
    historical_dsa_total: int
    historical_dsa_12m: int
    historical_dsa_3m: int

    # 速率因子
    base_rate_per_month: float
    recent_rate_per_month: float
    trend_multiplier: float

    # 增益因子
    severity_factor: float
    open_cve_pressure: int

    # 输出
    expected_dsa_count: float
    probability: float
    probability_ci: Tuple[float, float]
    risk_level: str
    explanation: List[str] = field(default_factory=list)

    # 元数据
    is_fallback: bool = False   # 是否使用产品线级回退
    confidence: float = 1.0     # 预测置信度 [0.0, 1.0]
    forecast_date: datetime = field(default_factory=datetime.now)

    # Phase 2 质量保障字段
    vmr_value: Optional[float] = None       # 方差/均值，None 表示样本不足无法计算
    is_poisson_valid: bool = True           # VMR ≤ 1.5 视为泊松假设成立
    ci_method: str = "poisson_analytical"   # "poisson_analytical" | "bootstrap" | "wide_default"
    prior_method: str = "empirical"         # "empirical" | "bayesian_age_adjusted" | "fallback_line"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["forecast_date"] = self.forecast_date.isoformat()
        d["probability_ci"] = list(self.probability_ci)
        return d


# ────────────────────────────────────────────────────────────────────────────
# 版本级预测器
# ────────────────────────────────────────────────────────────────────────────

class DSAVersionPredictor:
    """
    Dell 产品线×版本 DSA 概率预测器

    用法：
        predictor = DSAVersionPredictor("cve_data/cve_database.db")
        results = predictor.forecast_all_versions(forecast_days=30)
        for f in results:
            print(f.product_line, f.version_display, f.probability, f.risk_level)
    """

    def __init__(self, db_path: str, now: Optional[datetime] = None) -> None:
        self.db_path = db_path
        self.now = now or datetime.now()

        # 缓存
        self._dsa_records: Optional[List[Dict[str, Any]]] = None
        self._recent_cves: Optional[List[Dict[str, Any]]] = None
        self._dsa_cve_set: Optional[Set[str]] = None

        # 版本级索引
        self._version_dsa_index: Optional[Dict[str, List[Dict[str, Any]]]] = None
        self._version_cve_index: Optional[Dict[str, List[Dict[str, Any]]]] = None

        # Phase 2: 共享产品线级 predictor 与逐 forecast_days 缓存
        self._line_predictor = None
        self._line_forecast_cache: Dict[Tuple[str, int], Any] = {}

    # ── 数据加载 ────────────────────────────────────────────────────────

    def _load_dsa_records(self) -> List[Dict[str, Any]]:
        """加载所有 DSA 记录（含产品线和版本分类）"""
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
                affected_products = []
                if data_str:
                    try:
                        d = json.loads(data_str)
                        affected_products = d.get("affected_products", []) or []
                        ap = affected_products
                        affected_text = " ".join(
                            (p.get("name", "") + " " + p.get("model", ""))
                            for p in ap if isinstance(p, dict)
                        )
                        severity = (d.get("severity") or "").upper()
                    except (json.JSONDecodeError, TypeError):
                        pass

                # 产品线分类
                lines = classify_dsa(title or "", affected_text)

                # 版本提取
                versions = extract_versions_from_dsa(title or "", affected_products, lines)

                records.append({
                    "title": title or "",
                    "cve_ids": [c for c in re.split(r"[,\s]+", (cve_ids_str or "").strip()) if c.startswith("CVE-")],
                    "published": pub_dt,
                    "severity": severity,
                    "product_lines": lines,
                    "versions": versions,  # List[VersionInfo]
                })
        finally:
            conn.close()

        self._dsa_records = records
        return records

    def _load_recent_cves(self, days: int = 90) -> List[Dict[str, Any]]:
        """加载最近 N 天 CVE（用于压力 + 严重度因子计算）"""
        if self._recent_cves is not None:
            return self._recent_cves

        cutoff = self.now - timedelta(days=days)
        cutoff_str = cutoff.strftime("%Y-%m-%d")

        # 预筛选关键词
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
                        # 本项目 cves 表 data 是预解析过的扁平结构：description / cvss_score 都在顶层
                        desc = d.get("description", "") or ""
                        if not desc:
                            # 兜底：NVD 嵌套结构（兼容遗留数据）
                            cve_obj = d.get("cve", d)
                            for item in cve_obj.get("descriptions", []) or []:
                                if isinstance(item, dict) and item.get("lang") == "en":
                                    desc = item.get("value", "")
                                    break
                        # CVSS 分数：先取顶层 cvss_score
                        s = d.get("cvss_score")
                        if s is not None:
                            try:
                                cvss = float(s)
                            except (TypeError, ValueError):
                                cvss = 0.0
                        # 兜底：NVD 嵌套 metrics
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

                # 提取版本信息
                product_lines = classify_cve_text(desc)
                versions = []
                for line in product_lines:
                    from risk.version_extractor import extract_versions_from_text
                    versions.extend(extract_versions_from_text(desc, line))

                records.append({
                    "cve_id": cve_id,
                    "description": desc,
                    "published": pub_dt,
                    "cvss": cvss,
                    "product_lines": product_lines,
                    "versions": versions,  # List[VersionInfo]
                })
        finally:
            conn.close()

        self._recent_cves = records
        return records

    def _load_dsa_cve_set(self) -> Set[str]:
        """加载所有已被 DSA 引用的 CVE-ID 集合"""
        if self._dsa_cve_set is not None:
            return self._dsa_cve_set
        cve_set: Set[str] = set()
        for r in self._load_dsa_records():
            for c in r["cve_ids"]:
                cve_set.add(c)
        self._dsa_cve_set = cve_set
        return cve_set

    def _build_version_dsa_index(self) -> Dict[str, List[Dict[str, Any]]]:
        """构建 {版本key: [DSA记录]} 倒排索引"""
        if self._version_dsa_index is not None:
            return self._version_dsa_index

        index: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for dsa in self._load_dsa_records():
            for version_info in dsa["versions"]:
                key = normalize_version_key(version_info)
                index[key].append(dsa)

        self._version_dsa_index = dict(index)
        return self._version_dsa_index

    def _build_version_cve_index(self) -> Dict[str, List[Dict[str, Any]]]:
        """构建 {版本key: [CVE记录]} 倒排索引"""
        if self._version_cve_index is not None:
            return self._version_cve_index

        index: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for cve in self._load_recent_cves(days=90):
            for version_info in cve["versions"]:
                key = normalize_version_key(version_info)
                index[key].append(cve)

        self._version_cve_index = dict(index)
        return self._version_cve_index

    # ── Phase 2 质量保障辅助方法 ────────────────────────────────────────

    def _get_monthly_dsa_counts(self, version_key: str, months: int = 12) -> List[int]:
        """获取版本最近 N 个月的月度 DSA 数量（按 30 天/月近似分桶，不依赖日历月）"""
        version_dsa_index = self._build_version_dsa_index()
        version_dsas = version_dsa_index.get(version_key, [])
        counts = [0] * months
        cutoff = self.now - timedelta(days=30 * months)
        for dsa in version_dsas:
            pub = dsa["published"]
            if pub < cutoff or pub > self.now:
                continue
            month_idx = (self.now - pub).days // 30
            if 0 <= month_idx < months:
                counts[month_idx] += 1
        return counts

    @staticmethod
    def _check_version_vmr(monthly_counts: List[int]) -> Tuple[Optional[float], bool]:
        """
        VMR = 方差 / 均值。返回 (vmr, is_poisson_valid)。
        - 样本 < 6 月：(None, False)
        - 月均 < 0.1（几乎全零）：(None, False)
        - VMR ≤ 1.5：(vmr, True)
        - VMR > 1.5：(vmr, False)（过度离散，泊松假设失效）
        """
        if len(monthly_counts) < 6:
            return None, False
        n = len(monthly_counts)
        mean = sum(monthly_counts) / n
        if mean < 0.1:
            return None, False
        variance = sum((c - mean) ** 2 for c in monthly_counts) / n
        vmr = variance / mean
        return round(vmr, 3), vmr <= 1.5

    @staticmethod
    def _bayesian_version_prior(
        lambda_product_line: float,
        version_first_seen_months_ago: int,
    ) -> float:
        """
        零历史版本的先验 λ，按版本年龄缩放产品线基线：
        - 0–6 月：× 0.3（新版本风险尚未充分暴露）
        - 6–24 月：线性插值 0.3 → 1.0
        - 24 月+：× 1.0
        """
        age = max(0, version_first_seen_months_ago)
        if age <= 6:
            factor = 0.3
        elif age >= 24:
            factor = 1.0
        else:
            factor = 0.3 + (1.0 - 0.3) * (age - 6) / (24 - 6)
        return lambda_product_line * factor

    @staticmethod
    def _bootstrap_version_ci(
        monthly_counts: List[int],
        forecast_days: int,
        n_bootstrap: int = 500,
        ci_level: float = 0.80,
        seed: int = 42,
    ) -> Tuple[float, float]:
        """
        Bootstrap 估计 P(≥1 DSA in forecast_days) 的 CI。
        采用对月度计数有放回重抽样 → 计算样本均值 → 转概率。
        seed 固定以保证同一查询多次调用结果一致。
        """
        n = len(monthly_counts)
        if n < 3:
            return 0.0, 1.0
        rng = random.Random(seed)
        months_in_window = forecast_days / 30.0
        probs: List[float] = []
        for _ in range(n_bootstrap):
            sample_mean = sum(monthly_counts[rng.randrange(n)] for _ in range(n)) / n
            expected = sample_mean * months_in_window
            probs.append(1.0 - math.exp(-expected) if expected > 0 else 0.0)
        probs.sort()
        alpha = (1 - ci_level) / 2
        low_idx = max(0, int(alpha * n_bootstrap))
        high_idx = min(n_bootstrap - 1, int((1 - alpha) * n_bootstrap) - 1)
        return probs[low_idx], probs[high_idx]

    def _version_first_seen_months_ago(self, version_key: str) -> int:
        """该版本最早一条 DSA 距今几个月（用于 Bayesian 先验）"""
        version_dsa_index = self._build_version_dsa_index()
        version_dsas = version_dsa_index.get(version_key, [])
        if not version_dsas:
            return 0
        earliest = min(d["published"] for d in version_dsas)
        return max(0, (self.now - earliest).days // 30)

    # ── 预测主流程 ──────────────────────────────────────────────────────

    def forecast_version(self, version_key: str, forecast_days: int = 30) -> DSAVersionForecast:
        """对单个产品×版本做预测（集成 Phase 2 三件套：VMR / Bayesian / Bootstrap）"""
        product_line, product_name, version_number = parse_version_key(version_key)

        # 获取该版本的历史 DSA
        version_dsa_index = self._build_version_dsa_index()
        version_dsas = version_dsa_index.get(version_key, [])

        # 从历史 DSA 中找出该版本的限定符（取第一个 VersionInfo 的 qualifier）
        version_qualifier = ""
        for dsa in version_dsas:
            for v in dsa.get("versions", []):
                if (v.product_line == product_line and
                    v.product_name == product_name and
                    v.version_number == version_number):
                    version_qualifier = v.version_qualifier
                    break
            if version_qualifier:
                break

        # 构造显示名
        if version_qualifier:
            version_display = f"{product_name} {version_qualifier} {version_number}"
        else:
            version_display = f"{product_name} {version_number}"

        # 时间窗口
        cutoff_12m = self.now - timedelta(days=365)
        cutoff_3m = self.now - timedelta(days=90)
        dsa_12m = [r for r in version_dsas if r["published"] >= cutoff_12m]
        dsa_3m = [r for r in version_dsas if r["published"] >= cutoff_3m]

        # 月度分布（用于 VMR / Bootstrap）
        monthly_counts = self._get_monthly_dsa_counts(version_key, months=12)

        # ── 数据稀疏 / VMR 双重判定 ──
        is_sparse = len(version_dsas) < 3
        vmr_value, is_poisson_valid = self._check_version_vmr(monthly_counts)
        # VMR 判定仅对样本 ≥ 3 的版本生效；样本不足直接走稀疏分支
        force_fallback_by_vmr = (not is_sparse) and (vmr_value is not None) and (not is_poisson_valid)
        is_fallback = is_sparse or force_fallback_by_vmr

        # 置信度：稀疏 0.6；VMR 失败 0.4；正常 1.0
        if is_sparse:
            confidence = 0.6
        elif force_fallback_by_vmr:
            confidence = 0.4
        else:
            confidence = 1.0

        prior_method = "empirical"

        if is_fallback:
            # 回退：使用产品线级速率 × 版本权重（或零历史时用 Bayesian 先验）
            if self._line_predictor is None:
                from risk.dsa_prediction import DSAProductLinePredictor
                self._line_predictor = DSAProductLinePredictor(self.db_path, self.now)
            line_predictor = self._line_predictor

            cache_key = (product_line, forecast_days)
            line_forecast = self._line_forecast_cache.get(cache_key)
            if line_forecast is None:
                line_forecast = line_predictor.forecast_line(product_line, forecast_days)
                self._line_forecast_cache[cache_key] = line_forecast

            line_all_versions = [k for k in version_dsa_index.keys() if k.startswith(f"{product_line}::")]
            total_line_dsas = sum(len(version_dsa_index.get(k, [])) for k in line_all_versions)

            if len(version_dsas) == 0:
                # 零历史 → Bayesian 年龄调整先验，替换原 0.04 / 0.1 硬编码
                age_months = self._version_first_seen_months_ago(version_key)
                prior_lambda = self._bayesian_version_prior(
                    line_forecast.base_rate_per_month, age_months
                )
                base_rate = prior_lambda
                recent_rate = prior_lambda
                prior_method = "bayesian_age_adjusted"
            else:
                # 1~2 条历史 或 VMR 失败 → 产品线级速率 × 占比
                version_weight = (
                    len(version_dsas) / total_line_dsas
                    if total_line_dsas > 0 else 0.1
                )
                base_rate = line_forecast.base_rate_per_month * version_weight
                recent_rate = line_forecast.recent_rate_per_month * version_weight
                prior_method = "fallback_line"
            trend_multiplier = line_forecast.trend_multiplier
        else:
            # 正常计算：版本级速率
            base_rate = len(dsa_12m) / 12.0
            recent_rate = len(dsa_3m) / 3.0
            if base_rate < 0.05:
                trend_multiplier = 1.0
            else:
                raw_ratio = recent_rate / base_rate
                trend_multiplier = max(0.3, min(5.0, raw_ratio))

        # 严重度因子
        version_cve_index = self._build_version_cve_index()
        version_cves = version_cve_index.get(version_key, [])
        if version_cves:
            avg_cvss = sum(c["cvss"] for c in version_cves) / len(version_cves)
            severity_factor = max(1.0, min(1.5, 1.0 + 0.5 * (avg_cvss / 10.0)))
        else:
            avg_cvss = 0.0
            severity_factor = 1.0

        # 未覆盖 CVE 压力
        dsa_cve_set = self._load_dsa_cve_set()
        open_cves = [c for c in version_cves if c["cve_id"] not in dsa_cve_set]
        open_cve_pressure = len(open_cves)

        # 有效速率 + 概率
        lambda_effective = (
            base_rate * trend_multiplier * severity_factor
            + 0.04 * open_cve_pressure
        )
        expected = lambda_effective * (forecast_days / 30.0)
        probability = 1.0 - math.exp(-expected) if expected > 0 else 0.0

        # ── CI 选择：Bootstrap 优先，回退 Poisson 解析 ──
        ci_method = "poisson_analytical"
        if (not is_fallback) and (vmr_value is not None) and is_poisson_valid:
            # 高质量样本 → Bootstrap
            prob_low, prob_high = self._bootstrap_version_ci(
                monthly_counts, forecast_days
            )
            # Bootstrap 是基于历史 base_rate 的，需要把当前的 trend × severity × pressure 校准回去
            # 简化处理：用 (probability / base_prob) 比例缩放 CI
            base_expected = (sum(monthly_counts) / 12.0) * (forecast_days / 30.0)
            base_prob = 1.0 - math.exp(-base_expected) if base_expected > 0 else 0.0
            if base_prob > 0:
                scale = probability / base_prob
                prob_low = min(1.0, prob_low * scale)
                prob_high = min(1.0, prob_high * scale)
            # 保证概率在 CI 内
            prob_low = min(prob_low, probability)
            prob_high = max(prob_high, probability)
            ci_method = "bootstrap"
        else:
            # 退回 Poisson 解析（与原实现一致）
            std = math.sqrt(expected) if expected > 0 else 0.0
            exp_low = max(0.0, expected - 1.282 * std)
            exp_high = expected + 1.282 * std
            prob_low = 1.0 - math.exp(-exp_low) if exp_low > 0 else 0.0
            prob_high = 1.0 - math.exp(-exp_high) if exp_high > 0 else 0.0

        # 风险等级
        risk_level = self._level_from_probability(probability)

        explanation = self._build_explanation(
            product_line=product_line,
            version_display=version_display,
            forecast_days=forecast_days,
            historical_total=len(version_dsas),
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
            is_fallback=is_fallback,
            vmr_value=vmr_value,
            is_poisson_valid=is_poisson_valid,
            ci_method=ci_method,
            prior_method=prior_method,
            force_fallback_by_vmr=force_fallback_by_vmr,
        )

        return DSAVersionForecast(
            product_line=product_line,
            product_name=product_name,
            version_key=version_key,
            version_display=version_display,
            version_number=version_number,
            version_qualifier=version_qualifier,
            forecast_days=forecast_days,
            historical_dsa_total=len(version_dsas),
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
            is_fallback=is_fallback,
            confidence=confidence,
            forecast_date=self.now,
            vmr_value=vmr_value,
            is_poisson_valid=is_poisson_valid,
            ci_method=ci_method,
            prior_method=prior_method,
        )

    def forecast_all_versions(self, forecast_days: int = 30, min_confidence: float = 0.5) -> List[DSAVersionForecast]:
        """预测所有版本，按概率降序返回"""
        version_dsa_index = self._build_version_dsa_index()
        results = []

        for version_key in version_dsa_index.keys():
            forecast = self.forecast_version(version_key, forecast_days)
            if forecast.confidence >= min_confidence:
                results.append(forecast)

        results.sort(key=lambda f: f.probability, reverse=True)
        return results

    def forecast_by_product_line(self, product_line: str, forecast_days: int = 30) -> List[DSAVersionForecast]:
        """预测某产品线下的所有版本"""
        version_dsa_index = self._build_version_dsa_index()
        results = []

        for version_key in version_dsa_index.keys():
            if version_key.startswith(f"{product_line}::"):
                results.append(self.forecast_version(version_key, forecast_days))

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
        try:
            return datetime.strptime(s[:10], "%Y-%m-%d")
        except ValueError:
            return None

    @staticmethod
    def _level_from_probability(p: float) -> str:
        if p >= 0.80:
            return "CRITICAL"
        if p >= 0.50:
            return "HIGH"
        if p >= 0.20:
            return "MEDIUM"
        if p >= 0.05:
            return "LOW"
        return "MINIMAL"

    @staticmethod
    def _build_explanation(**kw) -> List[str]:
        lines = [
            f"产品线: {kw['product_line']}",
            f"版本: {kw['version_display']}",
            f"预测周期: 未来 {kw['forecast_days']} 天",
        ]

        # ── Phase 2 标注（最显眼位置）──
        vmr_value = kw.get('vmr_value')
        if vmr_value is not None:
            tag = "✅ 泊松假设成立" if kw.get('is_poisson_valid') else "⚠️ 过度离散"
            lines.append("")
            lines.append(f"{tag}：VMR = {vmr_value} (阈值 1.5)")
        if kw.get('force_fallback_by_vmr'):
            lines.append("[过度离散：已回退到产品线级别]")
        if kw.get('is_fallback'):
            lines.append("")
            lines.append("⚠️ 数据稀疏警告：该版本历史数据不足，使用产品线级速率回退")
        if kw.get('prior_method') == 'bayesian_age_adjusted':
            lines.append("[零历史版本：采用 Bayesian 年龄调整先验]")
        if kw.get('ci_method') == 'bootstrap':
            lines.append("[CI 方法：Bootstrap 500 次抽样]")
        else:
            lines.append("[CI 方法：Poisson 解析近似]")

        lines.extend([
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
            f"    (近期 / 基线，裁剪到 [0.3, 5.0])",
            "",
            "─ 增益因子 ─",
            f"  近 90 天平均 CVSS    = {kw['avg_cvss']:.2f}",
            f"  严重度因子 severity   = {kw['severity_factor']:.3f}",
            f"  未覆盖 CVE 压力       = {kw['open_cve_pressure']} 条",
            f"    (近 90 天匹配该版本但尚未进入 DSA 的 CVE)",
            "",
            "─ 输出 ─",
            f"  λ_effective = {kw['base_rate']:.2f} × {kw['trend_multiplier']:.2f} × {kw['severity_factor']:.2f}"
            f" + 0.04 × {kw['open_cve_pressure']}",
            f"  期望 DSA 数 = {kw['expected']:.3f}",
            f"  P(≥1 DSA 在未来 {kw['forecast_days']} 天) = 1 − exp(−{kw['expected']:.3f}) "
            f"= {kw['probability']:.1%}",
        ])
        return lines


__all__ = [
    "DSAVersionForecast",
    "DSAVersionPredictor",
]
