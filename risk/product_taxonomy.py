"""
Dell 产品分类与别名映射 (risk/product_taxonomy.py)

集中维护三类映射，解决产品风险分析中的分类问题：

1. **PRODUCT_NOISE_PHRASES**：抽取噪声短语（如 "an IAM"），应被丢弃或回退到标题
2. **PRODUCT_TO_LINE**：真实产品名 → 所属产品线（如 Color Management → 客户端外设）
3. **resolve_product_line()**：综合判定一个产品名归属哪条产品线

设计原则
--------
- 纯数据 + 纯函数，零外部依赖，可独立单元测试
- 与 [risk/dsa_prediction.py](risk/dsa_prediction.py) 的 DELL_PRODUCT_LINES 互补：
  前者是 DSA/CVE 文本分类（粗粒度），这里补充"已知但未被正则覆盖"的产品
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional


# ────────────────────────────────────────────────────────────────────────────
# 1. 抽取噪声短语（非产品名，应丢弃）
# ────────────────────────────────────────────────────────────────────────────
# 这些字符串出现在 affected_products.name 里，但其实是从公告标题/正文里
# 误抓的语法片段（如 "Security Update for an IAM Vulnerability" 抓出 "an IAM"）。
PRODUCT_NOISE_PHRASES = frozenset({
    "an iam",
    "a iam",
    "iam",
    "an iam vulnerability",
    "multiple vulnerabilities",
    "a vulnerability",
    "an vulnerability",
    "security update",
    "multiple security vulnerabilities",
})

# 以冠词 / 介词开头的短语极可能是误抓（产品名几乎不会以 "an "/"a " 开头）
_NOISE_PREFIX = re.compile(r"^(an?|the|for|to|of|in)\s+", re.IGNORECASE)


def is_noise_product(name: str) -> bool:
    """判断一个 affected_products.name 是否为抽取噪声（非真实产品名）"""
    if not name:
        return True
    low = name.strip().lower()
    if low in PRODUCT_NOISE_PHRASES:
        return True
    # "an IAM" / "a vulnerability" 这种冠词开头 + 短词
    if _NOISE_PREFIX.match(name) and len(name.split()) <= 3:
        return True
    return False


# ────────────────────────────────────────────────────────────────────────────
# 2. 真实产品 → 产品线映射（补充 DELL_PRODUCT_LINES 未覆盖的）
# ────────────────────────────────────────────────────────────────────────────
# key 用小写正则片段，value 为 (产品线展示名, 说明)
# 这些是"合法产品名但 DELL_PRODUCT_LINES 正则没收录"的条目。
PRODUCT_TO_LINE: Dict[str, str] = {
    # 客户端 / 显示器外设（Client Solutions Group）
    r"color\s*management\s*software": "Client BIOS / Precision / Latitude (客户端)",
    r"display\s*manager": "Client BIOS / Precision / Latitude (客户端)",
    r"\bultrasharp\b": "Client BIOS / Precision / Latitude (客户端)",
    r"\bwyse\b": "Client BIOS / Precision / Latitude (客户端)",
    r"peripheral\s*manager": "Client BIOS / Precision / Latitude (客户端)",
    r"\bdisplay\b.*\bmonitor\b": "Client BIOS / Precision / Latitude (客户端)",
    r"pair\s*&\s*setup": "Client BIOS / Precision / Latitude (客户端)",
    r"alienware": "Client BIOS / Precision / Latitude (客户端)",
    # 管理 / 安全功能模块
    # 注意：不收录单独的 "IAM" —— 它是身份访问管理功能，不是产品。
    # "an IAM" 这类是噪声，由 clean_product_name 回退到标题真实产品（如 ECS）。
    r"identity\s*and\s*access\s*management": "CloudIQ / DataIQ (管理)",
    r"secure\s*connect\s*gateway": "Command|Update (管理)",
    r"\bsupportassist\b": "Command|Update (管理)",
    # 存储补充
    r"\binsightiq\b": "PowerScale / Isilon (NAS)",
    r"power\s*scale|\bisilon\b|\bonefs\b": "PowerScale / Isilon (NAS)",
    r"\bunisphere\b": "PowerMax/VMAX (主存储)",
    r"\bstorage\s*center\b": "SC / Compellent (主存储)",
    # 网络补充
    r"\bsmartfabric\b": "Networking OS10 / SONiC (网络)",
    r"\bos6\b|\bos9\b": "Networking OS10 / SONiC (网络)",
}

_COMPILED_PRODUCT_TO_LINE = [
    (re.compile(pat, re.IGNORECASE), line) for pat, line in PRODUCT_TO_LINE.items()
]


def resolve_product_line(product_name: str, dsa_title: str = "") -> Optional[str]:
    """
    判定产品名归属哪条产品线。

    优先级：
    1. PRODUCT_TO_LINE 别名映射（精确补充）
    2. 从 DSA 标题里推断（如 "Dell ECS Security Update..." → ECS）

    返回产品线展示名，无法判定返回 None。
    """
    if not product_name:
        return None

    # 1. 别名映射
    for pat, line in _COMPILED_PRODUCT_TO_LINE:
        if pat.search(product_name):
            return line

    # 2. 从产品名本身或标题推断（用 dsa_prediction 的分类器，惰性导入避免循环依赖）
    try:
        from risk.dsa_prediction import classify_dsa
        # 先用产品名自身分类（"Dell ECS" → ECS 产品线）
        lines = classify_dsa(product_name, product_name)
        if lines:
            return lines[0]
        # 再用标题补充
        if dsa_title:
            lines = classify_dsa(dsa_title, product_name)
            if lines:
                return lines[0]
    except Exception:
        pass

    return None


def clean_product_name(name: str, dsa_title: str = "") -> Optional[str]:
    """
    清洗产品名：噪声短语回退到标题里的真实产品，合法名原样返回。

    返回 None 表示该名称应被丢弃（无法恢复出有意义的产品）。
    """
    if is_noise_product(name):
        # 噪声 → 尝试从标题恢复 "Dell XXX"，在停用词处截断
        if dsa_title:
            # 在 "Security Update"/"for"/"Multiple" 等停用词前截断，只保留产品名
            head = re.split(
                r"\s+(?:Security\s+Update|Update|for|Multiple|Vulnerabilit)",
                dsa_title,
                maxsplit=1,
                flags=re.IGNORECASE,
            )[0]
            m = re.search(
                r"Dell\s+(?:EMC\s+)?([A-Za-z][A-Za-z0-9]*(?:\s+[A-Za-z0-9]+){0,2})",
                head,
            )
            if m:
                recovered = m.group(0).strip()
                if not is_noise_product(recovered):
                    return recovered
        return None
    return name


__all__ = [
    "PRODUCT_NOISE_PHRASES",
    "PRODUCT_TO_LINE",
    "is_noise_product",
    "resolve_product_line",
    "clean_product_name",
]
