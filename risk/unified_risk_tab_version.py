"""
智能预测标签页 - 版本级扩展模块

为 unified_risk_tab.py 提供版本级 DSA 预测功能：
- 两级树结构（产品线 → 版本）
- 版本级详情面板
- 版本级报告导出
"""
from __future__ import annotations

import threading
import tkinter as tk
from tkinter import ttk
from typing import Any, Dict, List, Optional


def create_version_tree(parent_frame, gui) -> ttk.Treeview:
    """
    创建版本级两级树结构

    结构：
    ├─ 产品线 A (聚合概率)
    │  ├─ 版本 A1 (版本级概率)
    │  └─ 版本 A2
    └─ 产品线 B
       └─ 版本 B1
    """
    tree = ttk.Treeview(
        parent_frame,
        columns=("name", "prob", "level", "confidence"),
        show="tree headings",
        height=12
    )
    tree.heading("#0", text="")
    tree.heading("name", text="产品线/版本")
    tree.heading("prob", text="概率")
    tree.heading("level", text="等级")
    tree.heading("confidence", text="置信度")

    tree.column("#0", width=20)
    tree.column("name", width=180, anchor="w")
    tree.column("prob", width=55, anchor="center")
    tree.column("level", width=70, anchor="center")
    tree.column("confidence", width=60, anchor="center")

    # 等级颜色 tag
    tree.tag_configure("CRITICAL", background="#fdedec", foreground="#c0392b")
    tree.tag_configure("HIGH",     background="#fef5e7", foreground="#d35400")
    tree.tag_configure("MEDIUM",   background="#fef9e7", foreground="#b7950b")
    tree.tag_configure("LOW",      background="#eaf2f8", foreground="#2980b9")
    tree.tag_configure("MINIMAL",  background="#f4f6f6", foreground="#7f8c8d")

    # 产品线节点样式（加粗）
    tree.tag_configure("product_line", font=("Microsoft YaHei", 9, "bold"))

    # 版本节点样式（缩进）
    tree.tag_configure("version", font=("Microsoft YaHei", 8))

    return tree


def run_version_prediction(gui, forecast_days: int = 30) -> None:
    """运行版本级 DSA 预测（后台线程）"""
    def _worker():
        try:
            from risk.dsa_prediction_version import DSAVersionPredictor
            from risk.dsa_prediction import DSAProductLinePredictor

            db_path = str(gui.data_dir / "cve_database.db")
            gui.root.after(0, lambda: gui._ur_dsa_summary_var.set(
                "正在计算版本级预测（扫描 DSA + CVE + 版本信息）..."))

            # 版本级预测
            version_predictor = DSAVersionPredictor(db_path)
            version_results = version_predictor.forecast_all_versions(
                forecast_days=forecast_days,
                min_confidence=0.5
            )

            # 产品线级预测（用于聚合）
            line_predictor = DSAProductLinePredictor(db_path)
            line_results = line_predictor.forecast_all(forecast_days=forecast_days)

            # 存储结果
            gui._ur_version_results = version_results
            gui._ur_line_results = line_results

            gui.root.after(0, lambda: render_version_tree(
                gui, version_results, line_results, forecast_days))
        except Exception as e:
            import traceback
            err = f"{str(e)}\n{traceback.format_exc()}"
            gui.root.after(0, lambda: gui._ur_dsa_summary_var.set(
                f"版本级预测失败: {str(e)}"))

    threading.Thread(target=_worker, daemon=True).start()


def render_version_tree(gui, version_results, line_results, days: int) -> None:
    """渲染版本级两级树"""
    tree = gui._ur_dsa_tree
    for item in tree.get_children():
        tree.delete(item)

    if not version_results and not line_results:
        gui._ur_dsa_summary_var.set("无可用数据")
        return

    # 按产品线分组版本
    from collections import defaultdict
    line_versions: Dict[str, List[Any]] = defaultdict(list)
    for v in version_results:
        line_versions[v.product_line].append(v)

    # 构建产品线字典（用于快速查找）
    line_dict = {r.product_line: r for r in line_results}

    # 渲染树
    for line_name in sorted(line_versions.keys()):
        line_forecast = line_dict.get(line_name)
        if line_forecast is None:
            continue

        # 产品线节点（父节点）
        prob_str = f"{line_forecast.probability:.0%}"
        parent_id = tree.insert(
            "", tk.END,
            text="▶",
            values=(line_name, prob_str, line_forecast.risk_level, "100%"),
            tags=("product_line", line_forecast.risk_level),
            open=False  # 默认折叠
        )

        # 版本节点（子节点）
        versions = sorted(line_versions[line_name],
                         key=lambda v: v.probability, reverse=True)
        for v in versions:
            prob_str = f"{v.probability:.0%}"
            conf_str = f"{v.confidence:.0%}"
            tree.insert(
                parent_id, tk.END,
                text="  ",
                values=(f"  {v.version_display}", prob_str, v.risk_level, conf_str),
                tags=("version", v.risk_level)
            )

    # 更新摘要
    high_count = sum(1 for r in line_results if r.risk_level in ("CRITICAL", "HIGH"))
    total_versions = len(version_results)

    gui._ur_dsa_summary_var.set(
        f"未来 {days} 天 · {len(line_results)} 条产品线 · "
        f"{total_versions} 个版本 · {high_count} 条高风险"
    )

    # 默认选中第一个产品线
    children = tree.get_children()
    if children:
        tree.selection_set(children[0])
        on_version_tree_select(gui)


def on_version_tree_select(gui) -> None:
    """选中节点后展示详情"""
    sel = gui._ur_dsa_tree.selection()
    if not sel:
        return

    item = gui._ur_dsa_tree.item(sel[0])
    values = item["values"]
    if not values:
        return

    name = values[0].strip()

    # 判断是产品线还是版本
    is_version = "version" in item["tags"]

    txt = gui._ur_dsa_explain_text
    txt.config(state=tk.NORMAL)
    txt.delete("1.0", tk.END)

    if is_version:
        # 显示版本级详情
        forecast = next((r for r in gui._ur_version_results
                        if r.version_display == name), None)
        if forecast:
            lines = list(forecast.explanation)
            lines.extend([
                "",
                "─ 概率与置信区间 ─",
                f"  P(≥1 DSA) = {forecast.probability:.1%}",
                f"  80% CI    = [{forecast.probability_ci[0]:.1%}, {forecast.probability_ci[1]:.1%}]",
                f"  风险等级   = {forecast.risk_level}",
                f"  预测置信度 = {forecast.confidence:.0%}",
            ])
            if forecast.is_fallback:
                lines.extend([
                    "",
                    "⚠️ 注意：该版本使用产品线级速率回退（历史数据不足）"
                ])
            txt.insert("1.0", "\n".join(lines))
    else:
        # 显示产品线级详情
        forecast = next((r for r in gui._ur_line_results
                        if r.product_line == name), None)
        if forecast:
            lines = list(forecast.explanation)
            lines.extend([
                "",
                "─ 概率与置信区间 ─",
                f"  P(≥1 DSA) = {forecast.probability:.1%}",
                f"  80% CI    = [{forecast.probability_ci[0]:.1%}, {forecast.probability_ci[1]:.1%}]",
                f"  风险等级   = {forecast.risk_level}",
            ])
            txt.insert("1.0", "\n".join(lines))

    txt.config(state=tk.DISABLED)


def export_version_report(gui, file_path: str, fmt: str = "md") -> None:
    """导出版本级报告"""
    if not hasattr(gui, '_ur_version_results') or not gui._ur_version_results:
        return

    from datetime import datetime
    from collections import defaultdict

    version_results = gui._ur_version_results
    line_results = gui._ur_line_results

    # 按产品线分组
    line_versions: Dict[str, List[Any]] = defaultdict(list)
    for v in version_results:
        line_versions[v.product_line].append(v)

    # 生成 Markdown 报告
    lines = [
        "# Dell 产品线×版本 DSA 风险预测报告",
        "",
        f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**预测周期**: 未来 {version_results[0].forecast_days if version_results else 30} 天",
        f"**产品线数**: {len(line_results)}",
        f"**版本数**: {len(version_results)}",
        "",
        "---",
        "",
        "## 📊 执行摘要",
        "",
    ]

    # 风险等级统计
    from collections import Counter
    risk_counts = Counter(r.risk_level for r in line_results)
    lines.extend([
        "### 产品线风险分布",
        "",
        f"- 🔴 CRITICAL: {risk_counts.get('CRITICAL', 0)} 条",
        f"- 🟠 HIGH: {risk_counts.get('HIGH', 0)} 条",
        f"- 🟡 MEDIUM: {risk_counts.get('MEDIUM', 0)} 条",
        f"- 🔵 LOW: {risk_counts.get('LOW', 0)} 条",
        f"- ⚪ MINIMAL: {risk_counts.get('MINIMAL', 0)} 条",
        "",
    ])

    # 按产品线输出
    lines.extend([
        "---",
        "",
        "## 📋 产品线详细预测",
        "",
    ])

    for line_name in sorted(line_versions.keys()):
        line_forecast = next((r for r in line_results if r.product_line == line_name), None)
        if not line_forecast:
            continue

        versions = sorted(line_versions[line_name],
                         key=lambda v: v.probability, reverse=True)

        lines.extend([
            f"### {line_name}",
            "",
            f"**产品线级概率**: {line_forecast.probability:.1%} ({line_forecast.risk_level})",
            f"**历史 DSA**: {line_forecast.historical_dsa_total} 条（12个月: {line_forecast.historical_dsa_12m}, 3个月: {line_forecast.historical_dsa_3m}）",
            "",
            "#### 版本级预测",
            "",
            "| 版本 | 概率 | 等级 | 置信度 | 历史DSA | 未覆盖CVE |",
            "|------|------|------|--------|---------|-----------|",
        ])

        for v in versions:
            lines.append(
                f"| {v.version_display} | {v.probability:.1%} | {v.risk_level} | "
                f"{v.confidence:.0%} | {v.historical_dsa_total} | {v.open_cve_pressure} |"
            )

        lines.extend(["", ""])

    # 写入文件
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))


__all__ = [
    "create_version_tree",
    "run_version_prediction",
    "render_version_tree",
    "on_version_tree_select",
    "export_version_report",
]
