"""
智能预测标签页模块

布局设计（上下两区）：
┌─────────────────────────────────────────────────────────────────────┐
│ 工具栏: [全量分析] [导出]  状态信息                                   │
├──────────────┬──────────────────────────────────────────────────────┤
│ 产品风险排名  │  上区：知识图谱可视化（占主要空间） + 分析详情侧栏     │
│ (Treeview)   │                                                      │
├──────────────┼──────────────────────────────────────────────────────┤
│ 图谱统计     │  下区：预防性维护建议（卡片列表）                      │
│ + 算法摘要   │                                                      │
└──────────────┴──────────────────────────────────────────────────────┘
"""
from __future__ import annotations

import threading
import tkinter as tk
from tkinter import ttk, filedialog
from pathlib import Path
from typing import Any, Dict, List, Optional


PRIORITY_COLORS = {
    "P0": "#c0392b",
    "P1": "#d35400",
    "P2": "#f39c12",
    "P3": "#2980b9",
    "P4": "#7f8c8d",
}

PRIORITY_BG = {
    "P0": "#fdedec",
    "P1": "#fef5e7",
    "P2": "#fef9e7",
    "P3": "#eaf2f8",
    "P4": "#f2f3f4",
}


def create_unified_risk_view(gui) -> None:
    """构建趋势预测标签页"""
    gui._ur_kg = None
    gui._ur_builder = None
    gui._ur_reports: List[Any] = []
    gui._ur_loaded = False
    gui._ur_dsa_results: List[Any] = []  # Dell 产品线 DSA 预测结果
    gui._ur_micro_assessor = None       # MicrocodeRiskAssessor 缓存实例
    gui._ur_micro_results: List[Any] = []

    root = tk.Frame(gui.unified_risk_frame, bg="#f5f6fa")
    root.pack(fill=tk.BOTH, expand=True)

    # ── 顶部说明 banner（与 Dell / NVD 等其他标签页同款 ℹ️ 提示）──
    info_banner = tk.Frame(root, bg="#d1ecf1", pady=8)
    info_banner.pack(fill=tk.X, padx=0, pady=0)
    tk.Label(
        info_banner,
        text=(
            "ℹ️ 智能预测：基于知识图谱 + Dell DSA 历史 + NVD CVE 压力，"
            "采用 Poisson 速率模型预测产品线/版本/微码级未来风险。"
            "「全量分析」生成知识图谱与产品评分；「产品线DSA预测」按 30/60/90 天给出概率与风险等级。"
        ),
        bg="#d1ecf1",
        fg="#0c5460",
        font=("Microsoft YaHei", 9),
        wraplength=1200,
        justify=tk.LEFT,
    ).pack(padx=10)

    # ── 工具栏 ────────────────────────────────────────────────────────
    toolbar = tk.Frame(root, bg="white", relief=tk.FLAT, bd=0)
    toolbar.pack(fill=tk.X, padx=0, pady=0)
    toolbar_inner = tk.Frame(toolbar, bg="white")
    toolbar_inner.pack(fill=tk.X, padx=12, pady=6)

    tk.Button(toolbar_inner, text="▶ 全量分析", command=lambda: _ur_full_analyze(gui),
              bg="#2c3e50", fg="white", relief=tk.FLAT, cursor="hand2",
              font=("Microsoft YaHei", 9, "bold"), padx=16, pady=5).pack(side=tk.LEFT)

    tk.Button(toolbar_inner, text="🎯 产品线DSA预测", command=lambda: _ur_run_dsa_prediction(gui),
              bg="#8e44ad", fg="white", relief=tk.FLAT, cursor="hand2",
              font=("Microsoft YaHei", 9, "bold"), padx=12, pady=5).pack(side=tk.LEFT, padx=(8, 0))

    tk.Button(toolbar_inner, text="🔬 微码风险", command=lambda: _ur_run_microcode_assess(gui),
              bg="#d35400", fg="white", relief=tk.FLAT, cursor="hand2",
              font=("Microsoft YaHei", 9, "bold"), padx=12, pady=5).pack(side=tk.LEFT, padx=(8, 0))

    tk.Button(toolbar_inner, text="导出报告", command=lambda: _ur_export(gui, "md"),
              bg="#27ae60", fg="white", relief=tk.FLAT, cursor="hand2",
              font=("Microsoft YaHei", 9), padx=10, pady=5).pack(side=tk.LEFT, padx=(8, 0))

    # 预测周期选择（30 / 60 / 90 天）
    tk.Label(toolbar_inner, text="  周期:", bg="white", fg="#555",
             font=("Microsoft YaHei", 9)).pack(side=tk.LEFT, padx=(12, 2))
    gui._ur_dsa_days_var = tk.StringVar(value="30")
    for d in ("30", "60", "90"):
        tk.Radiobutton(toolbar_inner, text=f"{d}天", variable=gui._ur_dsa_days_var, value=d,
                       bg="white", fg="#2c3e50", font=("Microsoft YaHei", 9),
                       activebackground="white", selectcolor="white",
                       command=lambda: _ur_run_dsa_prediction(gui) if gui._ur_dsa_results else None
                       ).pack(side=tk.LEFT)

    gui._ur_status_var = tk.StringVar(value="切换到此标签页自动加载分析")
    tk.Label(toolbar_inner, textvariable=gui._ur_status_var, bg="white", fg="#7f8c8d",
             font=("Microsoft YaHei", 8)).pack(side=tk.RIGHT)

    # 分隔线
    tk.Frame(root, bg="#ecf0f1", height=1).pack(fill=tk.X)

    # ── 主体：左右分栏 ───────────────────────────────────────────────
    body = tk.PanedWindow(root, orient=tk.HORIZONTAL, bg="#ecf0f1", sashwidth=4, sashrelief=tk.FLAT)
    body.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

    # ─── 左栏：产品排名 + 统计 + 算法摘要 ────────────────────────────
    left = tk.Frame(body, bg="white")
    body.add(left, minsize=230, width=250)

    left_inner = tk.Frame(left, bg="white")
    left_inner.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

    tk.Label(left_inner, text="产品风险排名", bg="white", fg="#2c3e50",
             font=("Microsoft YaHei", 10, "bold")).pack(anchor="w", pady=(0, 4))

    tree_frame = tk.Frame(left_inner, bg="white")
    tree_frame.pack(fill=tk.BOTH, expand=True)

    gui._ur_tree = ttk.Treeview(tree_frame, columns=("product", "score", "level"),
                                 show="headings", height=14)
    gui._ur_tree.heading("product", text="产品")
    gui._ur_tree.heading("score", text="评分")
    gui._ur_tree.heading("level", text="等级")
    gui._ur_tree.column("product", width=130)
    gui._ur_tree.column("score", width=45, anchor="center")
    gui._ur_tree.column("level", width=65, anchor="center")

    tree_sb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=gui._ur_tree.yview)
    gui._ur_tree.configure(yscrollcommand=tree_sb.set)
    gui._ur_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    tree_sb.pack(side=tk.RIGHT, fill=tk.Y)
    gui._ur_tree.bind("<<TreeviewSelect>>", lambda e: _ur_on_select(gui))

    # 统计
    tk.Frame(left_inner, bg="#ecf0f1", height=1).pack(fill=tk.X, pady=6)
    gui._ur_stats_var = tk.StringVar(value="尚未加载")
    tk.Label(left_inner, textvariable=gui._ur_stats_var, bg="white", fg="#555",
             font=("Consolas", 8), justify=tk.LEFT, anchor="w").pack(fill=tk.X)

    # 算法摘要
    tk.Frame(left_inner, bg="#ecf0f1", height=1).pack(fill=tk.X, pady=6)
    tk.Label(left_inner, text="算法说明", bg="white", fg="#2c3e50",
             font=("Microsoft YaHei", 8, "bold")).pack(anchor="w")
    algo_text = (
        "评分 = 0.30×CVSS + 0.20×PageRank\n"
        "     + 0.15×时效 + 0.15×严重度密度\n"
        "     + 0.10×CWE多样性 + 0.10×暴露度\n"
        "数据: NVD CVE + Dell DSA\n"
        "规则: 10条YAML安全规则\n"
        "预测: 6月滑动窗口线性回归"
    )
    tk.Label(left_inner, text=algo_text, bg="white", fg="#7f8c8d",
             font=("Consolas", 7), justify=tk.LEFT, anchor="w").pack(fill=tk.X, pady=(2, 0))

    # ─── 右栏：上下分区 ──────────────────────────────────────────────
    right = tk.Frame(body, bg="#f5f6fa")
    body.add(right, minsize=600)

    right_paned = tk.PanedWindow(right, orient=tk.VERTICAL, bg="#ecf0f1", sashwidth=4, sashrelief=tk.FLAT)
    right_paned.pack(fill=tk.BOTH, expand=True)

    # ─── 上区：图谱 + 分析详情 ───────────────────────────────────────
    upper = tk.Frame(right_paned, bg="white")
    right_paned.add(upper, minsize=380, height=460)

    upper_paned = tk.PanedWindow(upper, orient=tk.HORIZONTAL, bg="#ecf0f1", sashwidth=3)
    upper_paned.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

    # 图谱画布（占主要空间，更大更醒目）
    graph_frame = tk.Frame(upper_paned, bg="white", relief=tk.FLAT, bd=0)
    upper_paned.add(graph_frame, minsize=480, width=620)

    graph_header = tk.Frame(graph_frame, bg="white")
    graph_header.pack(fill=tk.X, padx=8, pady=(6, 2))
    tk.Label(graph_header, text="◆ 知识图谱可视化", bg="white", fg="#2c3e50",
             font=("Microsoft YaHei", 11, "bold")).pack(side=tk.LEFT)
    tk.Label(graph_header, text="CVE · DSA · Product · CWE 关联网络",
             bg="white", fg="#95a5a6",
             font=("Microsoft YaHei", 8)).pack(side=tk.LEFT, padx=(8, 0))

    gui._ur_canvas_host = tk.Frame(graph_frame, bg="#fafafa", relief=tk.SOLID, bd=1,
                                    highlightbackground="#e0e0e0", highlightthickness=1)
    gui._ur_canvas_host.pack(fill=tk.BOTH, expand=True, padx=8, pady=(2, 8))

    # 分析详情 Notebook（侧栏，较窄）
    detail_frame = tk.Frame(upper_paned, bg="white")
    upper_paned.add(detail_frame, minsize=240, width=300)

    tk.Label(detail_frame, text="◆ 分析详情", bg="white", fg="#2c3e50",
             font=("Microsoft YaHei", 10, "bold")).pack(anchor="w", padx=8, pady=(6, 2))

    detail_nb = ttk.Notebook(detail_frame)
    detail_nb.pack(fill=tk.BOTH, expand=True, padx=4, pady=(2, 4))

    # ── 产品线 DSA 预测（默认 Tab，作为风险分析关键点）────────────────
    dsa_outer = tk.Frame(detail_nb, bg="#fafafa")
    detail_nb.add(dsa_outer, text="产品线 DSA 预测")

    dsa_top = tk.Frame(dsa_outer, bg="#fafafa")
    dsa_top.pack(fill=tk.X, padx=4, pady=(2, 0))
    gui._ur_dsa_summary_var = tk.StringVar(
        value="点击工具栏「🎯 产品线DSA预测」按钮开始计算"
    )
    tk.Label(dsa_top, textvariable=gui._ur_dsa_summary_var, bg="#fafafa",
             fg="#7f8c8d", font=("Microsoft YaHei", 8),
             justify=tk.LEFT, anchor="w", wraplength=280).pack(fill=tk.X)

    # 表格：产品线 / 概率 / 等级
    dsa_table_frame = tk.Frame(dsa_outer, bg="#fafafa")
    dsa_table_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=2)

    gui._ur_dsa_tree = ttk.Treeview(
        dsa_table_frame, columns=("line", "prob", "level"),
        show="headings", height=10
    )
    gui._ur_dsa_tree.heading("line", text="产品线")
    gui._ur_dsa_tree.heading("prob", text="概率")
    gui._ur_dsa_tree.heading("level", text="等级")
    gui._ur_dsa_tree.column("line", width=170, anchor="w")
    gui._ur_dsa_tree.column("prob", width=55, anchor="center")
    gui._ur_dsa_tree.column("level", width=70, anchor="center")
    dsa_sb = ttk.Scrollbar(dsa_table_frame, orient=tk.VERTICAL,
                           command=gui._ur_dsa_tree.yview)
    gui._ur_dsa_tree.configure(yscrollcommand=dsa_sb.set)
    gui._ur_dsa_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    dsa_sb.pack(side=tk.RIGHT, fill=tk.Y)
    gui._ur_dsa_tree.bind("<<TreeviewSelect>>",
                          lambda e: _ur_dsa_on_select(gui))

    # 等级颜色 tag
    gui._ur_dsa_tree.tag_configure("CRITICAL", background="#fdedec", foreground="#c0392b")
    gui._ur_dsa_tree.tag_configure("HIGH",     background="#fef5e7", foreground="#d35400")
    gui._ur_dsa_tree.tag_configure("MEDIUM",   background="#fef9e7", foreground="#b7950b")
    gui._ur_dsa_tree.tag_configure("LOW",      background="#eaf2f8", foreground="#2980b9")
    gui._ur_dsa_tree.tag_configure("MINIMAL",  background="#f4f6f6", foreground="#7f8c8d")

    # 解释文本（选中产品线后显示因子拆解）
    dsa_explain_frame = tk.Frame(dsa_outer, bg="#fafafa")
    dsa_explain_frame.pack(fill=tk.BOTH, expand=False, padx=4, pady=(2, 4))
    tk.Label(dsa_explain_frame, text="算法因子拆解", bg="#fafafa",
             fg="#2c3e50", font=("Microsoft YaHei", 9, "bold")
             ).pack(anchor="w")
    gui._ur_dsa_explain_text = tk.Text(
        dsa_explain_frame, wrap=tk.WORD, font=("Consolas", 8),
        bg="white", relief=tk.SOLID, bd=1, height=14, padx=4, pady=2
    )
    gui._ur_dsa_explain_text.pack(fill=tk.BOTH, expand=True)
    gui._ur_dsa_explain_text.insert(
        "1.0",
        "算法说明（Poisson 速率模型）\n"
        "─────────────────────\n"
        "λ_eff = λ_base × trend × severity + 0.04 × open_cves\n"
        "P(≥1 DSA) = 1 − exp(−λ_eff × D/30)\n\n"
        "因子来源：\n"
        "  λ_base    : 过去 12 个月该产品线月均 DSA 数\n"
        "  λ_recent  : 过去 3 个月月均 DSA 数\n"
        "  trend     : λ_recent / λ_base，裁剪到 [0.5, 3.0]\n"
        "  severity  : 1 + 0.5 × (近期 CVE 平均 CVSS / 10)\n"
        "  open_cves : 近 90 天匹配该产品线但未进入 DSA 的 CVE 数\n\n"
        "数据源：\n"
        "  - dell_advisories 表（2018+ 的全量 DSA）\n"
        "  - cves 表（NVD CVE，按描述/产品名匹配）\n\n"
        "选中表格中的产品线查看完整因子拆解"
    )
    gui._ur_dsa_explain_text.config(state=tk.DISABLED)

    gui._ur_score_text = tk.Text(detail_nb, wrap=tk.WORD, font=("Consolas", 9),
                                  bg="#fafafa", relief=tk.FLAT, padx=6, pady=4)
    detail_nb.add(gui._ur_score_text, text="评分因子")

    # ── 微码级风险 Tab ────────────────────────────────────────────────
    micro_outer = tk.Frame(detail_nb, bg="#fafafa")
    detail_nb.add(micro_outer, text="微码级风险")

    micro_top = tk.Frame(micro_outer, bg="#fafafa")
    micro_top.pack(fill=tk.X, padx=4, pady=(2, 0))
    gui._ur_micro_summary_var = tk.StringVar(
        value="点击工具栏「🔬 微码风险」按钮开始评估"
    )
    tk.Label(micro_top, textvariable=gui._ur_micro_summary_var, bg="#fafafa",
             fg="#7f8c8d", font=("Microsoft YaHei", 8),
             justify=tk.LEFT, anchor="w", wraplength=280).pack(fill=tk.X)

    # ── P1-8：unversioned / versioned 分组切换 ──
    # ── P1-9：产品线联动过滤 ──
    filter_row = tk.Frame(micro_outer, bg="#fafafa")
    filter_row.pack(fill=tk.X, padx=4, pady=(2, 2))
    tk.Label(filter_row, text="显示:", bg="#fafafa", fg="#555",
             font=("Microsoft YaHei", 8)).pack(side=tk.LEFT)
    gui._ur_micro_filter_var = tk.StringVar(value="all")
    for label, val in (("全部", "all"), ("仅有版本", "versioned"),
                        ("仅大类", "unversioned")):
        tk.Radiobutton(
            filter_row, text=label, variable=gui._ur_micro_filter_var,
            value=val, bg="#fafafa", fg="#2c3e50",
            font=("Microsoft YaHei", 8),
            activebackground="#fafafa", selectcolor="white",
            command=lambda: _ur_micro_apply_filter(gui)
        ).pack(side=tk.LEFT, padx=(2, 0))

    # 产品线联动下拉框（选中产品线 DSA 表格时自动同步）
    pl_row = tk.Frame(micro_outer, bg="#fafafa")
    pl_row.pack(fill=tk.X, padx=4, pady=(0, 2))
    tk.Label(pl_row, text="产品线:", bg="#fafafa", fg="#555",
             font=("Microsoft YaHei", 8)).pack(side=tk.LEFT)
    gui._ur_micro_pl_var = tk.StringVar(value="(全部)")
    gui._ur_micro_pl_combo = ttk.Combobox(
        pl_row, textvariable=gui._ur_micro_pl_var, width=24,
        state="readonly", font=("Microsoft YaHei", 8)
    )
    gui._ur_micro_pl_combo.pack(side=tk.LEFT, padx=(2, 0))
    gui._ur_micro_pl_combo.bind(
        "<<ComboboxSelected>>",
        lambda e: _ur_micro_apply_filter(gui)
    )

    # ── P1-7：反向查询区（紧凑型）──
    query_frame = tk.LabelFrame(
        micro_outer, text=" 🔍 反向查询：我有这个版本，受哪些 DSA 影响？ ",
        bg="#fafafa", fg="#2c3e50",
        font=("Microsoft YaHei", 8, "bold"), padx=4, pady=2
    )
    query_frame.pack(fill=tk.X, padx=4, pady=(4, 2))

    query_row = tk.Frame(query_frame, bg="#fafafa")
    query_row.pack(fill=tk.X)
    tk.Label(query_row, text="机型:", bg="#fafafa",
             font=("Microsoft YaHei", 8)).pack(side=tk.LEFT)
    gui._ur_query_model_var = tk.StringVar()
    tk.Entry(query_row, textvariable=gui._ur_query_model_var, width=10,
             font=("Consolas", 9)).pack(side=tk.LEFT, padx=(2, 6))
    tk.Label(query_row, text="类型:", bg="#fafafa",
             font=("Microsoft YaHei", 8)).pack(side=tk.LEFT)
    gui._ur_query_ftype_var = tk.StringVar(value="")
    ttk.Combobox(query_row, textvariable=gui._ur_query_ftype_var, width=8,
                 values=["", "BIOS", "Firmware", "iDRAC", "OS", "Software"],
                 state="readonly", font=("Consolas", 8)
                 ).pack(side=tk.LEFT, padx=(2, 6))
    tk.Label(query_row, text="版本:", bg="#fafafa",
             font=("Microsoft YaHei", 8)).pack(side=tk.LEFT)
    gui._ur_query_version_var = tk.StringVar()
    tk.Entry(query_row, textvariable=gui._ur_query_version_var, width=10,
             font=("Consolas", 9)).pack(side=tk.LEFT, padx=(2, 4))
    tk.Button(query_row, text="查询",
              command=lambda: _ur_micro_query(gui),
              bg="#2c3e50", fg="white", relief=tk.FLAT, cursor="hand2",
              font=("Microsoft YaHei", 8, "bold"), padx=8, pady=1
              ).pack(side=tk.LEFT, padx=(4, 0))

    gui._ur_query_result_var = tk.StringVar(value="提示: 例如 R640 / BIOS / 2.10.0")
    tk.Label(query_frame, textvariable=gui._ur_query_result_var,
             bg="#fafafa", fg="#7f8c8d",
             font=("Consolas", 8), anchor="w",
             justify=tk.LEFT, wraplength=280).pack(fill=tk.X, pady=(2, 0))

    micro_table_frame = tk.Frame(micro_outer, bg="#fafafa")
    micro_table_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=2)

    gui._ur_micro_tree = ttk.Treeview(
        micro_table_frame,
        columns=("product_line", "score", "band", "model", "type", "version", "hit"),
        show="headings", height=10
    )
    gui._ur_micro_tree.heading("product_line", text="产品线")
    gui._ur_micro_tree.heading("score", text="分")
    gui._ur_micro_tree.heading("band", text="等级")
    gui._ur_micro_tree.heading("model", text="机型")
    gui._ur_micro_tree.heading("type", text="类型")
    gui._ur_micro_tree.heading("version", text="版本")
    gui._ur_micro_tree.heading("hit", text="命中")
    # minwidth + stretch=False 让超出可视区不压缩，配合 xscrollbar
    gui._ur_micro_tree.column("product_line", width=160, minwidth=140, anchor="w", stretch=False)
    gui._ur_micro_tree.column("score", width=40, minwidth=40, anchor="center", stretch=False)
    gui._ur_micro_tree.column("band", width=70, minwidth=60, anchor="center", stretch=False)
    gui._ur_micro_tree.column("model", width=80, minwidth=60, anchor="w", stretch=False)
    gui._ur_micro_tree.column("type", width=70, minwidth=60, anchor="w", stretch=False)
    gui._ur_micro_tree.column("version", width=90, minwidth=70, anchor="w", stretch=False)
    gui._ur_micro_tree.column("hit", width=40, minwidth=35, anchor="center", stretch=False)
    micro_sb = ttk.Scrollbar(micro_table_frame, orient=tk.VERTICAL,
                             command=gui._ur_micro_tree.yview)
    micro_xsb = ttk.Scrollbar(micro_table_frame, orient=tk.HORIZONTAL,
                              command=gui._ur_micro_tree.xview)
    gui._ur_micro_tree.configure(yscrollcommand=micro_sb.set,
                                 xscrollcommand=micro_xsb.set)
    # grid 布局让横向滚动条对齐
    gui._ur_micro_tree.grid(row=0, column=0, sticky="nsew")
    micro_sb.grid(row=0, column=1, sticky="ns")
    micro_xsb.grid(row=1, column=0, sticky="ew")
    micro_table_frame.rowconfigure(0, weight=1)
    micro_table_frame.columnconfigure(0, weight=1)
    gui._ur_micro_tree.bind("<<TreeviewSelect>>",
                            lambda e: _ur_micro_on_select(gui))

    gui._ur_micro_tree.tag_configure("EXTREME", background="#fdedec", foreground="#c0392b")
    gui._ur_micro_tree.tag_configure("HIGH", background="#fef5e7", foreground="#d35400")
    gui._ur_micro_tree.tag_configure("MEDIUM", background="#fef9e7", foreground="#b7950b")
    gui._ur_micro_tree.tag_configure("LOW", background="#eaf2f8", foreground="#2980b9")
    gui._ur_micro_tree.tag_configure("MINIMAL", background="#f4f6f6", foreground="#7f8c8d")

    micro_explain_frame = tk.Frame(micro_outer, bg="#fafafa")
    micro_explain_frame.pack(fill=tk.BOTH, expand=False, padx=4, pady=(2, 4))
    tk.Label(micro_explain_frame, text="风险因子拆解", bg="#fafafa",
             fg="#2c3e50", font=("Microsoft YaHei", 9, "bold")).pack(anchor="w")
    gui._ur_micro_explain_text = tk.Text(
        micro_explain_frame, wrap=tk.WORD, font=("Consolas", 8),
        bg="white", relief=tk.SOLID, bd=1, height=8, padx=4, pady=2
    )
    gui._ur_micro_explain_text.pack(fill=tk.BOTH, expand=True)
    gui._ur_micro_explain_text.insert(
        "1.0",
        "评分公式 (exposure_score 0~100)\n"
        "──────────────────────────\n"
        "freq_score    = (展开命中数 / 全局最大) × 50\n"
        "severity_score = (avg_cvss / 10) × 25\n"
        "recency_score = (1 − 月数/24) × 25\n\n"
        "数据源：\n"
        "  Dell DSA affected_products → 四元组 key\n"
        "  `prior to` / `<` → 保守范围展开\n"
        "  CVSS: NVD cvss_score 优先，severity 文本兜底\n\n"
        "选中表格中的版本查看详细拆解"
    )
    gui._ur_micro_explain_text.config(state=tk.DISABLED)

    # （micro 缓存已在函数顶部初始化）

    gui._ur_propagation_text = tk.Text(detail_nb, wrap=tk.WORD, font=("Consolas", 9),
                                        bg="#fafafa", relief=tk.FLAT, padx=6, pady=4)
    detail_nb.add(gui._ur_propagation_text, text="传播分析")

    gui._ur_trend_text = tk.Text(detail_nb, wrap=tk.WORD, font=("Consolas", 9),
                                  bg="#fafafa", relief=tk.FLAT, padx=6, pady=4)
    detail_nb.add(gui._ur_trend_text, text="趋势预测")

    gui._ur_rules_text = tk.Text(detail_nb, wrap=tk.WORD, font=("Consolas", 9),
                                  bg="#fafafa", relief=tk.FLAT, padx=6, pady=4)
    detail_nb.add(gui._ur_rules_text, text="触发规则")

    # ─── 下区：预防性维护建议 ─────────────────────────────────────────
    lower = tk.Frame(right_paned, bg="white")
    right_paned.add(lower, minsize=180, height=240)

    # 建议标题栏
    rec_title_bar = tk.Frame(lower, bg="#2c3e50")
    rec_title_bar.pack(fill=tk.X)
    tk.Label(rec_title_bar, text="  预防性维护建议", bg="#2c3e50", fg="white",
             font=("Microsoft YaHei", 10, "bold")).pack(side=tk.LEFT, pady=5)
    tk.Label(rec_title_bar, text="基于规则引擎 + 图谱分析自动生成  ", bg="#2c3e50", fg="#bdc3c7",
             font=("Microsoft YaHei", 8)).pack(side=tk.RIGHT, pady=5)

    # 建议内容（水平滚动卡片）
    rec_container = tk.Frame(lower, bg="#f5f6fa")
    rec_container.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

    rec_canvas = tk.Canvas(rec_container, bg="#f5f6fa", highlightthickness=0)
    rec_sb = ttk.Scrollbar(rec_container, orient=tk.VERTICAL, command=rec_canvas.yview)
    gui._ur_rec_inner = tk.Frame(rec_canvas, bg="#f5f6fa")
    gui._ur_rec_inner.bind("<Configure>", lambda e: rec_canvas.configure(scrollregion=rec_canvas.bbox("all")))
    rec_canvas.create_window((0, 0), window=gui._ur_rec_inner, anchor="nw")
    rec_canvas.configure(yscrollcommand=rec_sb.set)
    rec_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    rec_sb.pack(side=tk.RIGHT, fill=tk.Y)
    # 鼠标滚轮绑定
    rec_canvas.bind("<MouseWheel>", lambda e: rec_canvas.yview_scroll(-1 * (e.delta // 120), "units"))

    # Tab 切换懒加载
    gui.notebook.bind("<<NotebookTabChanged>>", lambda e: _ur_on_tab_changed(gui), add="+")


# ════════════════════════════════════════════════════════════════════════════
# 事件处理与业务逻辑
# ════════════════════════════════════════════════════════════════════════════

def _ur_on_tab_changed(gui) -> None:
    try:
        current = gui.notebook.index(gui.notebook.select())
        unified_idx = gui.notebook.index(gui.unified_risk_tab_id)
        if current == unified_idx and not gui._ur_loaded:
            gui._ur_loaded = True
            _ur_auto_load(gui)
    except (tk.TclError, ValueError):
        pass


def _ur_auto_load(gui) -> None:
    def _worker():
        try:
            from knowledge_graph import KnowledgeGraph

            cache_path = gui.data_dir / "kg_cache.pkl"
            db_path = str(gui.data_dir / "cve_database.db")

            if cache_path.exists():
                gui.root.after(0, lambda: gui._ur_status_var.set("从缓存加载中..."))
                try:
                    kg = KnowledgeGraph.load_cache(str(cache_path))
                    gui._ur_kg = kg
                    stats = kg.stats()
                    gui.root.after(0, lambda: gui._ur_status_var.set(
                        f"已加载 | {stats['nodes_total']} 节点 · {stats['edges_total']} 边"))
                    gui.root.after(0, lambda: _ur_update_stats(gui))
                    _ur_run_analysis(gui)
                    return
                except Exception:
                    pass

            gui.root.after(0, lambda: gui._ur_status_var.set("首次构建知识图谱（约10秒）..."))
            kg = KnowledgeGraph.from_sqlite(db_path)
            kg.build(limit_cve=5000, limit_dsa=None)
            try:
                kg.save_cache(str(cache_path))
            except Exception:
                pass
            gui._ur_kg = kg
            stats = kg.stats()
            gui.root.after(0, lambda: gui._ur_status_var.set(
                f"构建完成 | {stats['nodes_total']} 节点 · {stats['edges_total']} 边"))
            gui.root.after(0, lambda: _ur_update_stats(gui))
            _ur_run_analysis(gui)
        except Exception as e:
            gui.root.after(0, lambda: gui._ur_status_var.set(f"加载失败: {e}"))

    threading.Thread(target=_worker, daemon=True).start()


def _ur_full_analyze(gui) -> None:
    gui._ur_loaded = True

    def _worker():
        try:
            from knowledge_graph import KnowledgeGraph

            db_path = str(gui.data_dir / "cve_database.db")
            cache_path = gui.data_dir / "kg_cache.pkl"

            gui.root.after(0, lambda: gui._ur_status_var.set("全量构建中..."))
            kg = KnowledgeGraph.from_sqlite(db_path)
            kg.build(limit_cve=5000, limit_dsa=None)
            try:
                kg.save_cache(str(cache_path))
            except Exception:
                pass
            gui._ur_kg = kg
            stats = kg.stats()
            gui.root.after(0, lambda: gui._ur_status_var.set(
                f"构建完成，正在分析... | {stats['nodes_total']} 节点"))
            gui.root.after(0, lambda: _ur_update_stats(gui))
            _ur_run_analysis(gui)
        except Exception as e:
            gui.root.after(0, lambda: gui._ur_status_var.set(f"分析失败: {e}"))

    threading.Thread(target=_worker, daemon=True).start()


def _ur_run_analysis(gui) -> None:
    from risk.report_builder import RiskReportBuilder

    builder = RiskReportBuilder(gui._ur_kg)
    gui._ur_builder = builder
    reports = builder.analyze_top_products(k=15, min_score=15.0)
    gui._ur_reports = reports

    gui.root.after(0, lambda: _ur_display_results(gui, reports))
    n = len(reports)
    gui.root.after(0, lambda: gui._ur_status_var.set(
        f"分析完成 | {n} 个风险产品 · {gui._ur_kg.stats()['nodes_total']} 节点"))


def _ur_update_stats(gui) -> None:
    if gui._ur_kg is None:
        return
    s = gui._ur_kg.stats()
    gui._ur_stats_var.set(
        f"CVE: {s.get('node:cve',0)}  DSA: {s.get('node:dsa',0)}\n"
        f"产品: {s.get('node:product',0)}  CWE: {s.get('node:cwe',0)}\n"
        f"总边数: {s.get('edges_total',0)}"
    )


def _ur_display_results(gui, reports) -> None:
    for item in gui._ur_tree.get_children():
        gui._ur_tree.delete(item)
    for report in reports:
        if not report.risk_scores:
            continue
        score = report.risk_scores[0]
        gui._ur_tree.insert("", tk.END, values=(
            score.entity_id, f"{score.score:.1f}", score.level.value
        ))
    children = gui._ur_tree.get_children()
    if children:
        gui._ur_tree.selection_set(children[0])
        _ur_on_select(gui)


def _ur_on_select(gui) -> None:
    selection = gui._ur_tree.selection()
    if not selection:
        return
    product = gui._ur_tree.item(selection[0])["values"][0]
    report = next((r for r in gui._ur_reports if r.subject == product), None)
    if report is None:
        return
    _ur_render_graph(gui, product)
    _ur_fill_details(gui, report)
    _ur_fill_recommendations(gui, report)


def _ur_render_graph(gui, product: str) -> None:
    if gui._ur_kg is None:
        return
    for w in gui._ur_canvas_host.winfo_children():
        w.destroy()
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
        from knowledge_graph import draw_subgraph

        sub = gui._ur_kg.ego_subgraph(product, radius=1)
        if sub.number_of_nodes() == 0:
            tk.Label(gui._ur_canvas_host, text="(无关联数据)", bg="#fafafa", fg="#aaa",
                     font=("Microsoft YaHei", 9)).pack(expand=True)
            return

        # 设置中文字体（必须在 plt.subplots 之前）
        plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei", "DejaVu Sans"]
        plt.rcParams["axes.unicode_minus"] = False

        # 根据节点数量自适应图谱尺寸
        n_nodes = sub.number_of_nodes()
        # 默认更大尺寸，让图谱更清晰美观
        fig_w = 8.5
        fig_h = 6.0
        fig, ax = plt.subplots(figsize=(fig_w, fig_h), dpi=95)
        fig.patch.set_facecolor("#fafafa")
        ax.set_facecolor("#fafafa")

        # 节点过多时使用 kamada_kawai 布局更清晰
        layout = "kamada_kawai" if n_nodes > 30 else "spring"
        draw_subgraph(sub, ax, layout=layout, seed=42)

        ax.set_title(f"{product}  —  {n_nodes} 节点 · {sub.number_of_edges()} 边",
                     fontsize=11, pad=10, color="#2c3e50",
                     fontfamily="Microsoft YaHei", fontweight="bold")

        # 紧凑布局，去除多余边距
        fig.tight_layout(pad=1.0)

        canvas = FigureCanvasTkAgg(fig, master=gui._ur_canvas_host)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        plt.close(fig)
    except Exception as e:
        tk.Label(gui._ur_canvas_host, text=f"渲染失败: {e}", bg="#fafafa", fg="red",
                 font=("Microsoft YaHei", 8)).pack(expand=True)


def _ur_fill_details(gui, report) -> None:
    score = report.risk_scores[0] if report.risk_scores else None

    # 评分因子
    gui._ur_score_text.config(state=tk.NORMAL)
    gui._ur_score_text.delete("1.0", tk.END)
    if score:
        lines = [
            f"产品: {score.entity_id}",
            f"综合评分: {score.score:.1f} / 100  ({score.level.value})",
            "",
            f"{'因子':<16s} {'原始分':>6s} {'权重':>5s} {'贡献':>6s}",
            "─" * 38,
        ]
        weights = {"cvss_avg": 0.30, "pagerank": 0.20, "recency": 0.15,
                   "severity_density": 0.15, "cwe_diversity": 0.10, "exposure": 0.10}
        for k, v in score.factors.items():
            w = weights.get(k, 0)
            lines.append(f"{k:<16s} {v:>6.1f} {w:>4.0%}  {v * w:>5.1f}")
        lines.extend(["", f"关键 CVE: {', '.join(score.evidence[:5])}"])
        gui._ur_score_text.insert("1.0", "\n".join(lines))
    gui._ur_score_text.config(state=tk.DISABLED)

    # 传播分析
    gui._ur_propagation_text.config(state=tk.NORMAL)
    gui._ur_propagation_text.delete("1.0", tk.END)
    if report.impact_paths:
        lines = [f"{'源CVE':<16s} {'影响产品':<22s} {'跳':>2s} {'可信度':>5s} {'共享CWE'}", "─" * 60]
        for p in report.impact_paths[:10]:
            cwes = ",".join(p.shared_cwes[:2])
            lines.append(f"{p.source_cve:<16s} {p.target_product:<22s} {p.hops:>2d} {p.confidence:>4.0%}  {cwes}")
        gui._ur_propagation_text.insert("1.0", "\n".join(lines))
    else:
        gui._ur_propagation_text.insert("1.0", "当前产品无高危 CVE 传播路径")
    gui._ur_propagation_text.config(state=tk.DISABLED)

    # 趋势预测
    gui._ur_trend_text.config(state=tk.NORMAL)
    gui._ur_trend_text.delete("1.0", tk.END)
    if report.trend_forecast and report.trend_forecast.method != "no_data":
        f = report.trend_forecast
        trend_map = {"rising": "↑ 上升", "stable": "→ 稳定", "declining": "↓ 下降"}
        lines = [
            f"产品: {f.subject}",
            f"预测周期: 未来 {f.forecast_days} 天",
            f"预测新增 CVE: {f.predicted_count} 个 (区间: {f.confidence_interval[0]}~{f.confidence_interval[1]})",
            f"风险趋势: {trend_map.get(f.risk_trend, f.risk_trend)}",
            f"方法: 6个月月度CVE计数 → 线性回归外推",
            "",
        ]
        if f.hot_cwes:
            lines.append("近期高频 CWE:")
            for cwe, ratio in f.hot_cwes[:5]:
                lines.append(f"  {cwe}: {ratio:.0%}")
        gui._ur_trend_text.insert("1.0", "\n".join(lines))
    else:
        gui._ur_trend_text.insert("1.0", "历史数据不足，无法生成趋势预测")
    gui._ur_trend_text.config(state=tk.DISABLED)

    # 触发规则
    gui._ur_rules_text.config(state=tk.NORMAL)
    gui._ur_rules_text.delete("1.0", tk.END)
    if report.rule_matches:
        lines = []
        for m in report.rule_matches:
            lines.append(f"[{m.severity.value}] {m.rule_name}")
            lines.append(f"  规则ID: {m.rule_id}  证据: {', '.join(m.matched_evidence[:3])}")
            lines.append("")
        gui._ur_rules_text.insert("1.0", "\n".join(lines))
    else:
        gui._ur_rules_text.insert("1.0", "未触发安全规则（当前产品风险较低）")
    gui._ur_rules_text.config(state=tk.DISABLED)


def _ur_fill_recommendations(gui, report) -> None:
    for w in gui._ur_rec_inner.winfo_children():
        w.destroy()

    if not report.recommendations:
        tk.Label(gui._ur_rec_inner, text="  当前产品无紧急维护建议",
                 bg="#f5f6fa", fg="#7f8c8d", font=("Microsoft YaHei", 9)).pack(
            anchor="w", padx=8, pady=12)
        return

    for rec in report.recommendations[:12]:
        pv = rec.priority.value
        color = PRIORITY_COLORS.get(pv, "#7f8c8d")
        bg = PRIORITY_BG.get(pv, "#f5f6fa")

        card = tk.Frame(gui._ur_rec_inner, bg=bg, relief=tk.FLAT, bd=0)
        card.pack(fill=tk.X, padx=4, pady=2, ipady=3)

        # 左侧色条
        tk.Frame(card, bg=color, width=4).pack(side=tk.LEFT, fill=tk.Y)

        content = tk.Frame(card, bg=bg)
        content.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8, pady=2)

        # 第一行：优先级 + 标题
        row1 = tk.Frame(content, bg=bg)
        row1.pack(fill=tk.X)
        tk.Label(row1, text=pv, bg=color, fg="white",
                 font=("Consolas", 7, "bold"), padx=4, pady=0).pack(side=tk.LEFT)
        tk.Label(row1, text=f" {rec.title}", bg=bg, fg="#2c3e50",
                 font=("Microsoft YaHei", 9, "bold"), anchor="w").pack(side=tk.LEFT)

        # 第二行：时间线 + 类型 + 工作量
        meta = f"{rec.timeline}  ·  {rec.action_type}  ·  工作量: {rec.estimated_effort}"
        tk.Label(content, text=meta, bg=bg, fg="#7f8c8d",
                 font=("Microsoft YaHei", 8), anchor="w").pack(fill=tk.X)


# ════════════════════════════════════════════════════════════════════════════
# 产品线 DSA 预测
# ════════════════════════════════════════════════════════════════════════════

def _ur_run_dsa_prediction(gui) -> None:
    """触发 Dell 产品线 DSA 概率预测（后台线程）"""
    try:
        days = int(gui._ur_dsa_days_var.get())
    except (ValueError, AttributeError):
        days = 30

    def _worker():
        try:
            from risk.dsa_prediction import DSAProductLinePredictor

            db_path = str(gui.data_dir / "cve_database.db")
            gui.root.after(0, lambda: gui._ur_dsa_summary_var.set(
                f"正在计算（扫描 DSA + 近 90 天 CVE）..."))

            predictor = DSAProductLinePredictor(db_path)
            results = predictor.forecast_all(forecast_days=days)
            gui._ur_dsa_results = results

            gui.root.after(0, lambda: _ur_dsa_render_table(gui, results, days))
        except Exception as e:
            err = str(e)
            gui.root.after(0, lambda: gui._ur_dsa_summary_var.set(f"预测失败: {err}"))

    threading.Thread(target=_worker, daemon=True).start()


def _ur_dsa_render_table(gui, results, days: int) -> None:
    """将预测结果渲染到表格 + 摘要"""
    tree = gui._ur_dsa_tree
    for item in tree.get_children():
        tree.delete(item)

    if not results:
        gui._ur_dsa_summary_var.set("无可用数据")
        return

    high_count = sum(1 for r in results if r.risk_level in ("CRITICAL", "HIGH"))
    total_dsa = sum(r.historical_dsa_total for r in results)

    gui._ur_dsa_summary_var.set(
        f"未来 {days} 天 · {len(results)} 条产品线 · "
        f"{high_count} 条高风险 · 历史 DSA 累计 {total_dsa} 条"
    )

    for r in results:
        prob_str = f"{r.probability:.0%}"
        tree.insert("", tk.END,
                    values=(r.product_line, prob_str, r.risk_level),
                    tags=(r.risk_level,))

    children = tree.get_children()
    if children:
        tree.selection_set(children[0])
        _ur_dsa_on_select(gui)


def _ur_dsa_on_select(gui) -> None:
    """选中产品线后展示因子拆解"""
    sel = gui._ur_dsa_tree.selection()
    if not sel:
        return
    line_name = gui._ur_dsa_tree.item(sel[0])["values"][0]
    forecast = next((r for r in gui._ur_dsa_results if r.product_line == line_name), None)
    if forecast is None:
        return

    txt = gui._ur_dsa_explain_text
    txt.config(state=tk.NORMAL)
    txt.delete("1.0", tk.END)

    lines = list(forecast.explanation)
    lines.extend([
        "",
        "─ 概率与置信区间 ─",
        f"  P(≥1 DSA) = {forecast.probability:.1%}",
        f"  80% CI    = [{forecast.probability_ci[0]:.1%}, {forecast.probability_ci[1]:.1%}]",
        f"  风险等级   = {forecast.risk_level}",
        "",
        "─ 等级阈值 ─",
        "  CRITICAL ≥ 80%   HIGH ≥ 50%",
        "  MEDIUM   ≥ 20%   LOW  ≥ 5%",
        "  MINIMAL  <  5%",
    ])
    txt.insert("1.0", "\n".join(lines))
    txt.config(state=tk.DISABLED)

    # P1-9：联动微码 Tab 产品线过滤（仅在 micro 已加载时生效）
    pl_var = getattr(gui, "_ur_micro_pl_var", None)
    combo = getattr(gui, "_ur_micro_pl_combo", None)
    if pl_var is not None and combo is not None:
        # 检查产品线是否在下拉框选项里
        if line_name in combo["values"]:
            pl_var.set(line_name)
            _ur_micro_apply_filter(gui)


def _ur_export(gui, fmt: str) -> None:
    if not gui._ur_reports and not gui._ur_dsa_results and not gui._ur_micro_results:
        gui._ur_status_var.set("无报告可导出，请先执行分析 / DSA 预测 / 微码评估")
        return

    if fmt == "json":
        path = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON", "*.json")],
            initialfile="trend_prediction_report.json")
    else:
        path = filedialog.asksaveasfilename(
            defaultextension=".md", filetypes=[("Markdown", "*.md")],
            initialfile="trend_prediction_report.md")
    if not path:
        return

    try:
        import json as _json
        if fmt == "json":
            data = {
                "product_risk_reports": [r.to_dict() for r in gui._ur_reports],
                "dsa_product_line_forecasts": [r.to_dict() for r in gui._ur_dsa_results],
                "microcode_risk_scores": [s.to_dict() for s in gui._ur_micro_results],
            }
            with open(path, "w", encoding="utf-8") as f:
                _json.dump(data, f, ensure_ascii=False, indent=2)
        else:
            sections = [_ur_build_overview(gui)]
            if gui._ur_dsa_results:
                sections.append(_ur_dsa_to_markdown(gui._ur_dsa_results))
            if gui._ur_micro_results:
                sections.append(_ur_micro_to_markdown(gui._ur_micro_results))
            if gui._ur_reports and gui._ur_builder:
                sections.append("\n\n---\n\n".join(
                    gui._ur_builder.to_markdown(r) for r in gui._ur_reports
                ))
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n\n---\n\n".join(sections))
        gui._ur_status_var.set(f"已导出: {Path(path).name}")
    except Exception as e:
        gui._ur_status_var.set(f"导出失败: {e}")


def _ur_dsa_to_markdown(results) -> str:
    """将 DSA 产品线预测结果格式化为 Markdown"""
    if not results:
        return ""
    days = results[0].forecast_days
    lines = [
        f"# Dell 产品线 DSA 概率预测（未来 {days} 天）",
        "",
        "## 算法",
        "",
        "Poisson 速率模型，可解释因子：",
        "",
        "```",
        "λ_eff = λ_base × trend_multiplier × severity_factor + 0.04 × open_cve_pressure",
        "P(≥1 DSA in D 天) = 1 − exp(−λ_eff × D / 30)",
        "```",
        "",
        "- λ_base: 过去 12 个月该产品线月均 DSA 数",
        "- trend_multiplier: 近 3 个月速率 / 12 个月基线，裁剪到 [0.5, 3.0]",
        "- severity_factor: 1 + 0.5 × (近期 CVE 平均 CVSS / 10)，∈ [1.0, 1.5]",
        "- open_cve_pressure: 近 90 天匹配该产品线但尚未进入 DSA 的 CVE 数",
        "",
        "## 预测结果",
        "",
        "| 产品线 | 全量DSA | 12M | 3M | λ_base | λ_recent | trend | sev | open | E[DSA] | P(≥1) | 等级 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|:---:|",
    ]
    for r in results:
        lines.append(
            f"| {r.product_line} | {r.historical_dsa_total} | "
            f"{r.historical_dsa_12m} | {r.historical_dsa_3m} | "
            f"{r.base_rate_per_month:.2f} | {r.recent_rate_per_month:.2f} | "
            f"{r.trend_multiplier:.2f} | {r.severity_factor:.2f} | "
            f"{r.open_cve_pressure} | {r.expected_dsa_count:.2f} | "
            f"{r.probability:.1%} | {r.risk_level} |"
        )
    return "\n".join(lines)


# ════════════════════════════════════════════════════════════════════════════
# 微码级风险评估
# ════════════════════════════════════════════════════════════════════════════

def _ur_run_microcode_assess(gui) -> None:
    """触发微码级风险评估（后台线程，复用 assessor 实例）"""
    def _worker():
        try:
            from risk.dsa_prediction_microcode import MicrocodeRiskAssessor

            db_path = str(gui.data_dir / "cve_database.db")

            # 复用缓存的 assessor 实例（避免重建索引 5-10s）
            if gui._ur_micro_assessor is None:
                gui.root.after(0, lambda: gui._ur_micro_summary_var.set(
                    "[1/4] 加载 DSA 与 CVSS 数据..."))
                assessor = MicrocodeRiskAssessor(db_path)
                gui.root.after(0, lambda: gui._ur_micro_summary_var.set(
                    "[2/4] 构建微码索引（产品线×机型×类型×版本）..."))
                assessor._build_index()
                gui.root.after(0, lambda: gui._ur_micro_summary_var.set(
                    "[3/4] 范围展开与全局归一..."))
                assessor._ensure_global_max_expanded()
                gui._ur_micro_assessor = assessor
            else:
                gui.root.after(0, lambda: gui._ur_micro_summary_var.set(
                    "使用缓存索引，正在评分..."))

            gui.root.after(0, lambda: gui._ur_micro_summary_var.set(
                "[4/4] 计算 Top 50 评分..."))
            results = gui._ur_micro_assessor.assess_all(top=50)
            gui._ur_micro_results = results

            gui.root.after(0, lambda: _ur_micro_render_table(gui, results))
        except Exception as e:
            err = str(e)
            gui.root.after(0, lambda: gui._ur_micro_summary_var.set(
                f"评估失败: {err}"))

    threading.Thread(target=_worker, daemon=True).start()


def _ur_micro_render_table(gui, results) -> None:
    """将微码评估结果渲染到表格（受 filter_var 与产品线下拉框过滤）"""
    tree = gui._ur_micro_tree
    for item in tree.get_children():
        tree.delete(item)

    if not results:
        gui._ur_micro_summary_var.set("无可用数据")
        return

    # 首次渲染时填入产品线下拉框选项
    combo = getattr(gui, "_ur_micro_pl_combo", None)
    if combo is not None and not combo["values"]:
        all_lines = sorted({s.key.product_line for s in results})
        combo["values"] = ["(全部)"] + all_lines

    # 应用 P1-8 unversioned/versioned 过滤
    flt = getattr(gui, "_ur_micro_filter_var", None)
    mode = flt.get() if flt else "all"
    if mode == "versioned":
        view = [s for s in results if s.key.version != "unversioned"]
    elif mode == "unversioned":
        view = [s for s in results if s.key.version == "unversioned"]
    else:
        view = list(results)

    # 应用 P1-9 产品线过滤
    pl_var = getattr(gui, "_ur_micro_pl_var", None)
    pl_filter = pl_var.get() if pl_var else "(全部)"
    if pl_filter and pl_filter != "(全部)":
        view = [s for s in view if s.key.product_line == pl_filter]

    from collections import Counter
    bands = Counter(s.risk_band for s in view)
    kev_total = sum(s.kev_hit_count for s in view)
    gui._ur_micro_summary_var.set(
        f"显示 {len(view)}/{len(results)} 条 · "
        f"EXTREME {bands.get('EXTREME', 0)} · "
        f"HIGH {bands.get('HIGH', 0)} · "
        f"MEDIUM {bands.get('MEDIUM', 0)} · "
        f"LOW {bands.get('LOW', 0)} · "
        f"⚠KEV {kev_total}"
    )

    for s in view:
        pl = s.key.product_line
        if len(pl) > 22:
            pl_disp = pl.split("(")[0].strip()[:20]
        else:
            pl_disp = pl
        version_disp = s.key.version
        if s.kev_hit_count > 0:
            version_disp = f"⚠ {version_disp}"
        tree.insert("", tk.END, values=(
            pl_disp,
            f"{s.exposure_score:.0f}",
            s.risk_band,
            s.key.model or "-",
            s.key.firmware_type,
            version_disp,
            str(s.expanded_dsa_count),
        ), tags=(s.risk_band,))

    children = tree.get_children()
    if children:
        tree.selection_set(children[0])
        _ur_micro_on_select(gui)


def _ur_micro_apply_filter(gui) -> None:
    """切换 unversioned / versioned 显示（不重算评分，只重渲染）"""
    if gui._ur_micro_results:
        _ur_micro_render_table(gui, gui._ur_micro_results)


def _ur_micro_on_select(gui) -> None:
    """选中微码版本后展示因子拆解"""
    sel = gui._ur_micro_tree.selection()
    if not sel:
        return
    idx = gui._ur_micro_tree.index(sel[0])
    if idx >= len(gui._ur_micro_results):
        return
    score = gui._ur_micro_results[idx]

    txt = gui._ur_micro_explain_text
    txt.config(state=tk.NORMAL)
    txt.delete("1.0", tk.END)
    txt.insert("1.0", "\n".join(score.explanation))
    txt.config(state=tk.DISABLED)


def _ur_build_overview(gui) -> str:
    """生成导出报告的总览章节（TOC + 摘要统计）"""
    from datetime import datetime as _dt
    parts = [
        "# 智能预测综合报告",
        "",
        f"生成时间: {_dt.now().strftime('%Y-%m-%d %H:%M')}",
        "",
        "## 概览",
        "",
    ]
    if gui._ur_dsa_results:
        high = [r for r in gui._ur_dsa_results if r.risk_level in ("CRITICAL", "HIGH")]
        parts.append(
            f"- **产品线 DSA 预测**: {len(gui._ur_dsa_results)} 条产品线，"
            f"其中 {len(high)} 条高风险 (CRITICAL/HIGH)"
        )
    if gui._ur_micro_results:
        ext = [s for s in gui._ur_micro_results if s.risk_band == "EXTREME"]
        kev = sum(s.kev_hit_count for s in gui._ur_micro_results)
        parts.append(
            f"- **微码级风险评估**: {len(gui._ur_micro_results)} 条微码版本，"
            f"其中 {len(ext)} 条 EXTREME，KEV 引用 {kev} 个"
        )
    if gui._ur_reports:
        parts.append(f"- **产品风险报告**: {len(gui._ur_reports)} 个产品")
    parts.extend(["", "## 目录", ""])
    if gui._ur_dsa_results:
        parts.append("1. [产品线 DSA 概率预测](#dell-产品线-dsa-概率预测)")
    if gui._ur_micro_results:
        parts.append("2. [微码级风险评估](#dell-微码级风险评估)")
    if gui._ur_reports:
        parts.append("3. [产品风险报告](#产品风险报告)")
    return "\n".join(parts)


def _ur_micro_query(gui) -> None:
    """反向查询：(机型, 类型, 版本) → 受影响的 DSA 列表"""
    if gui._ur_micro_assessor is None:
        gui._ur_query_result_var.set(
            "需要先点「🔬 微码风险」初始化索引（5-10s），再做反向查询"
        )
        return

    model = gui._ur_query_model_var.get().strip()
    ftype = gui._ur_query_ftype_var.get().strip() or None
    version = gui._ur_query_version_var.get().strip() or None
    if not model and not version:
        gui._ur_query_result_var.set(
            "请至少填写「机型」或「版本」其中一个"
        )
        return

    try:
        results = gui._ur_micro_assessor.query_by_microcode(
            model=model, firmware_type=ftype, version=version
        )
    except Exception as e:
        gui._ur_query_result_var.set(f"查询失败: {e}")
        return

    if not results:
        gui._ur_query_result_var.set(
            f"未命中: model={model!r} type={ftype!r} version={version!r}"
        )
        return

    # 摘要 + 最近 3 条
    kev_total = sum(len(r["kev_cves"]) for r in results)
    lines = [
        f"命中 {len(results)} 条 DSA，KEV 引用 {kev_total} 个",
        "─" * 40,
    ]
    for r in results[:5]:
        pub = r["published"].strftime("%Y-%m")
        kev_mark = f" ⚠KEV{len(r['kev_cves'])}" if r["kev_cves"] else ""
        title = r["title"][:50]
        lines.append(f"  [{pub}] CVSS {r['avg_cvss']:.1f}{kev_mark}")
        lines.append(f"    {title}")
    if len(results) > 5:
        lines.append(f"  ... 还有 {len(results) - 5} 条")
    gui._ur_query_result_var.set("\n".join(lines))


def _ur_micro_to_markdown(scores) -> str:
    """将微码级风险评估结果格式化为 Markdown"""
    if not scores:
        return ""
    from collections import Counter
    bands = Counter(s.risk_band for s in scores)
    lines = [
        "# Dell 微码级风险评估（Top {}）".format(len(scores)),
        "",
        "## 评分公式",
        "",
        "```",
        "exposure_score = freq_score (50%) + severity_score (25%) + recency_score (25%)",
        "  freq_score    = (展开命中数 / 全局最大命中数) × 50",
        "  severity_score = (avg_cvss / 10) × 25",
        "  recency_score = (1 − 月数_距最近一次出现 / 24) × 25",
        "```",
        "",
        "数据源：Dell DSA 历史 + cves.cvss_score（NVD）+ severity 文本兜底",
        "",
        f"## 风险带分布",
        "",
        f"- EXTREME: {bands.get('EXTREME', 0)}",
        f"- HIGH: {bands.get('HIGH', 0)}",
        f"- MEDIUM: {bands.get('MEDIUM', 0)}",
        f"- LOW: {bands.get('LOW', 0)}",
        f"- MINIMAL: {bands.get('MINIMAL', 0)}",
        "",
        "## Top 评分明细",
        "",
        "| 分 | 等级 | 产品线 | 机型 | 类型 | 版本 | 命中 | CVSS | 最近 |",
        "|---:|:---|:---|:---|:---|:---|---:|---:|---:|",
    ]
    for s in scores:
        recent = f"{s.months_since_last}月前" if s.months_since_last < 999 else "—"
        lines.append(
            f"| {s.exposure_score:.1f} | {s.risk_band} | "
            f"{s.key.product_line} | {s.key.model or '-'} | "
            f"{s.key.firmware_type} | {s.key.version} | "
            f"{s.expanded_dsa_count} | {s.severity_avg_cvss} | {recent} |"
        )
    return "\n".join(lines)
