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

try:
    from i18n import t
except ImportError:
    def t(key: str, **kwargs) -> str:
        return key


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
        text=t("ur_info_banner"),
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

    tk.Button(toolbar_inner, text=t("ur_btn_full_analyze"), command=lambda: _ur_full_analyze(gui),
              bg="#2c3e50", fg="white", relief=tk.FLAT, cursor="hand2",
              font=("Microsoft YaHei", 9, "bold"), padx=16, pady=5).pack(side=tk.LEFT)

    tk.Button(toolbar_inner, text=t("ur_btn_dsa_predict"), command=lambda: _ur_run_dsa_prediction(gui),
              bg="#8e44ad", fg="white", relief=tk.FLAT, cursor="hand2",
              font=("Microsoft YaHei", 9, "bold"), padx=12, pady=5).pack(side=tk.LEFT, padx=(8, 0))

    tk.Button(toolbar_inner, text=t("ur_btn_microcode"), command=lambda: _ur_run_microcode_assess(gui),
              bg="#d35400", fg="white", relief=tk.FLAT, cursor="hand2",
              font=("Microsoft YaHei", 9, "bold"), padx=12, pady=5).pack(side=tk.LEFT, padx=(8, 0))

    tk.Button(toolbar_inner, text=t("ur_btn_export"), command=lambda: _ur_export(gui, "md"),
              bg="#27ae60", fg="white", relief=tk.FLAT, cursor="hand2",
              font=("Microsoft YaHei", 9), padx=10, pady=5).pack(side=tk.LEFT, padx=(8, 0))

    # 预测周期选择（30 / 60 / 90 天）
    tk.Label(toolbar_inner, text=t("ur_period_label"), bg="white", fg="#555",
             font=("Microsoft YaHei", 9)).pack(side=tk.LEFT, padx=(12, 2))
    gui._ur_dsa_days_var = tk.StringVar(value="30")
    for d in ("30", "60", "90"):
        tk.Radiobutton(toolbar_inner, text=t("ur_days_suffix", d=d), variable=gui._ur_dsa_days_var, value=d,
                       bg="white", fg="#2c3e50", font=("Microsoft YaHei", 9),
                       activebackground="white", selectcolor="white",
                       command=lambda: _ur_run_dsa_prediction(gui) if gui._ur_dsa_results else None
                       ).pack(side=tk.LEFT)

    gui._ur_status_var = tk.StringVar(value=t("ur_status_autoload"))
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

    tk.Label(left_inner, text=t("ur_product_ranking"), bg="white", fg="#2c3e50",
             font=("Microsoft YaHei", 10, "bold")).pack(anchor="w", pady=(0, 4))

    tree_frame = tk.Frame(left_inner, bg="white")
    tree_frame.pack(fill=tk.BOTH, expand=True)

    gui._ur_tree = ttk.Treeview(tree_frame, columns=("product", "score", "level"),
                                 show="headings", height=14)
    gui._ur_tree.heading("product", text=t("ur_col_product"))
    gui._ur_tree.heading("score", text=t("ur_col_score"))
    gui._ur_tree.heading("level", text=t("ur_col_level"))
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
    gui._ur_stats_var = tk.StringVar(value=t("ur_not_loaded"))
    tk.Label(left_inner, textvariable=gui._ur_stats_var, bg="white", fg="#555",
             font=("Consolas", 8), justify=tk.LEFT, anchor="w").pack(fill=tk.X)

    # 算法摘要
    tk.Frame(left_inner, bg="#ecf0f1", height=1).pack(fill=tk.X, pady=6)
    tk.Label(left_inner, text=t("ur_algo_title"), bg="white", fg="#2c3e50",
             font=("Microsoft YaHei", 8, "bold")).pack(anchor="w")
    algo_text = t("ur_algo_text")
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
    tk.Label(graph_header, text=t("ur_kg_visual_title"), bg="white", fg="#2c3e50",
             font=("Microsoft YaHei", 11, "bold")).pack(side=tk.LEFT)
    tk.Label(graph_header, text=t("ur_kg_visual_subtitle"),
             bg="white", fg="#95a5a6",
             font=("Microsoft YaHei", 8)).pack(side=tk.LEFT, padx=(8, 0))

    gui._ur_canvas_host = tk.Frame(graph_frame, bg="#fafafa", relief=tk.SOLID, bd=1,
                                    highlightbackground="#e0e0e0", highlightthickness=1)
    gui._ur_canvas_host.pack(fill=tk.BOTH, expand=True, padx=8, pady=(2, 8))

    # 分析详情 Notebook（侧栏，较窄）
    detail_frame = tk.Frame(upper_paned, bg="white")
    upper_paned.add(detail_frame, minsize=240, width=300)

    tk.Label(detail_frame, text=t("ur_detail_title"), bg="white", fg="#2c3e50",
             font=("Microsoft YaHei", 10, "bold")).pack(anchor="w", padx=8, pady=(6, 2))

    detail_nb = ttk.Notebook(detail_frame)
    detail_nb.pack(fill=tk.BOTH, expand=True, padx=4, pady=(2, 4))

    # ── 产品线 DSA 预测（默认 Tab，作为风险分析关键点）────────────────
    dsa_outer = tk.Frame(detail_nb, bg="#fafafa")
    detail_nb.add(dsa_outer, text=t("ur_tab_dsa"))

    dsa_top = tk.Frame(dsa_outer, bg="#fafafa")
    dsa_top.pack(fill=tk.X, padx=4, pady=(2, 0))
    gui._ur_dsa_summary_var = tk.StringVar(
        value=t("ur_dsa_summary_init")
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
    gui._ur_dsa_tree.heading("line", text=t("ur_col_product_line"))
    gui._ur_dsa_tree.heading("prob", text=t("ur_col_prob"))
    gui._ur_dsa_tree.heading("level", text=t("ur_col_level"))
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
    tk.Label(dsa_explain_frame, text=t("ur_dsa_factor_title"), bg="#fafafa",
             fg="#2c3e50", font=("Microsoft YaHei", 9, "bold")
             ).pack(anchor="w")
    gui._ur_dsa_explain_text = tk.Text(
        dsa_explain_frame, wrap=tk.WORD, font=("Consolas", 8),
        bg="white", relief=tk.SOLID, bd=1, height=14, padx=4, pady=2
    )
    gui._ur_dsa_explain_text.pack(fill=tk.BOTH, expand=True)
    gui._ur_dsa_explain_text.insert(
        "1.0",
        t("ur_dsa_explain_text")
    )
    gui._ur_dsa_explain_text.config(state=tk.DISABLED)

    gui._ur_score_text = tk.Text(detail_nb, wrap=tk.WORD, font=("Consolas", 9),
                                  bg="#fafafa", relief=tk.FLAT, padx=6, pady=4)
    detail_nb.add(gui._ur_score_text, text=t("ur_tab_score_factor"))

    # ── 微码级风险 Tab ────────────────────────────────────────────────
    micro_outer = tk.Frame(detail_nb, bg="#fafafa")
    detail_nb.add(micro_outer, text=t("ur_tab_microcode"))

    micro_top = tk.Frame(micro_outer, bg="#fafafa")
    micro_top.pack(fill=tk.X, padx=4, pady=(2, 0))
    gui._ur_micro_summary_var = tk.StringVar(
        value=t("ur_micro_summary_init")
    )
    tk.Label(micro_top, textvariable=gui._ur_micro_summary_var, bg="#fafafa",
             fg="#7f8c8d", font=("Microsoft YaHei", 8),
             justify=tk.LEFT, anchor="w", wraplength=280).pack(fill=tk.X)

    # ── P1-8：unversioned / versioned 分组切换 ──
    # ── P1-9：产品线联动过滤 ──
    filter_row = tk.Frame(micro_outer, bg="#fafafa")
    filter_row.pack(fill=tk.X, padx=4, pady=(2, 2))
    tk.Label(filter_row, text=t("ur_micro_filter_label"), bg="#fafafa", fg="#555",
             font=("Microsoft YaHei", 8)).pack(side=tk.LEFT)
    gui._ur_micro_filter_var = tk.StringVar(value="all")
    for label, val in (
        (t("ur_micro_filter_all"), "all"),
        (t("ur_micro_filter_versioned"), "versioned"),
        (t("ur_micro_filter_unversioned"), "unversioned"),
    ):
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
    tk.Label(pl_row, text=t("ur_micro_pl_label"), bg="#fafafa", fg="#555",
             font=("Microsoft YaHei", 8)).pack(side=tk.LEFT)
    gui._ur_micro_pl_var = tk.StringVar(value=t("ur_micro_pl_all"))
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
        micro_outer, text=" " + t("ur_micro_lookup_title") + " ",
        bg="#fafafa", fg="#2c3e50",
        font=("Microsoft YaHei", 8, "bold"), padx=4, pady=2
    )
    query_frame.pack(fill=tk.X, padx=4, pady=(4, 2))

    query_row = tk.Frame(query_frame, bg="#fafafa")
    query_row.pack(fill=tk.X)
    tk.Label(query_row, text=t("ur_micro_lookup_model"), bg="#fafafa",
             font=("Microsoft YaHei", 8)).pack(side=tk.LEFT)
    gui._ur_query_model_var = tk.StringVar()
    tk.Entry(query_row, textvariable=gui._ur_query_model_var, width=10,
             font=("Consolas", 9)).pack(side=tk.LEFT, padx=(2, 6))
    tk.Label(query_row, text=t("ur_micro_lookup_type"), bg="#fafafa",
             font=("Microsoft YaHei", 8)).pack(side=tk.LEFT)
    gui._ur_query_ftype_var = tk.StringVar(value="")
    ttk.Combobox(query_row, textvariable=gui._ur_query_ftype_var, width=8,
                 values=["", "BIOS", "Firmware", "iDRAC", "OS", "Software"],
                 state="readonly", font=("Consolas", 8)
                 ).pack(side=tk.LEFT, padx=(2, 6))
    tk.Label(query_row, text=t("ur_micro_lookup_version"), bg="#fafafa",
             font=("Microsoft YaHei", 8)).pack(side=tk.LEFT)
    gui._ur_query_version_var = tk.StringVar()
    tk.Entry(query_row, textvariable=gui._ur_query_version_var, width=10,
             font=("Consolas", 9)).pack(side=tk.LEFT, padx=(2, 4))
    tk.Button(query_row, text=t("ur_micro_lookup_btn"),
              command=lambda: _ur_micro_query(gui),
              bg="#2c3e50", fg="white", relief=tk.FLAT, cursor="hand2",
              font=("Microsoft YaHei", 8, "bold"), padx=8, pady=1
              ).pack(side=tk.LEFT, padx=(4, 0))

    gui._ur_query_result_var = tk.StringVar(value=t("ur_micro_lookup_hint"))
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
    gui._ur_micro_tree.heading("product_line", text=t("ur_col_product_line"))
    gui._ur_micro_tree.heading("score", text=t("ur_col_score_short"))
    gui._ur_micro_tree.heading("band", text=t("ur_col_level"))
    gui._ur_micro_tree.heading("model", text=t("ur_col_model"))
    gui._ur_micro_tree.heading("type", text=t("ur_col_type"))
    gui._ur_micro_tree.heading("version", text=t("ur_col_version"))
    gui._ur_micro_tree.heading("hit", text=t("ur_col_hit"))
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

    # ── P2-12：月度趋势迷你图 ──
    trend_frame = tk.LabelFrame(
        micro_outer, text=t("ur_micro_trend_title"),
        bg="#fafafa", fg="#2c3e50",
        font=("Microsoft YaHei", 8, "bold"), padx=2, pady=2
    )
    trend_frame.pack(fill=tk.X, padx=4, pady=(2, 0))
    gui._ur_micro_trend_canvas = tk.Canvas(
        trend_frame, height=70, bg="white", relief=tk.SOLID, bd=1,
        highlightthickness=0
    )
    gui._ur_micro_trend_canvas.pack(fill=tk.X)
    gui._ur_micro_trend_caption = tk.StringVar(value="")
    tk.Label(trend_frame, textvariable=gui._ur_micro_trend_caption,
             bg="#fafafa", fg="#7f8c8d", font=("Consolas", 7),
             anchor="w", justify=tk.LEFT).pack(fill=tk.X)

    micro_explain_frame = tk.Frame(micro_outer, bg="#fafafa")
    micro_explain_frame.pack(fill=tk.BOTH, expand=False, padx=4, pady=(2, 4))
    tk.Label(micro_explain_frame, text=t("ur_micro_explain_title"), bg="#fafafa",
             fg="#2c3e50", font=("Microsoft YaHei", 9, "bold")).pack(anchor="w")
    gui._ur_micro_explain_text = tk.Text(
        micro_explain_frame, wrap=tk.WORD, font=("Consolas", 8),
        bg="white", relief=tk.SOLID, bd=1, height=8, padx=4, pady=2
    )
    gui._ur_micro_explain_text.pack(fill=tk.BOTH, expand=True)
    gui._ur_micro_explain_text.insert(
        "1.0",
        t("ur_micro_explain_body")
    )
    gui._ur_micro_explain_text.config(state=tk.DISABLED)

    # （micro 缓存已在函数顶部初始化）

    gui._ur_propagation_text = tk.Text(detail_nb, wrap=tk.WORD, font=("Consolas", 9),
                                        bg="#fafafa", relief=tk.FLAT, padx=6, pady=4)
    detail_nb.add(gui._ur_propagation_text, text=t("ur_tab_propagation"))

    gui._ur_trend_text = tk.Text(detail_nb, wrap=tk.WORD, font=("Consolas", 9),
                                  bg="#fafafa", relief=tk.FLAT, padx=6, pady=4)
    detail_nb.add(gui._ur_trend_text, text=t("ur_tab_trend"))

    gui._ur_rules_text = tk.Text(detail_nb, wrap=tk.WORD, font=("Consolas", 9),
                                  bg="#fafafa", relief=tk.FLAT, padx=6, pady=4)
    detail_nb.add(gui._ur_rules_text, text=t("ur_tab_rules"))

    # ─── 下区：预防性维护建议 ─────────────────────────────────────────
    lower = tk.Frame(right_paned, bg="white")
    right_paned.add(lower, minsize=180, height=240)

    # 建议标题栏
    rec_title_bar = tk.Frame(lower, bg="#2c3e50")
    rec_title_bar.pack(fill=tk.X)
    tk.Label(rec_title_bar, text=t("ur_maint_title"), bg="#2c3e50", fg="white",
             font=("Microsoft YaHei", 10, "bold")).pack(side=tk.LEFT, pady=5)
    tk.Label(rec_title_bar, text=t("ur_maint_subtitle"), bg="#2c3e50", fg="#bdc3c7",
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
                gui.root.after(0, lambda: gui._ur_status_var.set(t("ur_status_loading_cache")))
                try:
                    kg = KnowledgeGraph.load_cache(str(cache_path))
                    gui._ur_kg = kg
                    stats = kg.stats()
                    gui.root.after(0, lambda: gui._ur_status_var.set(
                        t("ur_status_loaded", nodes=stats['nodes_total'], edges=stats['edges_total'])))
                    gui.root.after(0, lambda: _ur_update_stats(gui))
                    _ur_run_analysis(gui)
                    return
                except Exception:
                    pass

            gui.root.after(0, lambda: gui._ur_status_var.set(t("ur_status_first_build")))
            kg = KnowledgeGraph.from_sqlite(db_path)
            kg.build(limit_cve=5000, limit_dsa=None)
            try:
                kg.save_cache(str(cache_path))
            except Exception:
                pass
            gui._ur_kg = kg
            stats = kg.stats()
            gui.root.after(0, lambda: gui._ur_status_var.set(
                t("ur_status_build_done", nodes=stats['nodes_total'], edges=stats['edges_total'])))
            gui.root.after(0, lambda: _ur_update_stats(gui))
            _ur_run_analysis(gui)
        except Exception as e:
            gui.root.after(0, lambda: gui._ur_status_var.set(t("ur_status_load_fail", err=e)))

    threading.Thread(target=_worker, daemon=True).start()


def _ur_full_analyze(gui) -> None:
    gui._ur_loaded = True

    def _worker():
        try:
            from knowledge_graph import KnowledgeGraph

            db_path = str(gui.data_dir / "cve_database.db")
            cache_path = gui.data_dir / "kg_cache.pkl"

            gui.root.after(0, lambda: gui._ur_status_var.set(t("ur_status_full_building")))
            kg = KnowledgeGraph.from_sqlite(db_path)
            kg.build(limit_cve=5000, limit_dsa=None)
            try:
                kg.save_cache(str(cache_path))
            except Exception:
                pass
            gui._ur_kg = kg
            stats = kg.stats()
            gui.root.after(0, lambda: gui._ur_status_var.set(
                t("ur_status_build_analyzing", nodes=stats['nodes_total'])))
            gui.root.after(0, lambda: _ur_update_stats(gui))
            _ur_run_analysis(gui)
        except Exception as e:
            gui.root.after(0, lambda: gui._ur_status_var.set(t("ur_status_analyze_fail", err=e)))

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
        t("ur_status_analyze_done", n=n, nodes=gui._ur_kg.stats()['nodes_total'])))


def _ur_update_stats(gui) -> None:
    if gui._ur_kg is None:
        return
    s = gui._ur_kg.stats()
    gui._ur_stats_var.set(
        t("ur_stats_text",
          cve=s.get('node:cve', 0), dsa=s.get('node:dsa', 0),
          product=s.get('node:product', 0), cwe=s.get('node:cwe', 0),
          edges=s.get('edges_total', 0))
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
            tk.Label(gui._ur_canvas_host, text=t("ur_no_related"), bg="#fafafa", fg="#aaa",
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

        ax.set_title(t("ur_graph_title", product=product, nodes=n_nodes, edges=sub.number_of_edges()),
                     fontsize=11, pad=10, color="#2c3e50",
                     fontfamily="Microsoft YaHei", fontweight="bold")

        # 紧凑布局，去除多余边距
        fig.tight_layout(pad=1.0)

        canvas = FigureCanvasTkAgg(fig, master=gui._ur_canvas_host)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        plt.close(fig)
    except Exception as e:
        tk.Label(gui._ur_canvas_host, text=t("ur_render_fail", err=e), bg="#fafafa", fg="red",
                 font=("Microsoft YaHei", 8)).pack(expand=True)


def _ur_fill_details(gui, report) -> None:
    score = report.risk_scores[0] if report.risk_scores else None

    # 评分因子
    gui._ur_score_text.config(state=tk.NORMAL)
    gui._ur_score_text.delete("1.0", tk.END)
    if score:
        lines = [
            t("ur_score_product", product=score.entity_id),
            t("ur_score_overall", score=f"{score.score:.1f}", level=score.level.value),
            "",
            f"{t('ur_score_factor_col'):<16s} {t('ur_score_raw_col'):>6s} {t('ur_score_weight_col'):>5s} {t('ur_score_contrib_col'):>6s}",
            "─" * 38,
        ]
        weights = {"cvss_avg": 0.30, "pagerank": 0.20, "recency": 0.15,
                   "severity_density": 0.15, "cwe_diversity": 0.10, "exposure": 0.10}
        for k, v in score.factors.items():
            w = weights.get(k, 0)
            lines.append(f"{k:<16s} {v:>6.1f} {w:>4.0%}  {v * w:>5.1f}")
        lines.extend(["", t("ur_score_key_cve", cves=', '.join(score.evidence[:5]))])
        gui._ur_score_text.insert("1.0", "\n".join(lines))
    gui._ur_score_text.config(state=tk.DISABLED)

    # 传播分析
    gui._ur_propagation_text.config(state=tk.NORMAL)
    gui._ur_propagation_text.delete("1.0", tk.END)
    if report.impact_paths:
        lines = [f"{t('ur_prop_src_cve'):<16s} {t('ur_prop_target'):<22s} {t('ur_prop_hops'):>2s} {t('ur_prop_conf'):>5s} {t('ur_prop_shared_cwe')}", "─" * 60]
        for p in report.impact_paths[:10]:
            cwes = ",".join(p.shared_cwes[:2])
            lines.append(f"{p.source_cve:<16s} {p.target_product:<22s} {p.hops:>2d} {p.confidence:>4.0%}  {cwes}")
        gui._ur_propagation_text.insert("1.0", "\n".join(lines))
    else:
        gui._ur_propagation_text.insert("1.0", t("ur_prop_none"))
    gui._ur_propagation_text.config(state=tk.DISABLED)

    # 趋势预测
    gui._ur_trend_text.config(state=tk.NORMAL)
    gui._ur_trend_text.delete("1.0", tk.END)
    if report.trend_forecast and report.trend_forecast.method != "no_data":
        f = report.trend_forecast
        trend_map = {"rising": t("ur_trend_rising"), "stable": t("ur_trend_stable"), "declining": t("ur_trend_declining")}
        lines = [
            t("ur_trend_subject", subject=f.subject),
            t("ur_trend_period", days=f.forecast_days),
            t("ur_trend_predicted", count=f.predicted_count, lo=f.confidence_interval[0], hi=f.confidence_interval[1]),
            t("ur_trend_risk", trend=trend_map.get(f.risk_trend, f.risk_trend)),
            t("ur_trend_method"),
            "",
        ]
        if f.hot_cwes:
            lines.append(t("ur_trend_hot_cwe"))
            for cwe, ratio in f.hot_cwes[:5]:
                lines.append(f"  {cwe}: {ratio:.0%}")
        gui._ur_trend_text.insert("1.0", "\n".join(lines))
    else:
        gui._ur_trend_text.insert("1.0", t("ur_trend_insufficient"))
    gui._ur_trend_text.config(state=tk.DISABLED)

    # 触发规则
    gui._ur_rules_text.config(state=tk.NORMAL)
    gui._ur_rules_text.delete("1.0", tk.END)
    if report.rule_matches:
        lines = []
        for m in report.rule_matches:
            lines.append(f"[{m.severity.value}] {m.rule_name}")
            lines.append(t("ur_rule_id_evidence", rid=m.rule_id, ev=', '.join(m.matched_evidence[:3])))
            lines.append("")
        gui._ur_rules_text.insert("1.0", "\n".join(lines))
    else:
        gui._ur_rules_text.insert("1.0", t("ur_rules_none"))
    gui._ur_rules_text.config(state=tk.DISABLED)


def _ur_fill_recommendations(gui, report) -> None:
    for w in gui._ur_rec_inner.winfo_children():
        w.destroy()

    if not report.recommendations:
        tk.Label(gui._ur_rec_inner, text=t("ur_rec_none"),
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
        meta = t("ur_rec_meta", timeline=rec.timeline, atype=rec.action_type, effort=rec.estimated_effort)
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
                t("ur_dsa_calculating")))

            predictor = DSAProductLinePredictor(db_path)
            results = predictor.forecast_all(forecast_days=days)
            gui._ur_dsa_results = results

            gui.root.after(0, lambda: _ur_dsa_render_table(gui, results, days))
        except Exception as e:
            err = str(e)
            gui.root.after(0, lambda: gui._ur_dsa_summary_var.set(t("ur_dsa_predict_fail", err=err)))

    threading.Thread(target=_worker, daemon=True).start()


def _ur_dsa_render_table(gui, results, days: int) -> None:
    """将预测结果渲染到表格 + 摘要"""
    tree = gui._ur_dsa_tree
    for item in tree.get_children():
        tree.delete(item)

    if not results:
        gui._ur_dsa_summary_var.set(t("ur_dsa_no_data"))
        return

    high_count = sum(1 for r in results if r.risk_level in ("CRITICAL", "HIGH"))
    total_dsa = sum(r.historical_dsa_total for r in results)

    gui._ur_dsa_summary_var.set(
        t("ur_dsa_summary", days=days, n=len(results), high=high_count, total=total_dsa)
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
        t("ur_dsa_ci_header"),
        t("ur_dsa_ci_prob", prob=f"{forecast.probability:.1%}"),
        t("ur_dsa_ci_interval", lo=f"{forecast.probability_ci[0]:.1%}", hi=f"{forecast.probability_ci[1]:.1%}"),
        t("ur_dsa_ci_level", level=forecast.risk_level),
        "",
        t("ur_dsa_threshold_header"),
        t("ur_dsa_threshold_1"),
        t("ur_dsa_threshold_2"),
        t("ur_dsa_threshold_3"),
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
        gui._ur_status_var.set(t("ur_export_no_report"))
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
            md = _ur_build_hierarchical_markdown(gui)
            with open(path, "w", encoding="utf-8") as f:
                f.write(md)
        gui._ur_status_var.set(t("ur_export_done", name=Path(path).name))
    except Exception as e:
        gui._ur_status_var.set(t("ur_export_fail", err=e))


def _ur_anchor(text: str) -> str:
    """规范化锚点：保留中英数字，其他转为 -，去除连续 - 和首尾 -"""
    import re
    s = re.sub(r"[^\w一-鿿]+", "-", text.lower())
    return re.sub(r"-+", "-", s).strip("-")


def _ur_build_hierarchical_markdown(gui) -> str:
    """
    P3-15：按产品线分组的层次化 Markdown 报告。

    结构:
        # 智能预测综合报告
        ## 概览
        ## 目录
        ## 产品线 A
            ### DSA 预测（30/60/90 天）
            ### 微码风险 Top N
        ## 产品线 B
            ...
        ## 知识图谱产品评分（如有）
    """
    from collections import defaultdict
    sections = [_ur_build_overview(gui), ""]

    dsa_by_pl: Dict[str, Any] = {}
    for r in gui._ur_dsa_results:
        dsa_by_pl[r.product_line] = r

    micro_by_pl: Dict[str, List[Any]] = defaultdict(list)
    for s in gui._ur_micro_results:
        micro_by_pl[s.key.product_line].append(s)

    # 产品线集合 = 出现在 DSA 预测或微码评分里的所有产品线
    all_pls = sorted(set(dsa_by_pl.keys()) | set(micro_by_pl.keys()))

    # ── TOC ──
    if all_pls:
        sections.append("## 目录")
        sections.append("")
        for pl in all_pls:
            anchor = _ur_anchor(pl)
            sections.append(f"- [{pl}](#{anchor})")
        sections.append("")

    # ── 算法说明（仅一次） ──
    if dsa_by_pl:
        sections.append("## 算法说明")
        sections.append("")
        sections.append("Poisson 速率模型，可解释因子：")
        sections.append("")
        sections.append("```")
        sections.append("λ_eff = λ_base × trend_multiplier × severity_factor + 0.04 × open_cve_pressure")
        sections.append("P(≥1 DSA in D 天) = 1 − exp(−λ_eff × D / 30)")
        sections.append("```")
        sections.append("")
        sections.append("- λ_base: 过去 12 个月该产品线月均 DSA 数")
        sections.append("- trend_multiplier: 近 3 个月速率 / 12 个月基线，裁剪到 [0.5, 3.0]")
        sections.append("- severity_factor: 1 + 0.5 × (近期 CVE 平均 CVSS / 10)，∈ [1.0, 1.5]")
        sections.append("- open_cve_pressure: 近 90 天匹配该产品线但尚未进入 DSA 的 CVE 数")
        sections.append("")
        sections.append("微码 exposure_score：freq_score(50) + severity_score(25) + recency_score(25) + KEV(+5/CVE，上限 +15)")
        sections.append("")

    # ── 按产品线嵌套 ──
    for pl in all_pls:
        anchor = _ur_anchor(pl)
        sections.append(f"## {pl}")
        sections.append("")
        sections.append(f'<a id="{anchor}"></a>')
        sections.append("")

        # DSA 预测
        if pl in dsa_by_pl:
            r = dsa_by_pl[pl]
            sections.append(f"### DSA 概率预测（未来 {r.forecast_days} 天）")
            sections.append("")
            sections.append(
                "| 全量 DSA | 12M | 3M | λ_base | λ_recent | trend | "
                "sev | open | E[DSA] | P(≥1) | 等级 |"
            )
            sections.append(
                "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|:---:|"
            )
            sections.append(
                f"| {r.historical_dsa_total} | {r.historical_dsa_12m} | "
                f"{r.historical_dsa_3m} | {r.base_rate_per_month:.2f} | "
                f"{r.recent_rate_per_month:.2f} | {r.trend_multiplier:.2f} | "
                f"{r.severity_factor:.2f} | {r.open_cve_pressure} | "
                f"{r.expected_dsa_count:.2f} | {r.probability:.1%} | "
                f"{r.risk_level} |"
            )
            sections.append("")

        # 微码评分（按当前产品线过滤后的 Top N，最多 10 条避免冗长）
        if pl in micro_by_pl:
            scores = sorted(micro_by_pl[pl],
                            key=lambda s: s.exposure_score, reverse=True)[:10]
            sections.append(f"### 微码风险 Top {len(scores)}")
            sections.append("")
            sections.append(
                "| 机型 | 类型 | 版本 | exposure | 等级 | KEV | "
                "命中数 | avg CVSS | 距今(月) |"
            )
            sections.append(
                "|---|---|---|---:|:---:|---:|---:|---:|---:|"
            )
            for s in scores:
                last = "—" if s.months_since_last >= 999 else str(s.months_since_last)
                sections.append(
                    f"| {s.key.model} | {s.key.firmware_type} | {s.key.version} | "
                    f"{s.exposure_score:.1f} | {s.risk_band} | {s.kev_hit_count} | "
                    f"{s.expanded_dsa_count} | {s.severity_avg_cvss:.1f} | {last} |"
                )
            sections.append("")

    # ── 知识图谱产品评分（独立段，因不是按产品线分布）──
    if gui._ur_reports and gui._ur_builder:
        sections.append("## 知识图谱产品风险评分")
        sections.append("")
        sections.append("\n\n---\n\n".join(
            gui._ur_builder.to_markdown(r) for r in gui._ur_reports
        ))

    return "\n".join(sections)




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
                    t("ur_micro_status_1")))
                assessor = MicrocodeRiskAssessor(db_path)
                gui.root.after(0, lambda: gui._ur_micro_summary_var.set(
                    t("ur_micro_status_2")))
                assessor._build_index()
                gui.root.after(0, lambda: gui._ur_micro_summary_var.set(
                    t("ur_micro_status_3")))
                assessor._ensure_global_max_expanded()
                gui._ur_micro_assessor = assessor
            else:
                gui.root.after(0, lambda: gui._ur_micro_summary_var.set(
                    t("ur_micro_status_cache")))

            gui.root.after(0, lambda: gui._ur_micro_summary_var.set(
                t("ur_micro_status_4")))
            results = gui._ur_micro_assessor.assess_all(top=50)
            gui._ur_micro_results = results

            gui.root.after(0, lambda: _ur_micro_render_table(gui, results))
        except Exception as e:
            err = str(e)
            gui.root.after(0, lambda: gui._ur_micro_summary_var.set(
                t("ur_micro_assess_fail", err=err)))

    threading.Thread(target=_worker, daemon=True).start()


def _ur_micro_render_table(gui, results) -> None:
    """将微码评估结果渲染到表格（受 filter_var 与产品线下拉框过滤）"""
    tree = gui._ur_micro_tree
    for item in tree.get_children():
        tree.delete(item)

    if not results:
        gui._ur_micro_summary_var.set(t("ur_micro_no_data"))
        return

    # 首次渲染时填入产品线下拉框选项
    combo = getattr(gui, "_ur_micro_pl_combo", None)
    if combo is not None and not combo["values"]:
        all_lines = sorted({s.key.product_line for s in results})
        combo["values"] = [t("ur_micro_pl_all")] + all_lines

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
    pl_filter = pl_var.get() if pl_var else t("ur_micro_pl_all")
    if pl_filter and pl_filter != t("ur_micro_pl_all"):
        view = [s for s in view if s.key.product_line == pl_filter]

    from collections import Counter
    bands = Counter(s.risk_band for s in view)
    kev_total = sum(s.kev_hit_count for s in view)
    gui._ur_micro_summary_var.set(
        t("ur_micro_summary",
          shown=len(view), total=len(results),
          ext=bands.get('EXTREME', 0), high=bands.get('HIGH', 0),
          med=bands.get('MEDIUM', 0), low=bands.get('LOW', 0),
          kev=kev_total)
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
    """选中微码版本后展示因子拆解 + 月度趋势迷你图"""
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

    # P2-12：迷你图（同步绘制，从已构建索引取数据，毫秒级）
    canvas = getattr(gui, "_ur_micro_trend_canvas", None)
    caption = getattr(gui, "_ur_micro_trend_caption", None)
    if canvas is None or caption is None:
        return
    if gui._ur_micro_assessor is None:
        return
    try:
        series = gui._ur_micro_assessor.monthly_hits(score.key, months=12)
    except Exception:
        return
    _ur_micro_draw_trend(canvas, caption, series, score)


def _ur_micro_draw_trend(canvas: tk.Canvas, caption_var: tk.StringVar,
                          series, score) -> None:
    """在 Canvas 上绘制 12 月柱状图。每月一根，按比例高，缺月留白。"""
    canvas.delete("all")
    canvas.update_idletasks()
    w = canvas.winfo_width() or 280
    h = canvas.winfo_height() or 70

    if not series:
        canvas.create_text(w / 2, h / 2, text=t("ur_chart_no_data"),
                            fill="#bdc3c7", font=("Consolas", 8))
        caption_var.set("")
        return

    counts = [c for _, c in series]
    max_c = max(counts) if counts else 1
    if max_c == 0:
        canvas.create_text(
            w / 2, h / 2, text=t("ur_micro_trend_no_data"),
            fill="#bdc3c7", font=("Consolas", 8)
        )
        caption_var.set("")
        return

    pad_l, pad_r, pad_t, pad_b = 4, 4, 4, 14
    plot_w = w - pad_l - pad_r
    plot_h = h - pad_t - pad_b
    bar_w = plot_w / len(series)

    # 风险带颜色
    band_color = {
        "EXTREME": "#c0392b", "HIGH": "#d35400",
        "MEDIUM": "#b7950b", "LOW": "#2980b9",
        "MINIMAL": "#95a5a6",
    }.get(score.risk_band, "#7f8c8d")

    for i, (label, cnt) in enumerate(series):
        x0 = pad_l + i * bar_w + 1
        x1 = pad_l + (i + 1) * bar_w - 1
        bar_h = (cnt / max_c) * plot_h if max_c > 0 else 0
        y0 = pad_t + plot_h - bar_h
        y1 = pad_t + plot_h
        if cnt > 0:
            canvas.create_rectangle(x0, y0, x1, y1,
                                     fill=band_color, outline="")
            # 命中数标注（高于 0 的柱顶）
            canvas.create_text((x0 + x1) / 2, y0 - 1,
                                text=str(cnt), anchor="s",
                                font=("Consolas", 6), fill="#2c3e50")
        # 月份 x 轴（只画 1/4/7/10 月，避免拥挤）
        month = label.split("-")[1]
        if month in ("01", "04", "07", "10"):
            canvas.create_text((x0 + x1) / 2, h - 2,
                                text=label[2:], anchor="s",
                                font=("Consolas", 6), fill="#7f8c8d")

    total = sum(counts)
    nonzero_months = sum(1 for c in counts if c > 0)
    last_3 = sum(counts[-3:])
    prev_3 = sum(counts[-6:-3]) if len(counts) >= 6 else 0
    if prev_3 == 0 and last_3 == 0:
        trend = t("ur_micro_trend_none")
    elif prev_3 == 0:
        trend = t("ur_micro_trend_new")
    elif last_3 > prev_3 * 1.5:
        trend = t("ur_micro_trend_accel")
    elif last_3 < prev_3 * 0.5:
        trend = t("ur_micro_trend_cool")
    else:
        trend = t("ur_micro_trend_steady")
    caption_var.set(t(
        "ur_micro_trend_caption",
        total=total, months=nonzero_months,
        last3=last_3, prev3=prev_3, trend=trend,
    ))


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
            t("ur_micro_query_need_init")
        )
        return

    model = gui._ur_query_model_var.get().strip()
    ftype = gui._ur_query_ftype_var.get().strip() or None
    version = gui._ur_query_version_var.get().strip() or None
    if not model and not version:
        gui._ur_query_result_var.set(
            t("ur_micro_query_need_input")
        )
        return

    try:
        results = gui._ur_micro_assessor.query_by_microcode(
            model=model, firmware_type=ftype, version=version
        )
    except Exception as e:
        gui._ur_query_result_var.set(t("ur_micro_query_fail", err=e))
        return

    if not results:
        gui._ur_query_result_var.set(
            t("ur_micro_query_no_hit", model=repr(model), ftype=repr(ftype), version=repr(version))
        )
        return

    # 摘要 + 最近 3 条
    kev_total = sum(len(r["kev_cves"]) for r in results)
    lines = [
        t("ur_micro_query_hit_header", n=len(results), kev=kev_total),
        "─" * 40,
    ]
    for r in results[:5]:
        pub = r["published"].strftime("%Y-%m")
        kev_mark = f" ⚠KEV{len(r['kev_cves'])}" if r["kev_cves"] else ""
        title = r["title"][:50]
        lines.append(f"  [{pub}] CVSS {r['avg_cvss']:.1f}{kev_mark}")
        lines.append(f"    {title}")
    if len(results) > 5:
        lines.append(t("ur_micro_query_more", n=len(results) - 5))
    gui._ur_query_result_var.set("\n".join(lines))


