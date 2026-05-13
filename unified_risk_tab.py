"""
趋势预测标签页模块

布局设计（上下两区）：
┌─────────────────────────────────────────────────────────────────────┐
│ 工具栏: [全量分析] [导出]  状态信息                                   │
├──────────────┬──────────────────────────────────────────────────────┤
│ 产品风险排名  │  上区：知识图谱可视化 + 评分/传播/趋势/规则 Notebook   │
│ (Treeview)   │                                                      │
├──────────────┼──────────────────────────────────────────────────────┤
│ 图谱统计     │  下区：预防性维护建议（卡片列表）+ 算法说明            │
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

    root = tk.Frame(gui.unified_risk_frame, bg="#f5f6fa")
    root.pack(fill=tk.BOTH, expand=True)

    # ── 工具栏 ────────────────────────────────────────────────────────
    toolbar = tk.Frame(root, bg="white", relief=tk.FLAT, bd=0)
    toolbar.pack(fill=tk.X, padx=0, pady=0)
    toolbar_inner = tk.Frame(toolbar, bg="white")
    toolbar_inner.pack(fill=tk.X, padx=12, pady=6)

    tk.Button(toolbar_inner, text="▶ 全量分析", command=lambda: _ur_full_analyze(gui),
              bg="#2c3e50", fg="white", relief=tk.FLAT, cursor="hand2",
              font=("Microsoft YaHei", 9, "bold"), padx=16, pady=5).pack(side=tk.LEFT)

    tk.Button(toolbar_inner, text="导出报告", command=lambda: _ur_export(gui, "md"),
              bg="#27ae60", fg="white", relief=tk.FLAT, cursor="hand2",
              font=("Microsoft YaHei", 9), padx=10, pady=5).pack(side=tk.LEFT, padx=(8, 0))

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
    body.add(right, minsize=500)

    right_paned = tk.PanedWindow(right, orient=tk.VERTICAL, bg="#ecf0f1", sashwidth=4, sashrelief=tk.FLAT)
    right_paned.pack(fill=tk.BOTH, expand=True)

    # ─── 上区：图谱 + 分析详情 ───────────────────────────────────────
    upper = tk.Frame(right_paned, bg="white")
    right_paned.add(upper, minsize=200)

    upper_paned = tk.PanedWindow(upper, orient=tk.HORIZONTAL, bg="#ecf0f1", sashwidth=3)
    upper_paned.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

    # 图谱画布
    graph_frame = tk.Frame(upper_paned, bg="white")
    upper_paned.add(graph_frame, minsize=280)
    tk.Label(graph_frame, text="知识图谱", bg="white", fg="#2c3e50",
             font=("Microsoft YaHei", 9, "bold")).pack(anchor="w", padx=6, pady=(4, 0))
    gui._ur_canvas_host = tk.Frame(graph_frame, bg="#fafafa", relief=tk.SUNKEN, bd=1)
    gui._ur_canvas_host.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

    # 分析详情 Notebook
    detail_frame = tk.Frame(upper_paned, bg="white")
    upper_paned.add(detail_frame, minsize=280)

    detail_nb = ttk.Notebook(detail_frame)
    detail_nb.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

    gui._ur_score_text = tk.Text(detail_nb, wrap=tk.WORD, font=("Consolas", 9),
                                  bg="#fafafa", relief=tk.FLAT, padx=6, pady=4)
    detail_nb.add(gui._ur_score_text, text="评分因子")

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
    right_paned.add(lower, minsize=150)

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

        fig, ax = plt.subplots(figsize=(5.5, 3.5), dpi=85)
        fig.patch.set_facecolor("#fafafa")
        # 设置中文字体
        plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei", "DejaVu Sans"]
        plt.rcParams["axes.unicode_minus"] = False
        draw_subgraph(sub, ax, layout="spring", seed=42)
        ax.set_title(product, fontsize=8, pad=6, color="#555",
                     fontfamily="Microsoft YaHei")

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


def _ur_export(gui, fmt: str) -> None:
    if not gui._ur_reports:
        gui._ur_status_var.set("无报告可导出，请先执行分析")
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
            data = [r.to_dict() for r in gui._ur_reports]
            with open(path, "w", encoding="utf-8") as f:
                _json.dump(data, f, ensure_ascii=False, indent=2)
        else:
            parts = [gui._ur_builder.to_markdown(r) for r in gui._ur_reports]
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n\n---\n\n".join(parts))
        gui._ur_status_var.set(f"已导出: {Path(path).name}")
    except Exception as e:
        gui._ur_status_var.set(f"导出失败: {e}")
