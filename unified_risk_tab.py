"""
统一知识图谱与风险分析 Tab 模块

将知识图谱可视化和风险分析合并为单一标签页：
- 自动加载（缓存优先）
- 一键全量分析
- 产品选中联动（图谱 + 报告 + 维护建议）
- 突出预防性维护建议
- 算法与数据说明

设计原则：
- 减少人工输入，默认全量数据库
- 自动化操作流程
- 高质量交付物输出
"""
from __future__ import annotations

import threading
import tkinter as tk
from tkinter import ttk, filedialog
from pathlib import Path
from typing import Any, Dict, List, Optional


# 优先级颜色映射
PRIORITY_COLORS = {
    "P0": "#e74c3c",  # 红
    "P1": "#e67e22",  # 橙
    "P2": "#f39c12",  # 黄
    "P3": "#3498db",  # 蓝
    "P4": "#95a5a6",  # 灰
}

ALGORITHM_INFO = """━━━ 评分模型 ━━━
RiskScore = 0.30×CVSS均分 + 0.20×PageRank
          + 0.15×时间衰减 + 0.10×严重度密度
          + 0.15×CWE多样性 + 0.10×暴露度

━━━ 因子说明 ━━━
• CVSS均分: 产品关联CVE的CVSS分数平均值(0-10→0-100)
• PageRank: 节点在图中的结构重要性(NetworkX alpha=0.85)
• 时间衰减: exp(-days/90), 最新CVE越近分越高
• 严重度密度: Critical×1.0 + High×0.7 + Medium×0.4 + Low×0.1
• CWE多样性: 关联不同CWE数量/全图CWE总数(攻击面广度)
• 暴露度: 共享CVE的邻居产品数/全产品数

━━━ 数据来源 ━━━
• SQLite: cves表(NVD数据) + dell_advisories表(Dell安全公告)
• 图谱节点: CVE(蓝) / DSA(橙) / Product(绿) / CWE(紫)
• 图谱边: mentions(DSA→CVE) / affects(DSA→Product) / classified_as(CVE→CWE)

━━━ 规则引擎 ━━━
• 10条YAML声明式规则(risk/rules/*.yaml)
• 覆盖: RCE/提权/注入/认证绕过/DoS/信息泄露/内存安全/弱加密/陈旧漏洞/高风险产品
• 操作符: equals/in/greater_than/contains/regex 等8种

━━━ 趋势预测 ━━━
• 方法: 6个月滑动窗口月度CVE计数 → 线性回归外推
• 输出: 未来30天预测新增CVE数 + 置信区间 + 趋势方向
"""


# ════════════════════════════════════════════════════════════════════════════


def create_unified_risk_view(gui) -> None:
    """在 gui.unified_risk_frame 中构建统一的知识图谱与风险分析界面"""
    gui._ur_kg = None
    gui._ur_builder = None
    gui._ur_reports: List[Any] = []
    gui._ur_loaded = False

    root_frame = tk.Frame(gui.unified_risk_frame, bg="white")
    root_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

    # ── 顶部标题 ──────────────────────────────────────────────────────
    header = tk.Frame(root_frame, bg="#fef3e2")
    header.pack(fill=tk.X, pady=(0, 6))
    tk.Label(header, text="知识图谱与风险分析", bg="#fef3e2", fg="#d35400",
             font=("Microsoft YaHei", 14, "bold")).pack(anchor="w", padx=10, pady=(6, 0))
    tk.Label(header, text="基于图谱的多因子风险评分 · 传播分析 · 趋势预测 · 预防性维护建议",
             bg="#fef3e2", fg="#666", font=("Microsoft YaHei", 9)).pack(anchor="w", padx=10, pady=(0, 6))

    # ── 工具栏 ────────────────────────────────────────────────────────
    toolbar = tk.Frame(root_frame, bg="#f8f8f8", relief=tk.GROOVE, bd=1)
    toolbar.pack(fill=tk.X, pady=(0, 6))

    tk.Button(toolbar, text="全量分析", command=lambda: _ur_full_analyze(gui),
              bg="#d35400", fg="white", relief=tk.FLAT,
              font=("Microsoft YaHei", 9, "bold"), padx=14, pady=4).pack(side=tk.LEFT, padx=6, pady=4)

    tk.Button(toolbar, text="导出 Markdown", command=lambda: _ur_export(gui, "md"),
              bg="#27ae60", fg="white", relief=tk.FLAT, padx=8, pady=4).pack(side=tk.LEFT, padx=2, pady=4)
    tk.Button(toolbar, text="导出 JSON", command=lambda: _ur_export(gui, "json"),
              bg="#2980b9", fg="white", relief=tk.FLAT, padx=8, pady=4).pack(side=tk.LEFT, padx=2, pady=4)

    gui._ur_status_var = tk.StringVar(value="点击「全量分析」或切换到此标签页自动加载")
    tk.Label(toolbar, textvariable=gui._ur_status_var, bg="#f8f8f8", fg="#555",
             font=("Microsoft YaHei", 8)).pack(side=tk.RIGHT, padx=10, pady=4)

    # ── 三栏主体 ──────────────────────────────────────────────────────
    paned = tk.PanedWindow(root_frame, orient=tk.HORIZONTAL, bg="#ddd", sashwidth=3)
    paned.pack(fill=tk.BOTH, expand=True)

    # ─── 左栏：产品风险排名 + 统计 ───────────────────────────────────
    left = tk.Frame(paned, bg="white")
    paned.add(left, minsize=220, width=260)

    tk.Label(left, text="产品风险排名", bg="white",
             font=("Microsoft YaHei", 10, "bold"), fg="#333").pack(anchor="w", padx=4, pady=(4, 2))

    tree_frame = tk.Frame(left, bg="white")
    tree_frame.pack(fill=tk.BOTH, expand=True, padx=2)

    gui._ur_tree = ttk.Treeview(tree_frame, columns=("product", "score", "level"),
                                 show="headings", height=18)
    gui._ur_tree.heading("product", text="产品")
    gui._ur_tree.heading("score", text="评分")
    gui._ur_tree.heading("level", text="等级")
    gui._ur_tree.column("product", width=140)
    gui._ur_tree.column("score", width=50, anchor="center")
    gui._ur_tree.column("level", width=70, anchor="center")

    tree_sb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=gui._ur_tree.yview)
    gui._ur_tree.configure(yscrollcommand=tree_sb.set)
    gui._ur_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    tree_sb.pack(side=tk.RIGHT, fill=tk.Y)
    gui._ur_tree.bind("<<TreeviewSelect>>", lambda e: _ur_on_select(gui))

    # 统计区
    stats_lf = tk.LabelFrame(left, text="图谱统计", bg="white", font=("Microsoft YaHei", 8))
    stats_lf.pack(fill=tk.X, padx=4, pady=(4, 2))
    gui._ur_stats_var = tk.StringVar(value="尚未加载")
    tk.Label(stats_lf, textvariable=gui._ur_stats_var, bg="white", fg="#555",
             font=("Consolas", 8), justify=tk.LEFT, anchor="w").pack(fill=tk.X, padx=4, pady=2)

    # ─── 中栏：图谱可视化 + 详细分析 ─────────────────────────────────
    center = tk.Frame(paned, bg="white")
    paned.add(center, minsize=350)

    # 图谱画布
    gui._ur_canvas_frame = tk.LabelFrame(center, text="知识图谱可视化", bg="white",
                                          font=("Microsoft YaHei", 9))
    gui._ur_canvas_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=(0, 4))
    gui._ur_canvas_host = tk.Frame(gui._ur_canvas_frame, bg="#fafafa")
    gui._ur_canvas_host.pack(fill=tk.BOTH, expand=True)

    # 详细分析 Notebook
    detail_nb = ttk.Notebook(center)
    detail_nb.pack(fill=tk.BOTH, expand=True, padx=2)

    gui._ur_score_text = tk.Text(detail_nb, wrap=tk.WORD, font=("Consolas", 9),
                                  bg="#fafafa", height=8, relief=tk.FLAT)
    detail_nb.add(gui._ur_score_text, text="评分因子")

    gui._ur_propagation_text = tk.Text(detail_nb, wrap=tk.WORD, font=("Consolas", 9),
                                        bg="#fafafa", height=8, relief=tk.FLAT)
    detail_nb.add(gui._ur_propagation_text, text="传播分析")

    gui._ur_trend_text = tk.Text(detail_nb, wrap=tk.WORD, font=("Consolas", 9),
                                  bg="#fafafa", height=8, relief=tk.FLAT)
    detail_nb.add(gui._ur_trend_text, text="趋势预测")

    gui._ur_rules_text = tk.Text(detail_nb, wrap=tk.WORD, font=("Consolas", 9),
                                  bg="#fafafa", height=8, relief=tk.FLAT)
    detail_nb.add(gui._ur_rules_text, text="触发规则")

    # ─── 右栏：预防性维护建议 + 算法说明 ─────────────────────────────
    right = tk.Frame(paned, bg="white")
    paned.add(right, minsize=260, width=300)

    # 维护建议区
    rec_header = tk.Frame(right, bg="#e74c3c")
    rec_header.pack(fill=tk.X)
    tk.Label(rec_header, text="★ 预防性维护建议", bg="#e74c3c", fg="white",
             font=("Microsoft YaHei", 10, "bold")).pack(anchor="w", padx=8, pady=4)

    rec_container = tk.Frame(right, bg="white")
    rec_container.pack(fill=tk.BOTH, expand=True)

    rec_canvas = tk.Canvas(rec_container, bg="white", highlightthickness=0)
    rec_scrollbar = ttk.Scrollbar(rec_container, orient=tk.VERTICAL, command=rec_canvas.yview)
    gui._ur_rec_inner = tk.Frame(rec_canvas, bg="white")
    gui._ur_rec_inner.bind("<Configure>", lambda e: rec_canvas.configure(scrollregion=rec_canvas.bbox("all")))
    rec_canvas.create_window((0, 0), window=gui._ur_rec_inner, anchor="nw")
    rec_canvas.configure(yscrollcommand=rec_scrollbar.set)
    rec_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    rec_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # 算法说明（可折叠）
    algo_frame = tk.Frame(right, bg="white")
    algo_frame.pack(fill=tk.X, side=tk.BOTTOM)
    gui._ur_algo_expanded = False
    gui._ur_algo_btn = tk.Button(algo_frame, text="算法与数据说明 ▶", bg="#ecf0f1",
                                  fg="#333", relief=tk.FLAT, anchor="w",
                                  font=("Microsoft YaHei", 8, "bold"),
                                  command=lambda: _ur_toggle_algo(gui))
    gui._ur_algo_btn.pack(fill=tk.X, padx=2, pady=2)
    gui._ur_algo_text = tk.Text(algo_frame, wrap=tk.WORD, font=("Consolas", 8),
                                 bg="#f9f9f9", fg="#444", height=0, relief=tk.FLAT)
    gui._ur_algo_text.insert("1.0", ALGORITHM_INFO)
    gui._ur_algo_text.config(state=tk.DISABLED)

    # 绑定 Tab 切换事件实现懒加载
    gui.notebook.bind("<<NotebookTabChanged>>", lambda e: _ur_on_tab_changed(gui), add="+")


# ════════════════════════════════════════════════════════════════════════════
# 事件处理
# ════════════════════════════════════════════════════════════════════════════

def _ur_toggle_algo(gui) -> None:
    """折叠/展开算法说明"""
    if gui._ur_algo_expanded:
        gui._ur_algo_text.pack_forget()
        gui._ur_algo_btn.config(text="算法与数据说明 ▶")
        gui._ur_algo_expanded = False
    else:
        gui._ur_algo_text.config(height=16)
        gui._ur_algo_text.pack(fill=tk.X, padx=2, pady=(0, 2))
        gui._ur_algo_expanded = True
        gui._ur_algo_btn.config(text="算法与数据说明 ▼")


def _ur_on_tab_changed(gui) -> None:
    """Tab 切换时自动加载"""
    try:
        current = gui.notebook.index(gui.notebook.select())
        unified_idx = gui.notebook.index(gui.unified_risk_tab_id)
        if current == unified_idx and not gui._ur_loaded:
            gui._ur_loaded = True
            _ur_auto_load(gui)
    except (tk.TclError, ValueError):
        pass


def _ur_auto_load(gui) -> None:
    """自动加载：缓存优先，后台线程"""
    def _worker():
        try:
            from knowledge_graph import KnowledgeGraph
            from risk.report_builder import RiskReportBuilder

            cache_path = gui.data_dir / "kg_cache.pkl"
            db_path = str(gui.data_dir / "cve_database.db")

            # 缓存优先
            if cache_path.exists():
                gui.root.after(0, lambda: gui._ur_status_var.set("正在从缓存加载知识图谱..."))
                try:
                    kg = KnowledgeGraph.load_cache(str(cache_path))
                    gui._ur_kg = kg
                    gui.root.after(0, lambda: gui._ur_status_var.set(
                        f"已从缓存加载 ({kg.stats()['nodes_total']} 节点, {kg.stats()['edges_total']} 边)"))
                    gui.root.after(0, lambda: _ur_update_stats(gui))
                    _ur_run_analysis(gui)
                    return
                except Exception:
                    pass

            # 无缓存：全量构建
            gui.root.after(0, lambda: gui._ur_status_var.set("首次加载，正在构建知识图谱（约30秒）..."))
            kg = KnowledgeGraph.from_sqlite(db_path)
            kg.build(limit_cve=5000, limit_dsa=None)
            try:
                kg.save_cache(str(cache_path))
            except Exception:
                pass
            gui._ur_kg = kg
            gui.root.after(0, lambda: gui._ur_status_var.set(
                f"构建完成 ({kg.stats()['nodes_total']} 节点, {kg.stats()['edges_total']} 边)"))
            gui.root.after(0, lambda: _ur_update_stats(gui))
            _ur_run_analysis(gui)

        except Exception as e:
            gui.root.after(0, lambda: gui._ur_status_var.set(f"加载失败: {e}"))

    threading.Thread(target=_worker, daemon=True).start()


def _ur_full_analyze(gui) -> None:
    """全量分析按钮：重建 KG + 重新分析"""
    gui._ur_loaded = True

    def _worker():
        try:
            from knowledge_graph import KnowledgeGraph
            from risk.report_builder import RiskReportBuilder

            db_path = str(gui.data_dir / "cve_database.db")
            cache_path = gui.data_dir / "kg_cache.pkl"

            gui.root.after(0, lambda: gui._ur_status_var.set("正在全量构建知识图谱..."))
            kg = KnowledgeGraph.from_sqlite(db_path)
            kg.build(limit_cve=5000, limit_dsa=None)
            try:
                kg.save_cache(str(cache_path))
            except Exception:
                pass
            gui._ur_kg = kg
            gui.root.after(0, lambda: gui._ur_status_var.set(
                f"构建完成 ({kg.stats()['nodes_total']} 节点)，正在分析风险..."))
            gui.root.after(0, lambda: _ur_update_stats(gui))
            _ur_run_analysis(gui)

        except Exception as e:
            gui.root.after(0, lambda: gui._ur_status_var.set(f"分析失败: {e}"))

    threading.Thread(target=_worker, daemon=True).start()


def _ur_run_analysis(gui) -> None:
    """执行风险分析（在工作线程中调用）"""
    from risk.report_builder import RiskReportBuilder

    builder = RiskReportBuilder(gui._ur_kg)
    gui._ur_builder = builder
    reports = builder.analyze_top_products(k=15, min_score=15.0)
    gui._ur_reports = reports

    gui.root.after(0, lambda: _ur_display_results(gui, reports))
    gui.root.after(0, lambda: gui._ur_status_var.set(
        f"分析完成: {len(reports)} 个风险产品 | "
        f"{gui._ur_kg.stats()['nodes_total']} 节点, {gui._ur_kg.stats()['edges_total']} 边"))


def _ur_update_stats(gui) -> None:
    """更新左下角统计"""
    if gui._ur_kg is None:
        return
    stats = gui._ur_kg.stats()
    text = (
        f"CVE: {stats.get('node:cve', 0)}  DSA: {stats.get('node:dsa', 0)}\n"
        f"产品: {stats.get('node:product', 0)}  CWE: {stats.get('node:cwe', 0)}\n"
        f"边: {stats.get('edges_total', 0)}  构建: {stats.get('build_time', 'N/A')[:16]}"
    )
    gui._ur_stats_var.set(text)


def _ur_display_results(gui, reports) -> None:
    """填充左侧产品排名列表"""
    for item in gui._ur_tree.get_children():
        gui._ur_tree.delete(item)

    for report in reports:
        if not report.risk_scores:
            continue
        score = report.risk_scores[0]
        gui._ur_tree.insert("", tk.END, values=(
            score.entity_id, f"{score.score:.1f}", score.level.value
        ))

    # 自动选中第一个
    children = gui._ur_tree.get_children()
    if children:
        gui._ur_tree.selection_set(children[0])
        _ur_on_select(gui)


def _ur_on_select(gui) -> None:
    """产品选中：联动图谱 + 报告 + 建议"""
    selection = gui._ur_tree.selection()
    if not selection:
        return
    item = gui._ur_tree.item(selection[0])
    product = item["values"][0]

    # 查找对应报告
    report = None
    for r in gui._ur_reports:
        if r.subject == product:
            report = r
            break

    if report is None:
        return

    # 1. 渲染图谱
    _ur_render_graph(gui, product)
    # 2. 填充详细分析
    _ur_fill_details(gui, report)
    # 3. 填充维护建议
    _ur_fill_recommendations(gui, report)


def _ur_render_graph(gui, product: str) -> None:
    """渲染产品的 ego_subgraph"""
    if gui._ur_kg is None:
        return

    # 清除旧画布
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
            tk.Label(gui._ur_canvas_host, text="(无图谱数据)", bg="#fafafa", fg="#999").pack(expand=True)
            return

        fig, ax = plt.subplots(figsize=(6, 4), dpi=90)
        fig.patch.set_facecolor("#fafafa")
        draw_subgraph(sub, ax, layout="spring", seed=42)
        ax.set_title(f"{product} 关联图谱 (radius=1)", fontsize=9, pad=8)

        canvas = FigureCanvasTkAgg(fig, master=gui._ur_canvas_host)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        plt.close(fig)
    except Exception as e:
        tk.Label(gui._ur_canvas_host, text=f"图谱渲染失败: {e}", bg="#fafafa", fg="red").pack(expand=True)


def _ur_fill_details(gui, report) -> None:
    """填充中栏详细分析 Notebook"""
    score = report.risk_scores[0] if report.risk_scores else None

    # 评分因子
    gui._ur_score_text.config(state=tk.NORMAL)
    gui._ur_score_text.delete("1.0", tk.END)
    if score:
        lines = [f"产品: {score.entity_id}", f"综合评分: {score.score:.1f} / 100 ({score.level.value})", ""]
        lines.append(f"{'因子':<16s} {'得分':>6s} {'权重':>6s} {'贡献':>6s}")
        lines.append("-" * 40)
        weights = {"cvss_avg": 0.30, "pagerank": 0.20, "recency": 0.15,
                   "severity_density": 0.15, "cwe_diversity": 0.10, "exposure": 0.10}
        for k, v in score.factors.items():
            w = weights.get(k, 0)
            lines.append(f"{k:<16s} {v:>6.1f} {w:>5.0%} {v * w:>6.1f}")
        lines.append("")
        lines.append(f"关键证据 CVE: {', '.join(score.evidence[:5])}")
        gui._ur_score_text.insert("1.0", "\n".join(lines))
    gui._ur_score_text.config(state=tk.DISABLED)

    # 传播分析
    gui._ur_propagation_text.config(state=tk.NORMAL)
    gui._ur_propagation_text.delete("1.0", tk.END)
    if report.impact_paths:
        lines = [f"{'源CVE':<18s} {'影响产品':<25s} {'跳数':>4s} {'可信度':>6s} {'共享CWE'}"]
        lines.append("-" * 70)
        for p in report.impact_paths[:12]:
            cwes = ",".join(p.shared_cwes[:2])
            lines.append(f"{p.source_cve:<18s} {p.target_product:<25s} {p.hops:>4d} {p.confidence:>5.0%}  {cwes}")
        gui._ur_propagation_text.insert("1.0", "\n".join(lines))
    else:
        gui._ur_propagation_text.insert("1.0", "无传播路径数据（产品关联的高危CVE较少）")
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
            f"预测新增 CVE: {f.predicted_count} 个",
            f"置信区间: [{f.confidence_interval[0]}, {f.confidence_interval[1]}]",
            f"风险趋势: {trend_map.get(f.risk_trend, f.risk_trend)}",
            f"预测方法: {f.method}",
            "",
        ]
        if f.hot_cwes:
            lines.append("近期高频 CWE:")
            for cwe, ratio in f.hot_cwes[:5]:
                lines.append(f"  {cwe}: {ratio:.0%}")
        gui._ur_trend_text.insert("1.0", "\n".join(lines))
    else:
        gui._ur_trend_text.insert("1.0", "数据不足，无法生成趋势预测")
    gui._ur_trend_text.config(state=tk.DISABLED)

    # 触发规则
    gui._ur_rules_text.config(state=tk.NORMAL)
    gui._ur_rules_text.delete("1.0", tk.END)
    if report.rule_matches:
        lines = []
        for m in report.rule_matches:
            lines.append(f"[{m.severity.value}] {m.rule_name} (规则 {m.rule_id})")
            lines.append(f"  匹配证据: {', '.join(m.matched_evidence[:3])}")
            lines.append("")
        gui._ur_rules_text.insert("1.0", "\n".join(lines))
    else:
        gui._ur_rules_text.insert("1.0", "未触发任何安全规则（产品风险较低）")
    gui._ur_rules_text.config(state=tk.DISABLED)


def _ur_fill_recommendations(gui, report) -> None:
    """填充右栏预防性维护建议"""
    # 清除旧内容
    for w in gui._ur_rec_inner.winfo_children():
        w.destroy()

    if not report.recommendations:
        tk.Label(gui._ur_rec_inner, text="当前产品无需紧急维护操作",
                 bg="white", fg="#888", font=("Microsoft YaHei", 9)).pack(padx=8, pady=20)
        return

    for i, rec in enumerate(report.recommendations[:10]):
        card = tk.Frame(gui._ur_rec_inner, bg="white", relief=tk.GROOVE, bd=1)
        card.pack(fill=tk.X, padx=4, pady=3)

        # 优先级色条
        color = PRIORITY_COLORS.get(rec.priority.value, "#95a5a6")
        color_bar = tk.Frame(card, bg=color, width=4)
        color_bar.pack(side=tk.LEFT, fill=tk.Y)

        content = tk.Frame(card, bg="white")
        content.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6, pady=4)

        # 标题行
        title_frame = tk.Frame(content, bg="white")
        title_frame.pack(fill=tk.X)
        tk.Label(title_frame, text=f"[{rec.priority.value}]", bg=color, fg="white",
                 font=("Consolas", 8, "bold"), padx=4).pack(side=tk.LEFT)
        tk.Label(title_frame, text=rec.title, bg="white", fg="#222",
                 font=("Microsoft YaHei", 9, "bold"), wraplength=220, justify=tk.LEFT).pack(
            side=tk.LEFT, padx=4)

        # 详情行
        detail = f"{rec.timeline} | {rec.action_type} | 工作量: {rec.estimated_effort}"
        tk.Label(content, text=detail, bg="white", fg="#666",
                 font=("Microsoft YaHei", 8)).pack(anchor="w")

        # 描述（截断）
        if rec.description:
            desc = rec.description[:80] + ("..." if len(rec.description) > 80 else "")
            tk.Label(content, text=desc, bg="white", fg="#888",
                     font=("Microsoft YaHei", 8), wraplength=240, justify=tk.LEFT).pack(anchor="w")


def _ur_export(gui, fmt: str) -> None:
    """导出报告"""
    if not gui._ur_reports:
        gui._ur_status_var.set("无报告可导出，请先执行分析")
        return

    if fmt == "md":
        path = filedialog.asksaveasfilename(
            defaultextension=".md", filetypes=[("Markdown", "*.md")],
            initialfile="risk_analysis_report.md")
    else:
        path = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON", "*.json")],
            initialfile="risk_analysis_report.json")

    if not path:
        return

    try:
        import json
        if fmt == "json":
            data = [r.to_dict() for r in gui._ur_reports]
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        else:
            lines = []
            for report in gui._ur_reports:
                lines.append(gui._ur_builder.to_markdown(report))
                lines.append("\n\n---\n\n")
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
        gui._ur_status_var.set(f"已导出: {path}")
    except Exception as e:
        gui._ur_status_var.set(f"导出失败: {e}")
