# 产品系列 DSA 预测模块使用手册

## 目录
- [1. 快速开始](#1-快速开始)
- [2. API 使用示例](#2-api-使用示例)
- [3. 典型场景](#3-典型场景)
- [4. 参数调优](#4-参数调优)
- [5. FAQ 常见问题](#5-faq-常见问题)

---

## 1. 快速开始

### 1.1 安装依赖

本模块**无需安装新依赖**，所有依赖项已包含在项目核心依赖中：

```bash
# Git Bash 环境（推荐）
source /E/AI/cursor/starone/.venv/Scripts/activate
cd /e/AI/Claude/CVE
pip install -r requirements.txt
```

核心依赖：
- Python 3.9+（标准库：`sqlite3`、`json`、`datetime`）
- `risk.dsa_prediction`（产品线分类器，可选）
- `risk.eoss_loader`（EOSS 数据加载器，可选）

### 1.2 准备 EOSS 数据

EOSS（End of Software Support）数据用于生命周期调整，支持两种格式：

#### 方式 1：JSON 格式（推荐）

路径：`E:\AI\Claude\CVE\risk\eoss_data.json`

```json
[
  {
    "product": "PowerScale OneFS",
    "firmware_release": "9.8.0.0",
    "rts_date": "2024-01-15",
    "eoss_date": "2026-12-31",
    "eosl_date": "2027-12-31"
  },
  {
    "product": "iDRAC 9",
    "firmware_release": "9.0.0.0",
    "rts_date": "2020-05-01",
    "eoss_date": "2025-06-30",
    "eosl_date": "2026-06-30"
  }
]
```

**字段说明：**
- `product`: 产品系列名称（如 "PowerScale OneFS"）
- `firmware_release`: 固件版本号（如 "9.8.0.0"）
- `eoss_date`: 软件支持终止日期（YYYY-MM-DD 格式）
- `rts_date`/`eosl_date`: 可选字段（未参与计算）

#### 方式 2：Markdown 格式

路径：`E:\AI\Claude\CVE\risk\software EOSS .md`

使用 `risk.eoss_loader.load_oe_versions()` 解析表格数据。

**注意：** EOSS 数据为可选项，缺失时生命周期调整因子固定为 1.0。

### 1.3 GUI 使用流程

1. **启动应用**
   ```bash
   cd /e/AI/Claude/CVE
   python cve_integrated_gui.py
   ```

2. **进入"模型预测"标签页**
   - 位于主窗口第 7 个标签页（Model Prediction）

3. **填写预测参数**
   - **产品系列**：输入目标产品线（如 `PowerScale OneFS`、`iDRAC`）
   - **目标版本**：输入版本号（如 `9.8.0.0`）
   - **预测天数**：选择时间窗口（30/60/90 天）

4. **执行预测**
   - 点击"开始预测"按钮
   - 后台自动调用 `ProductSeriesPredictor`
   - 预测完成后右侧显示结果

5. **查看结果**
   - **DSA 发生概率**：彩色进度条 + 百分比（0-100%）
   - **CWE Top-3**：高频弱点类型统计表
   - **历史匹配 DSA**：过去 12 个月的相关安全公告列表

---

## 2. API 使用示例

### 示例 1：基础预测（推荐）

```python
from risk.dsa_prediction_series import ProductSeriesPredictor

# 初始化预测器
predictor = ProductSeriesPredictor(
    db_path="E:/AI/Claude/CVE/cve_data/cve_database.db",
    eoss_oe_path="E:/AI/Claude/CVE/risk/eoss_data.json"
)

# 执行预测
result = predictor.forecast_series(
    product_series="PowerScale OneFS",
    version="9.8.0.0",
    forecast_days=90
)

# 输出结果
print(f"DSA 发生概率: {result.probability:.1%}")
print(f"期望 DSA 数: {result.expected_count:.2f}")
print(f"风险等级: {result.risk_level}")
print(f"Top CWE: {result.likely_cwes[0] if result.likely_cwes else '无数据'}")
```

**预期输出：**
```
DSA 发生概率: 65.3%
期望 DSA 数: 1.15
风险等级: HIGH
Top CWE: ('CWE-787', '越界写', 28.5)
```

---

### 示例 2：完整结果解析

```python
from risk.dsa_prediction_series import ProductSeriesPredictor

predictor = ProductSeriesPredictor(
    db_path="cve_data/cve_database.db",
    eoss_oe_path="risk/eoss_data.json"
)

result = predictor.forecast_series("iDRAC", "9.0.0.0", 60)

# 核心预测指标
print(f"产品系列: {result.product_series}")
print(f"目标版本: {result.version}")
print(f"预测窗口: {result.forecast_days} 天")
print(f"DSA 概率: {result.probability:.1%}")
print(f"期望数量: {result.expected_count:.3f}")
print(f"风险等级: {result.risk_level}")

# CWE 分布分析
print("\n高频弱点类型 Top-5:")
for cwe_id, label, pct in result.likely_cwes:
    print(f"  {cwe_id:<12} {label:<24} {pct:5.1f}%")

# 中间计算因子（调试用）
print(f"\n历史月均速率: {result.historical_rate:.3f}")
print(f"版本匹配数: {result.version_match_count}")
print(f"趋势倍数: {result.trend_multiplier:.3f}")
print(f"生命周期调整: {result.lifecycle_adjustment:.3f}")
print(f"EOSS 日期: {result.eoss_date or '无数据'}")

# 可解释性说明
print("\n预测依据:")
for line in result.explanation:
    print(f"  • {line}")
```

---

### 示例 3：批量预测对比

```python
from risk.dsa_prediction_series import ProductSeriesPredictor
import pandas as pd

predictor = ProductSeriesPredictor(
    db_path="cve_data/cve_database.db",
    eoss_oe_path="risk/eoss_data.json"
)

# 批量预测多个版本
versions = ["9.5.0.0", "9.6.0.0", "9.7.0.0", "9.8.0.0"]
results = []

for ver in versions:
    forecast = predictor.forecast_series("PowerScale OneFS", ver, 90)
    results.append({
        "版本": ver,
        "概率": f"{forecast.probability:.1%}",
        "期望DSA数": f"{forecast.expected_count:.2f}",
        "风险等级": forecast.risk_level,
        "历史匹配": forecast.version_match_count
    })

# 生成对比表格
df = pd.DataFrame(results)
print(df.to_string(index=False))
```

**预期输出：**
```
    版本     概率  期望DSA数  风险等级  历史匹配
9.5.0.0   45.2%      0.78    MEDIUM        2
9.6.0.0   52.7%      0.94      HIGH        5
9.7.0.0   61.3%      1.12      HIGH        7
9.8.0.0   65.3%      1.15      HIGH        9
```

---

### 示例 4：JSON 导出

```python
import json
from risk.dsa_prediction_series import ProductSeriesPredictor

predictor = ProductSeriesPredictor(
    db_path="cve_data/cve_database.db",
    eoss_oe_path="risk/eoss_data.json"
)

result = predictor.forecast_series("PowerScale OneFS", "9.8.0.0", 90)

# 导出为 JSON
output = result.to_dict()
with open("forecast_result.json", "w", encoding="utf-8") as f:
    json.dump(output, f, indent=2, ensure_ascii=False)

print("预测结果已保存至 forecast_result.json")
```

---

### 示例 5：时间序列预测（固定版本，变化窗口）

```python
from risk.dsa_prediction_series import ProductSeriesPredictor
import matplotlib.pyplot as plt

predictor = ProductSeriesPredictor(
    db_path="cve_data/cve_database.db",
    eoss_oe_path="risk/eoss_data.json"
)

# 预测 30/60/90/120 天的风险变化
forecast_days = [30, 60, 90, 120]
probabilities = []

for days in forecast_days:
    result = predictor.forecast_series("PowerScale OneFS", "9.8.0.0", days)
    probabilities.append(result.probability * 100)

# 绘制趋势图
plt.figure(figsize=(10, 6))
plt.plot(forecast_days, probabilities, marker='o', linewidth=2, markersize=8)
plt.xlabel("预测天数", fontsize=12)
plt.ylabel("DSA 发生概率 (%)", fontsize=12)
plt.title("PowerScale OneFS 9.8.0.0 风险预测趋势", fontsize=14, fontweight='bold')
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig("risk_trend.png", dpi=300)
print("趋势图已保存至 risk_trend.png")
```

---

## 3. 典型场景

### 场景 1：评估即将部署的 OneFS 版本风险

**背景：** 企业计划在 2 个月后部署 PowerScale OneFS 9.8.0.0，需评估未来 90 天内出现安全公告的风险。

**操作步骤：**
```python
from risk.dsa_prediction_series import ProductSeriesPredictor

predictor = ProductSeriesPredictor(
    db_path="cve_data/cve_database.db",
    eoss_oe_path="risk/eoss_data.json"
)

result = predictor.forecast_series("PowerScale OneFS", "9.8.0.0", 90)

# 风险决策
if result.risk_level in ["CRITICAL", "HIGH"]:
    print(f"⚠ 警告：该版本风险等级为 {result.risk_level}")
    print(f"90 天内 DSA 发生概率: {result.probability:.1%}")
    print(f"期望安全公告数: {result.expected_count:.2f}")
    print("\n建议：")
    print("  1. 延迟部署，等待更稳定的版本")
    print("  2. 建立快速响应机制，监控安全公告")
    print("  3. 优先关注以下 CWE 类型:")
    for cwe_id, label, pct in result.likely_cwes[:3]:
        print(f"     - {cwe_id}: {label} ({pct:.1f}%)")
else:
    print(f"✓ 版本风险可控（{result.risk_level}），建议正常部署")
```

**预期输出：**
```
⚠ 警告：该版本风险等级为 HIGH
90 天内 DSA 发生概率: 65.3%
期望安全公告数: 1.15

建议：
  1. 延迟部署，等待更稳定的版本
  2. 建立快速响应机制，监控安全公告
  3. 优先关注以下 CWE 类型:
     - CWE-787: 越界写 (28.5%)
     - CWE-125: 越界读 (22.1%)
     - CWE-416: 释放后使用（UAF） (18.7%)
```

---

### 场景 2：对比不同预测窗口（30/60/90 天）

**背景：** 运维团队需要制定短期（30 天）、中期（60 天）、长期（90 天）的安全响应计划。

**操作步骤：**
```python
from risk.dsa_prediction_series import ProductSeriesPredictor

predictor = ProductSeriesPredictor(
    db_path="cve_data/cve_database.db",
    eoss_oe_path="risk/eoss_data.json"
)

windows = [30, 60, 90]
print("PowerScale OneFS 9.8.0.0 多窗口风险评估")
print("=" * 60)

for days in windows:
    result = predictor.forecast_series("PowerScale OneFS", "9.8.0.0", days)
    print(f"\n【{days} 天预测】")
    print(f"  DSA 概率: {result.probability:.1%}")
    print(f"  期望数量: {result.expected_count:.3f}")
    print(f"  风险等级: {result.risk_level}")
    
    # 决策建议
    if days == 30 and result.probability > 0.4:
        print("  ⚠ 短期风险高，需立即准备应急预案")
    elif days == 60 and result.probability > 0.6:
        print("  ⚠ 中期风险高，建议提前测试补丁流程")
    elif days == 90 and result.probability > 0.7:
        print("  ⚠ 长期风险高，考虑版本升级规划")
```

**预期输出：**
```
PowerScale OneFS 9.8.0.0 多窗口风险评估
============================================================

【30 天预测】
  DSA 概率: 38.2%
  期望数量: 0.383
  风险等级: MEDIUM

【60 天预测】
  DSA 概率: 55.7%
  期望数量: 0.767
  风险等级: HIGH
  ⚠ 中期风险高，建议提前测试补丁流程

【90 天预测】
  DSA 概率: 65.3%
  期望数量: 1.150
  风险等级: HIGH
```


---

### 场景 3：查看历史 DSA 的 CWE 分布趋势

**背景：** 安全团队需分析 PowerScale OneFS 9.8.0.0 历史 DSA 中的弱点类型分布，制定针对性防护策略。

**操作步骤：**
```python
from risk.dsa_prediction_series import ProductSeriesPredictor

predictor = ProductSeriesPredictor(
    db_path="cve_data/cve_database.db",
    eoss_oe_path="risk/eoss_data.json"
)

result = predictor.forecast_series("PowerScale OneFS", "9.8.0.0", 90)

# 分析 CWE 分布
print("PowerScale OneFS 9.8.0.0 历史 CWE 类型分布")
print("=" * 60)
print(f"基于过去 12 个月的 {result.historical_dsa_12m} 条 DSA")
print(f"版本 9.8.0.0 匹配 {result.version_match_count} 条\n")

if result.likely_cwes:
    print("Top CWE 类型（降序）:")
    for i, (cwe_id, label, pct) in enumerate(result.likely_cwes, 1):
        print(f"  {i}. {cwe_id:<12} {label:<24} {pct:5.1f}%")

    # 针对性建议
    print("\n防护建议:")
    top_cwe = result.likely_cwes[0][0]
    if "787" in top_cwe or "125" in top_cwe:
        print("  • 内存安全风险高，建议启用地址空间布局随机化（ASLR）")
        print("  • 对外部输入进行严格边界检查")
    elif "79" in top_cwe or "89" in top_cwe:
        print("  • Web 接口注入风险高，建议启用 WAF")
        print("  • 对用户输入进行严格转义和参数化查询")
else:
    print("⚠ 无足够历史 CVE 数据，无法生成 CWE 分布")
```

**预期输出：**
```
PowerScale OneFS 9.8.0.0 历史 CWE 类型分布
============================================================
基于过去 12 个月的 12 条 DSA
版本 9.8.0.0 匹配 9 条

Top CWE 类型（降序）:
  1. CWE-787      越界写                      28.5%
  2. CWE-125      越界读                      22.1%
  3. CWE-416      释放后使用（UAF）              18.7%
  4. CWE-476      空指针解引用                  12.3%
  5. CWE-20       输入验证不当                   9.8%

防护建议:
  • 内存安全风险高，建议启用地址空间布局随机化（ASLR）
  • 对外部输入进行严格边界检查
```

---

## 4. 参数调优

### 4.1 生命周期调整因子

**位置：** `ProductSeriesPredictor._EOSS_WINDOW_DAYS` 和 `_EOSS_MAX_UPLIFT`

**默认值：**
- `_EOSS_WINDOW_DAYS = 180`（距 EOSS 180 天内触发上调）
- `_EOSS_MAX_UPLIFT = 0.2`（最大上调幅度 20%）

**调整方法：**
```python
from risk.dsa_prediction_series import ProductSeriesPredictor

# 方法 1：修改类属性（全局生效）
ProductSeriesPredictor._EOSS_WINDOW_DAYS = 365  # 提前 1 年触发
ProductSeriesPredictor._EOSS_MAX_UPLIFT = 0.3   # 上调幅度改为 30%

predictor = ProductSeriesPredictor(
    db_path="cve_data/cve_database.db",
    eoss_oe_path="risk/eoss_data.json"
)

result = predictor.forecast_series("PowerScale OneFS", "9.8.0.0", 90)
print(f"生命周期调整因子: {result.lifecycle_adjustment:.3f}")
```

**调优建议：**
- **保守策略**（降低误报）：`_EOSS_WINDOW_DAYS = 90`, `_EOSS_MAX_UPLIFT = 0.1`
- **激进策略**（提前预警）：`_EOSS_WINDOW_DAYS = 365`, `_EOSS_MAX_UPLIFT = 0.5`
- **默认策略**（平衡）：`_EOSS_WINDOW_DAYS = 180`, `_EOSS_MAX_UPLIFT = 0.2`

---

### 4.2 版本匹配最小样本数

**位置：** `ProductSeriesPredictor._MIN_VERSION_SAMPLES`

**默认值：** `_MIN_VERSION_SAMPLES = 3`

**调整方法：**
```python
from risk.dsa_prediction_series import ProductSeriesPredictor

# 降低阈值，在历史数据少时也使用版本级速率
ProductSeriesPredictor._MIN_VERSION_SAMPLES = 2

predictor = ProductSeriesPredictor(
    db_path="cve_data/cve_database.db",
    eoss_oe_path="risk/eoss_data.json"
)

result = predictor.forecast_series("iDRAC", "9.0.0.0", 90)
print(f"版本匹配数: {result.version_match_count}")
print(f"趋势倍数: {result.trend_multiplier:.3f}")
```

**调优建议：**
- **数据充足场景**（12 个月内 DSA >= 10 条）：保持默认值 3
- **数据稀疏场景**（12 个月内 DSA < 5 条）：降至 2 或 1
- **高置信度要求**：提升至 5

---

### 4.3 扩展 CWE 映射表

**位置：** `risk.dsa_prediction_series.CWE_MAPPING` 字典

**当前包含：** 35 个常见 CWE（MITRE Top-25 + Dell 产品特有）

**扩展方法：**
```python
from risk.dsa_prediction_series import CWE_MAPPING, ProductSeriesPredictor

# 添加自定义 CWE 标签
CWE_MAPPING["CWE-295"] = "证书验证不当"
CWE_MAPPING["CWE-327"] = "弱加密算法"
CWE_MAPPING["CWE-601"] = "开放重定向"

predictor = ProductSeriesPredictor(
    db_path="cve_data/cve_database.db",
    eoss_oe_path="risk/eoss_data.json"
)

result = predictor.forecast_series("PowerScale OneFS", "9.8.0.0", 90)

# 验证新 CWE 是否生效
for cwe_id, label, pct in result.likely_cwes:
    print(f"{cwe_id}: {label} ({pct:.1f}%)")
```

**扩展建议：**
- 参考 [MITRE CWE Top 25](https://cwe.mitre.org/top25/)
- 根据实际产品线添加领域特定 CWE（如工控系统、云平台）
- 保持中文标签简洁（≤ 12 字符），便于表格显示

---

## 5. FAQ 常见问题

### Q1: 为什么某版本预测概率为 0？

**原因：**
1. 过去 12 个月该产品系列无任何 DSA 记录（`historical_dsa_12m == 0`）
2. 该版本发布时间晚于数据库最新 DSA 日期（无历史数据）

**解决方法：**
```python
from risk.dsa_prediction_series import ProductSeriesPredictor

predictor = ProductSeriesPredictor(
    db_path="cve_data/cve_database.db",
    eoss_oe_path="risk/eoss_data.json"
)

result = predictor.forecast_series("PowerScale OneFS", "9.8.0.0", 90)

# 检查历史数据量
if result.historical_dsa_12m == 0:
    print("⚠ 无历史 DSA 数据，概率为 0 属正常")
    print("建议：")
    print("  1. 检查产品系列名称是否正确（如 'PowerScale' vs 'PowerScale OneFS'）")
    print("  2. 更新数据库，收集更多历史 DSA")
    print("  3. 回退到产品线级预测（不指定版本）")
elif result.low_confidence:
    print(f"⚠ 历史样本不足（仅 {result.historical_dsa_12m} 条），预测置信度低")
```

---

### Q2: CWE Top-3 和实际 DSA 不匹配怎么办？

**原因：**
CWE 分布基于 DSA 关联的 NVD CVE 数据，可能存在：
1. DSA 未关联 CVE（字段为空）
2. NVD CVE 缺失 weaknesses 字段
3. 第三方组件 CVE 占比高，未反映 Dell 自身代码弱点

**验证方法：**
```python
from risk.dsa_prediction_series import ProductSeriesPredictor

predictor = ProductSeriesPredictor(
    db_path="cve_data/cve_database.db",
    eoss_oe_path="risk/eoss_data.json"
)

result = predictor.forecast_series("PowerScale OneFS", "9.8.0.0", 90)

# 检查 CWE 覆盖率
if not result.likely_cwes:
    print("⚠ 无 CWE 数据，可能原因:")
    print("  1. DSA 未关联 CVE ID")
    print("  2. 关联 CVE 在 cves 表中缺失")
    print("  3. CVE 的 weaknesses 字段为空")

    # 手动查询验证
    import sqlite3
    conn = sqlite3.connect("cve_data/cve_database.db")
    cur = conn.cursor()
    cur.execute("""
        SELECT dsa_id, cve_ids
        FROM dell_advisories
        WHERE title LIKE '%PowerScale%'
        LIMIT 5
    """)
    for dsa_id, cve_ids in cur.fetchall():
        print(f"  {dsa_id}: {cve_ids or '无 CVE'}")
    conn.close()
```

**解决方法：**
1. 运行 `risk/dsa_cve_backfill.py` 补全 DSA 的 CVE 关联
2. 使用 `collect_cves.py` 更新 NVD CVE 数据库
3. 手动添加 CWE 映射（见 4.3 节）

---

### Q3: 如何更新 EOSS 数据？

**方法 1：编辑 JSON 文件（推荐）**
```bash
# 编辑文件
code E:/AI/Claude/CVE/risk/eoss_data.json

# 添加新版本
{
  "product": "PowerScale OneFS",
  "firmware_release": "9.9.0.0",
  "rts_date": "2025-01-15",
  "eoss_date": "2027-12-31",
  "eosl_date": "2028-12-31"
}
```

**方法 2：从 Dell 官网自动抓取**
```python
# 暂未实现自动爬虫，手动查询：
# https://www.dell.com/support/kbdoc/zh-cn/000150437/dell-powerscale-onefs-support-matrix
```

**验证更新：**
```python
from risk.dsa_prediction_series import ProductSeriesPredictor

predictor = ProductSeriesPredictor(
    db_path="cve_data/cve_database.db",
    eoss_oe_path="risk/eoss_data.json"
)

result = predictor.forecast_series("PowerScale OneFS", "9.9.0.0", 90)
print(f"EOSS 日期: {result.eoss_date}")
print(f"距 EOSS 天数: {result.eoss_proximity_days}")
print(f"生命周期调整: {result.lifecycle_adjustment:.3f}")
```

---

### Q4: 为什么不同窗口的风险等级不单调递增？

**原因：**
风险等级（CRITICAL / HIGH / MEDIUM / LOW / MINIMAL）同时考虑：
1. **概率**（P(≥1 DSA)）
2. **期望值**（expected_count）

两者取更高档，导致可能出现以下情况：
- 30 天：概率 38%（MEDIUM），期望 0.38
- 60 天：概率 56%（HIGH），期望 0.77
- 90 天：概率 65%（HIGH），期望 1.15 ← 期望超过 1.0，触发 MEDIUM

**示例：**
```python
from risk.dsa_prediction_series import ProductSeriesPredictor

predictor = ProductSeriesPredictor(
    db_path="cve_data/cve_database.db",
    eoss_oe_path="risk/eoss_data.json"
)

for days in [30, 60, 90]:
    result = predictor.forecast_series("PowerScale OneFS", "9.8.0.0", days)
    print(f"{days:3d} 天 | 概率 {result.probability:.1%} | "
          f"期望 {result.expected_count:.2f} | "
          f"等级 {result.risk_level}")
```

**预期输出：**
```
 30 天 | 概率 38.2% | 期望 0.38 | 等级 MEDIUM
 60 天 | 概率 55.7% | 期望 0.77 | 等级 HIGH
 90 天 | 概率 65.3% | 期望 1.15 | 等级 HIGH
```

**说明：** 这是预期行为，风险等级反映"最坏情况"（概率和期望值的最高档）。

---

### Q5: 如何处理产品系列名称不匹配？

**问题：** 输入 "PowerScale" 查不到任何 DSA，但数据库中存储为 "PowerScale OneFS"。

**原因：**
`_query_series_history` 使用模糊匹配：
1. 检查 DSA title 是否包含输入的产品系列名
2. 调用 `classify_dsa` 自动分类

**解决方法：**
```python
from risk.dsa_prediction_series import ProductSeriesPredictor

predictor = ProductSeriesPredictor(
    db_path="cve_data/cve_database.db",
    eoss_oe_path="risk/eoss_data.json"
)

# 测试不同名称变体
test_names = [
    "PowerScale",
    "PowerScale OneFS",
    "OneFS",
    "Isilon"
]

for name in test_names:
    result = predictor.forecast_series(name, "9.8.0.0", 90)
    print(f"{name:<20} → 历史 DSA: {result.historical_dsa_12m}")
```

**预期输出：**
```
PowerScale           → 历史 DSA: 12
PowerScale OneFS     → 历史 DSA: 12
OneFS                → 历史 DSA: 12
Isilon               → 历史 DSA: 12
```

**说明：** 模块已支持多种名称变体，通常无需完全匹配。

---

### Q6: 预测结果置信度如何判断？

**置信度指标：**
1. **`low_confidence` 标志**：历史样本 < 3 条时为 `True`
2. **版本匹配数**：`version_match_count >= 3` 时使用版本级速率
3. **CWE 覆盖率**：`likely_cwes` 列表长度反映数据完整性

**判断方法：**
```python
from risk.dsa_prediction_series import ProductSeriesPredictor

predictor = ProductSeriesPredictor(
    db_path="cve_data/cve_database.db",
    eoss_oe_path="risk/eoss_data.json"
)

result = predictor.forecast_series("PowerScale OneFS", "9.8.0.0", 90)

# 置信度评估
confidence_score = 0
if result.historical_dsa_12m >= 10:
    confidence_score += 40
elif result.historical_dsa_12m >= 5:
    confidence_score += 20

if result.version_match_count >= 3:
    confidence_score += 30

if len(result.likely_cwes) >= 3:
    confidence_score += 30

print(f"置信度评分: {confidence_score}/100")
if confidence_score >= 70:
    print("✓ 高置信度，预测结果可靠")
elif confidence_score >= 40:
    print("⚠ 中等置信度，建议结合人工判断")
else:
    print("✗ 低置信度，建议收集更多历史数据")
```

---

### Q7: 如何集成到 CI/CD 流程？

**场景：** 在版本发布前自动评估风险，阻断高风险版本上线。

**示例：GitLab CI**
```yaml
# .gitlab-ci.yml
risk_assessment:
  stage: test
  script:
    - python -m venv .venv
    - source .venv/bin/activate
    - pip install -r requirements.txt
    - python scripts/ci_risk_check.py --version $CI_COMMIT_TAG
  only:
    - tags
  allow_failure: false
```

**风险检查脚本：**
```python
# scripts/ci_risk_check.py
import sys
import argparse
from risk.dsa_prediction_series import ProductSeriesPredictor

parser = argparse.ArgumentParser()
parser.add_argument("--version", required=True)
args = parser.parse_args()

predictor = ProductSeriesPredictor(
    db_path="cve_data/cve_database.db",
    eoss_oe_path="risk/eoss_data.json"
)

result = predictor.forecast_series("PowerScale OneFS", args.version, 90)

print(f"版本 {args.version} 风险评估:")
print(f"  风险等级: {result.risk_level}")
print(f"  DSA 概率: {result.probability:.1%}")

# 阻断 CRITICAL 风险版本
if result.risk_level == "CRITICAL":
    print("✗ 风险等级 CRITICAL，阻断发布")
    sys.exit(1)
elif result.risk_level == "HIGH":
    print("⚠ 风险等级 HIGH，需人工审批")
    sys.exit(0)  # 或改为 sys.exit(1) 强制阻断
else:
    print("✓ 风险可控，允许发布")
    sys.exit(0)
```

---

### Q8: 预测速度慢怎么优化？

**性能瓶颈：**
1. 数据库查询（历史 DSA + CVE weaknesses）
2. JSON 解析（`data` 字段）
3. CWE 统计（分批查询 500 条 CVE）

**优化方法：**
```python
from risk.dsa_prediction_series import ProductSeriesPredictor
import time

# 测试当前性能
start = time.time()
predictor = ProductSeriesPredictor(
    db_path="cve_data/cve_database.db",
    eoss_oe_path="risk/eoss_data.json"
)
result = predictor.forecast_series("PowerScale OneFS", "9.8.0.0", 90)
print(f"预测耗时: {time.time() - start:.2f} 秒")

# 优化 1：使用 Redis 缓存
from redis_manager import RedisDataManager
redis_mgr = RedisDataManager()
cache_key = "forecast:PowerScale_OneFS:9.8.0.0:90"
cached_result = redis_mgr.get_dsa_forecast(cache_key)
if cached_result:
    print("使用缓存结果")
else:
    result = predictor.forecast_series("PowerScale OneFS", "9.8.0.0", 90)
    redis_mgr.cache_dsa_forecast(cache_key, result.to_dict(), ttl=3600)
```

**优化 2：数据库索引**
```sql
-- 在 dell_advisories 表添加索引
CREATE INDEX IF NOT EXISTS idx_published_date
ON dell_advisories(published_date);

CREATE INDEX IF NOT EXISTS idx_title
ON dell_advisories(title);
```

**预期提升：**
- 无索引：~2-5 秒
- 添加索引：~0.5-1 秒
- 使用 Redis 缓存：~0.01 秒

---

### Q9: 如何解释 `trend_multiplier` 的含义？

**定义：** 版本级速率 / 系列级速率（≤ 1.0）

**计算公式：**
```
trend_multiplier = (version_match_count / 12) / (historical_dsa_12m / 12)
                 = version_match_count / historical_dsa_12m
```

**示例解读：**
```python
from risk.dsa_prediction_series import ProductSeriesPredictor

predictor = ProductSeriesPredictor(
    db_path="cve_data/cve_database.db",
    eoss_oe_path="risk/eoss_data.json"
)

result = predictor.forecast_series("PowerScale OneFS", "9.8.0.0", 90)

print(f"历史 DSA 总数: {result.historical_dsa_12m}")
print(f"版本匹配数: {result.version_match_count}")
print(f"趋势倍数: {result.trend_multiplier:.3f}")
print(f"解读: 该版本占系列全部 DSA 的 {result.trend_multiplier:.1%}")
```

**预期输出：**
```
历史 DSA 总数: 12
版本匹配数: 9
趋势倍数: 0.750
解读: 该版本占系列全部 DSA 的 75.0%
```

**应用场景：**
- `trend_multiplier < 0.5`：该版本受影响较少，相对安全
- `trend_multiplier ≈ 1.0`：版本级和系列级风险一致
- `trend_multiplier >= 3` 时会被系统限制回 1.0（避免样本偏差）

---

### Q10: 模块支持哪些产品系列？

**已验证产品线：**
1. **PowerScale / OneFS / Isilon**（NAS 存储）
2. **iDRAC**（服务器管理控制器）
3. **PowerEdge**（服务器硬件）
4. **Unity / VxRail**（存储阵列）

**测试方法：**
```python
from risk.dsa_prediction_series import ProductSeriesPredictor
import sqlite3

# 查询数据库中的产品分布
db_path = "cve_data/cve_database.db"
conn = sqlite3.connect(db_path)
cur = conn.cursor()
cur.execute("""
    SELECT DISTINCT
        CASE
            WHEN title LIKE '%PowerScale%' OR title LIKE '%OneFS%' THEN 'PowerScale'
            WHEN title LIKE '%iDRAC%' THEN 'iDRAC'
            WHEN title LIKE '%PowerEdge%' THEN 'PowerEdge'
            ELSE 'Other'
        END as product_family,
        COUNT(*) as dsa_count
    FROM dell_advisories
    WHERE published_date >= date('now', '-12 months')
    GROUP BY product_family
    ORDER BY dsa_count DESC
""")
print("产品系列 DSA 分布:")
for product, count in cur.fetchall():
    print(f"  {product:<20} {count:3d} 条")
conn.close()
```

**扩展方法：**
修改 `risk.dsa_prediction.classify_dsa` 函数，添加新产品线关键词。

---

**文档版本：** v1.0
**最后更新：** 2026-06-07
**维护者：** CVE 监控系统开发团队
**反馈渠道：** 提交 Issue 至项目 GitHub 仓库
