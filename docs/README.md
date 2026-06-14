# 项目文档索引

本目录包含项目的核心设计文档和技术指南。

## 核心设计文档

### 🎯 风险分析系统
- **[风险分析系统设计](risk_analysis_system_design.md)** (34K)
  - 知识图谱架构（CVE × DSA × 产品 × CWE）
  - Poisson 速率模型（产品线级 DSA 概率预测）
  - 三层风险评估（产品线 / 版本 / 微码）
  - PageRank 传播分析 + 规则引擎

### 📊 模型级预测
- **[模型级预测架构](model_level_prediction_architecture.md)** (49K)
  - VMR 验证器（Version Match Ratio）
  - Bayesian 年龄调整先验
  - Bootstrap 500 次抽样置信区间
  - EOSS 生命周期调整
- **[模型级预测使用指南](model_level_prediction_usage.md)** (27K)
  - 快速开始（产品型号预测标签页）
  - API 调用示例
  - 数据源配置（EOSS JSON）
  - 可解释性因子拆解

### 🌐 国际化
- **[国际化实施指南](I18N_IMPLEMENTATION_GUIDE.md)** (6K)
  - i18n.py 架构（zh_CN / en_US）
  - 新增语言步骤
  - key 命名规范
  - 占位符使用（{count} / {name}）

## 归档文档

历史优化计划和实施总结归档在 [archive/](archive/) 目录，仅供参考。

## 相关文档

- **[项目主 README](../README.md)** — 功能概览、代码规模、快速开始
- **[贡献指南](../CONTRIBUTING.md)** — 提交规范、分支策略、代码风格
- **[变更日志](../CHANGELOG.md)** — 版本历史（v5.6.1 最新）
- **[Claude 开发环境配置](../CLAUDE.md)** — 虚拟环境、工具链配置（内部）

---

**维护原则**：
- 只追踪核心设计文档（架构、系统设计、使用指南）
- 历史报告（bug 分析、版本升级报告）归档或不追踪
- 新增文档前检查是否与现有文档冗余

**最后更新**: 2026-06-14 (v5.6.1)
