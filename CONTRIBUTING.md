# 贡献指南

感谢您对本项目的关注！本文档说明如何为项目贡献代码。

## 提交规范

本项目采用 [Conventional Commits](https://www.conventionalcommits.org/) 规范，提交信息格式如下：

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Type（类型）

- `feat`: 新功能
- `fix`: Bug 修复
- `docs`: 文档更新
- `style`: 代码格式（不影响代码运行的变动）
- `refactor`: 重构（既不是新增功能，也不是修改 bug）
- `perf`: 性能优化
- `test`: 测试相关
- `chore`: 构建过程或辅助工具的变动
- `i18n`: 国际化相关

### Scope（范围）

模块或功能范围，例如：
- `model-predict`: 产品型号预测
- `unified-risk`: 智能预测标签页
- `taxonomy`: 产品分类
- `dx`: 开发者体验
- `readme`: README 文档

### Subject（主题）

简短描述（50 字符内），动词开头，不加句号。

### Body（正文）

详细描述改动内容、原因和影响：
- 问题背景（可选）
- 解决方案（具体改动）
- 验证方法（测试/端到端验证）

### Footer（脚注）

- 关闭 issue：`Closes #123`
- 破坏性变更：`BREAKING CHANGE: 说明`
- 协作者署名：`Co-Authored-By: Name <email>`

## 提交示例

### 新功能

```
feat(taxonomy): 新增产品系列名规范化函数

新增 normalize_series_name() 纯函数，用于剥离产品名尾部的微码/版本号：
- 'Dell PowerMaxOS 5978.714.714' → 'Dell PowerMaxOS'
- 'Dell EMC VPLEX 6.2.0' → 'Dell EMC VPLEX'

设计原则：
- 只剥离点分版本串（6.2.0 / 5978.714.714），保留型号位
  （PowerStore 1000T / Unity 600F 等无点数字是型号，不是版本）
- 反复剥离覆盖多段拼接（'Foo 1.2.3 4.5.6'）

测试覆盖：
- 用户提到的 5 个实例（PowerMaxOS/VPLEX/PowerMax OS/VxRail/SRS）
- 型号位保留边界条件（PowerStore 1000T / PowerScale H700）

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
```

### Bug 修复

```
fix(model-predict): 产品系列下拉框剥离微码版本号

问题：智能模型预测标签页的产品系列下拉框混入微码版本号，如
'Dell PowerMaxOS 5978.714.714'、'Dell EMC VPLEX 6.2.0'，
版本号被当作独立系列。

解决：
- 应用 normalize_series_name() 剥离尾部微码版本号
- 知识图谱 + 数据库两条路径统一规范化 + 去重（Top-100 → 93 条）
- 下拉框只显示系列名，版本号由用户在独立输入框填写

端到端验证：规范化后的系列名（PowerMaxOS/VPLEX/VxRail）仍能
正常匹配历史 DSA 并产出预测（实测 P=63%/22%/78%）
```

### 国际化

```
i18n(unified-risk): 智能预测标签页全面国际化

问题：unified_risk_tab.py 约 60 处硬编码中文在英文模式下
仍显示中文，用户体验不一致。

解决：
- i18n.py: zh_CN/en_US 各新增 138 条 ur_* key，占位符完全对等
- unified_risk_tab.py: 所有 UI 构建与运行时字符串改为 t() 调用

验证：
- 两套语言下模块均可导入
- 英文模式实测主要 UI 元素全部正确显示英文
```

### 文档更新

```
docs(readme): 更新版本号至 5.6.1 + 记录新增功能

版本号：5.6.0 → 5.6.1

功能更新：
- 智能预测章节新增"产品型号预测"标签页说明
- 补充系列名规范化特性（剥离微码版本号，Top-100→93 条）
- i18n 覆盖度更新（智能预测 138 key + 产品型号预测 36 key）
```

## 提交原则

### 原子性

每次提交只做一件事：
- ✅ 好：`feat(taxonomy): 新增产品系列名规范化函数`
- ❌ 差：`feat: 新增规范化函数 + 修复 i18n bug + 更新 README`

### 颗粒度

根据功能独立性选择合适的提交粒度：
- **单一功能新增**：一个提交（如新增纯函数）
- **大功能 + 应用**：拆分为两次提交（纯函数 → GUI 应用）
- **国际化大批量替换**：单独一次提交（性质单一，方便回滚）
- **体验优化合集**：多个小修小补可合并提交（如 bat 脚本 + 依赖补全 + CHANGELOG）

### 可回滚性

每次提交应能独立回滚而不破坏项目运行：
- 提交前运行相关测试（`pytest tests/test_*.py`）
- 功能完整（不提交半成品）
- 依赖明确（如新增函数先提交，再提交调用处）

### 提交信息质量

- **主题行**：50 字符内，动词开头，清晰描述"做了什么"
- **正文**：
  - 问题背景（为什么改）
  - 解决方案（怎么改的，关键设计决策）
  - 验证方法（测试/实测结果）
- **避免无意义信息**：
  - ❌ "fix bug" / "update" / "修改"
  - ✅ "fix(model-predict): 产品系列下拉框剥离微码版本号"

## 分支策略

- `main` 分支：稳定版本，只接受经过测试的 PR
- 功能分支：`feature/<name>`，从 `main` 切出
- 修复分支：`fix/<issue-id>`，从 `main` 切出

## Pull Request

1. Fork 项目并克隆到本地
2. 创建功能分支：`git checkout -b feature/my-feature`
3. 提交改动（遵循上述规范）
4. 推送到 fork：`git push origin feature/my-feature`
5. 在 GitHub 上创建 Pull Request

PR 标题遵循 Conventional Commits 格式，描述中包含：
- 改动概述
- 关联 issue（如有）
- 测试结果截图（UI 改动时）

## 代码风格

- Python: 遵循 PEP 8
- 行宽：120 字符（配置在 pyproject.toml）
- 导入：按标准库、第三方库、本地模块分组
- 类型注解：公开 API 必须有类型注解

## 测试

新增功能必须包含单元测试：
- 测试文件：`tests/test_<module>.py`
- 测试类：`class Test<Feature>`
- 测试方法：`def test_<scenario>`

运行测试：
```bash
pytest tests/test_<module>.py -v
```

## 问题反馈

提交 issue 前请搜索是否已有相同问题。新建 issue 时包含：
- 问题描述（预期行为 vs 实际行为）
- 复现步骤
- 环境信息（Python 版本、OS）
- 错误日志（如有）

---

再次感谢您的贡献！🎉
