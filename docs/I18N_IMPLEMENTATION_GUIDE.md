# 国际化(i18n)实施指南

## 概述

本项目已实现中英文语言切换功能的核心基础设施。本文档提供完整的实施指南和使用说明。

## 已完成的工作

### 1. 核心模块

#### i18n.py - 国际化配置模块
- 定义了完整的中英文文本字典
- 提供 `t(key)` 函数用于获取翻译文本
- 提供 `set_language(lang)` 和 `get_language()` 函数管理当前语言
- 支持文本模板（如：`t("msg_delete_confirm", count=5)`）

#### config.py - 配置管理
- 添加 `get_language_setting()` 函数从配置文件加载语言设置
- 添加 `save_language_setting(lang)` 函数保存语言设置
- 语言配置保存在 `cve_data/language_config.json`

### 2. 主界面修改

#### cve_integrated_gui.py
- 在 `__init__` 方法中初始化语言设置
- 在顶部标题栏添加语言选择下拉菜单
- 实现 `on_language_change()` 回调函数处理语言切换
- 窗口标题已使用 `t("app_title")` 实现国际化

### 3. 辅助工具

#### apply_i18n.py - 批量文本替换脚本
- 提供批量替换硬编码中文文本为 i18n 函数调用的工具
- 支持预览模式和执行模式
- 可扩展的文本映射配置

## 使用方法

### 1. 在代码中使用国际化文本

```python
from i18n import t

# 简单文本
button_text = t("btn_save")  # 返回 "💾 保存" 或 "💾 Save"

# 带参数的文本模板
message = t("msg_delete_confirm", count=5)  # 返回 "确定要删除选中的 5 条记录吗？"

# 在 tkinter 控件中使用
tk.Button(parent, text=t("btn_search"), command=self.search)
tk.Label(parent, text=t("nvd_search_label"))
```

### 2. 添加新的翻译文本

在 `i18n.py` 的 `TEXTS` 字典中添加新的键值对：

```python
TEXTS = {
    "zh_CN": {
        "new_key": "新文本",
        # ...
    },
    "en_US": {
        "new_key": "New Text",
        # ...
    }
}
```

### 3. 使用批量替换工具

```bash
# 激活虚拟环境
source /E/AI/cursor/starone/.venv/Scripts/activate

# 运行替换脚本（预览模式）
python apply_i18n.py

# 确认后执行替换
# 脚本会提示是否执行替换，输入 'y' 确认
```

## 实施步骤

### 阶段 1：核心界面元素（已完成）
- ✅ 主窗口标题
- ✅ 语言选择控件
- ✅ 语言切换机制

### 阶段 2：标签页和按钮（待完成）

需要替换的主要界面元素：

1. **标签页标题**
   ```python
   # 修改前
   self.notebook.add(self.news_frame, text="📰 IT新闻简报")
   
   # 修改后
   self.notebook.add(self.news_frame, text=t("tab_news"))
   ```

2. **按钮文本**
   ```python
   # 修改前
   tk.Button(parent, text="🔍 搜索", command=self.search)
   
   # 修改后
   tk.Button(parent, text=t("btn_search"), command=self.search)
   ```

3. **标签文本**
   ```python
   # 修改前
   tk.Label(parent, text="搜索：")
   
   # 修改后
   tk.Label(parent, text=t("nvd_search_label"))
   ```

4. **消息框**
   ```python
   # 修改前
   messagebox.showinfo("提示", "操作成功")
   
   # 修改后
   messagebox.showinfo(t("msg_info"), t("msg_save_success"))
   ```

### 阶段 3：报告生成（待完成）

需要修改的报告生成函数：

1. **新闻简报生成**
   - 修改 AI 提示词，根据语言设置生成对应语言的简报
   - 修改报告模板

2. **播客脚本生成**
   - 修改 AI 提示词
   - 修改脚本模板

3. **AI 分析报告**
   - 修改分析提示词
   - 修改报告格式

### 阶段 4：AI 提示词（待完成）

需要修改的 AI 提示词位置：

```python
def generate_news_brief(self):
    # 根据语言设置选择提示词
    if get_language() == "zh_CN":
        prompt = "请用中文生成500字的科技新闻简报..."
    else:
        prompt = "Please generate a 500-word tech news brief in English..."
```

## 快速实施方案

### 方案 1：渐进式替换（推荐）

1. 优先替换用户最常见的界面元素
2. 按标签页逐个替换
3. 每次替换后测试功能

### 方案 2：批量替换

1. 使用 `apply_i18n.py` 脚本批量替换
2. 扩展脚本中的 `TEXT_MAPPINGS` 字典
3. 运行脚本并测试

## 测试清单

- [ ] 语言选择下拉菜单显示正常
- [ ] 切换语言后提示重启
- [ ] 重启后界面显示新语言
- [ ] 所有按钮文本正确显示
- [ ] 所有标签页标题正确显示
- [ ] 消息框文本正确显示
- [ ] 报告生成使用正确语言
- [ ] AI 分析使用正确语言

## 注意事项

1. **重启应用**：语言切换后需要重启应用才能完全生效
2. **文本键命名**：使用清晰的键名，如 `btn_save`、`msg_error`
3. **保持一致性**：相同功能的文本使用相同的键
4. **测试覆盖**：每次添加新文本后都要测试中英文显示

## 扩展支持更多语言

如需添加其他语言（如日语、韩语等）：

1. 在 `i18n.py` 的 `TEXTS` 字典中添加新语言代码
2. 在语言选择下拉菜单中添加新选项
3. 翻译所有文本键

```python
TEXTS = {
    "zh_CN": { ... },
    "en_US": { ... },
    "ja_JP": {  # 日语
        "app_title": "インテリジェント知識管理プラットフォーム",
        # ...
    }
}
```

## 常见问题

### Q: 为什么切换语言后界面没有变化？
A: 需要重启应用。当前实现采用启动时加载语言设置的方式，避免运行时动态刷新的复杂性。

### Q: 如何添加新的翻译文本？
A: 在 `i18n.py` 的 `TEXTS` 字典中添加新的键值对，然后在代码中使用 `t("new_key")` 引用。

### Q: 批量替换脚本会破坏代码吗？
A: 脚本提供预览模式，可以先查看将要替换的内容。建议在替换前备份代码或使用 Git 版本控制。

## 贡献指南

如果您要为项目添加新功能，请遵循以下国际化规范：

1. 所有用户可见的文本都应使用 `t()` 函数
2. 在 `i18n.py` 中添加对应的翻译
3. 提交代码前测试中英文显示

## 相关文件

- `i18n.py` - 国际化配置模块
- `config.py` - 配置管理（包含语言设置持久化）
- `cve_integrated_gui.py` - 主界面（包含语言选择控件）
- `apply_i18n.py` - 批量文本替换工具
- `cve_data/language_config.json` - 语言配置文件（自动生成）

---

*最后更新时间：2026-05-09*
*文档版本：v1.0.0*
