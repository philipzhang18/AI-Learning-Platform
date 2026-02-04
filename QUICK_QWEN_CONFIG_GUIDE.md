# CVE AI解决方案快速配置指南

## ⚡ 快速修复（3步）

### 1️⃣ 设置API密钥环境变量

**如果您有DASHSCOPE_API_KEY** (推荐):
```batch
setx DASHSCOPE_API_KEY sk-your-api-key-here
```

**或者设置QWEN_API_KEY**:
```batch
setx QWEN_API_KEY sk-your-api-key-here
```

### 2️⃣ 验证QWEN_MODEL已设置

```batch
echo %QWEN_MODEL%
```

应该显示: `qwen3-max-2026-01-23`

如果未设置，运行:
```batch
setx QWEN_MODEL qwen3-max-2026-01-23
```

### 3️⃣ 重启应用

关闭并重新启动CVE GUI应用。

---

## ✅ 验证修复成功

### 测试步骤

1. 启动CVE应用
2. 进入 "🔗 CVE-Dell关联" 标签页
3. 点击 "🔄 刷新关联数据"
4. 选择一条关联数据
5. 点击 "🤖 AI解决方案"

### 成功标志

✓ 日志中出现: `正在调用AI分析: CVE-xxx - DSA-xxx...`
✓ 没有 "API密钥未设置" 错误
✓ 分析在后台进行
✓ 结果显示在"💡 解决方案"标签页

### 失败排除

如果仍然出错，请检查:

```batch
REM 检查所有相关环境变量
echo QWEN_API_KEY: %QWEN_API_KEY%
echo DASHSCOPE_API_KEY: %DASHSCOPE_API_KEY%
echo QWEN_MODEL: %QWEN_MODEL%
echo QWEN_BASE_URL: %QWEN_BASE_URL%
```

---

## 📚 环境变量说明

### 必需

| 变量 | 含义 | 示例 |
|-----|------|------|
| **DASHSCOPE_API_KEY** 或 **QWEN_API_KEY** | API认证密钥 | sk-22ec825... |

### 可选

| 变量 | 含义 | 默认值 |
|-----|------|--------|
| QWEN_MODEL | 使用的AI模型 | qwen-max-latest |
| QWEN_BASE_URL | API服务地址 | https://dashscope.aliyuncs.com/... |

---

## 🆘 常见问题

### Q: 如何获取DASHSCOPE_API_KEY?

A: 访问 https://dashscope.console.aliyun.com/ 申请API密钥

### Q: 为什么设置了环境变量后仍然报错?

A: 需要**重启应用**使新环境变量生效

### Q: 如何确认环境变量已设置?

A: 打开新的CMD窗口，运行:
```batch
echo %DASHSCOPE_API_KEY%
```
应显示您的API密钥开头

### Q: 模型名称如何选择?

A: 使用您购买的模型:
- qwen3-max-2026-01-23 (推荐)
- qwen-max-latest
- qwen-turbo
- 其他可用模型

---

## 🔧 高级配置

### 在命令行临时设置 (仅当前会话)

```batch
set DASHSCOPE_API_KEY=sk-xxxx
set QWEN_MODEL=qwen3-max-2026-01-23
python cve_integrated_gui.py
```

### 从.env文件读取 (需修改代码)

如需支持.env文件，可使用python-dotenv:
```bash
pip install python-dotenv
```

### Python中直接设置 (仅供测试)

```python
import os
os.environ['DASHSCOPE_API_KEY'] = 'sk-xxxx'
os.environ['QWEN_MODEL'] = 'qwen3-max-2026-01-23'
```

---

## 📋 完整配置清单

- [ ] 获取DASHSCOPE_API_KEY
- [ ] 运行: `setx DASHSCOPE_API_KEY sk-xxxx`
- [ ] 运行: `setx QWEN_MODEL qwen3-max-2026-01-23`
- [ ] 重启应用
- [ ] 测试AI分析功能
- [ ] 验证结果正常显示

---

## 相关文档

完整的技术细节请查看: **QWEN_API_CONFIG_FIX_REPORT.md**

