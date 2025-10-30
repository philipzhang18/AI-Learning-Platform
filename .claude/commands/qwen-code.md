---
description: 使用 Qwen 3 Coder Plus 模型回答代码相关问题
---

# Qwen Code Assistant

你现在需要使用 Qwen 3 Coder Plus 模型来协助用户。

## 使用方式

1. **执行 Python 脚本调用 Qwen**：使用 Bash 工具执行以下命令：
   ```bash
   python .claude/qwen_code_helper.py "用户的问题"
   ```

2. **将 Qwen 的响应呈现给用户**：
   - 清晰地展示 Qwen 的回答
   - 如果是代码，确保格式正确
   - 添加必要的解释和上下文

3. **适用场景**：
   - 代码编写和生成
   - 代码审查和优化建议
   - 算法问题求解
   - 调试和问题诊断
   - 架构设计建议

## 重要说明

- Qwen 3 Coder Plus 专注于代码相关任务
- 确保问题清晰、具体
- 可以进行多轮对话，根据 Qwen 的回答进行追问
- 如果 Qwen 返回错误，请检查 API 配置和网络连接

## 示例工作流程

用户询问代码问题 → 使用 Bash 调用 qwen_code_helper.py → 获取 Qwen 响应 → 呈现结果给用户

现在，请准备好使用 Qwen 模型协助用户。用户的问题将在下一条消息中提供。
