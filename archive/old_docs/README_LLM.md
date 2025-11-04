# LLM API 集成模块 - Claude & Qwen

一个支持 Claude 和 Qwen（阿里云百炼）API 的统一集成模块，具备自动故障切换功能。

## 功能特性

- ✨ **双模型支持**：同时支持 Anthropic Claude 和阿里云 Qwen 模型
- 🔄 **自动故障切换**：当主模型不可用时自动切换到备用模型
- 🔁 **重试机制**：内置指数退避的重试逻辑
- 📝 **统一接口**：使用相同的 API 调用不同的模型
- 🌊 **流式输出**：支持流式响应（模拟）
- 📊 **使用统计**：追踪 Token 使用情况
- 🔐 **安全配置**：支持环境变量和配置文件

## 快速开始

### 1. 安装依赖

```bash
pip install anthropic openai requests python-dotenv
```

### 2. 配置 API 密钥

#### 方法一：使用配置文件

编辑 `llm_config.py`：

```python
CLAUDE_API_KEY = "your-claude-api-key"
QWEN_API_KEY = "sk-your-qwen-api-key"
```

#### 方法二：使用环境变量

```bash
# Windows CMD
set CLAUDE_API_KEY=your-claude-api-key
set QWEN_API_KEY=sk-your-qwen-api-key

# Windows PowerShell
$env:CLAUDE_API_KEY="your-claude-api-key"
$env:QWEN_API_KEY="sk-your-qwen-api-key"

# Linux/Mac
export CLAUDE_API_KEY="your-claude-api-key"
export QWEN_API_KEY="sk-your-qwen-api-key"
```

### 3. 基础使用

```python
from llm_api_client import chat_with_llm

# 快速聊天
response = chat_with_llm("解释什么是机器学习")
print(response)
```

## 详细用法

### 创建客户端

```python
from llm_api_client import LLMClient, Message

# 创建客户端（默认使用 Claude，启用自动切换）
client = LLMClient(
    primary_provider="claude",  # 或 "qwen"
    auto_fallback=True
)
```

### 基础聊天

```python
# 准备消息
messages = [
    Message(role="system", content="你是一个有帮助的助手"),
    Message(role="user", content="写一个Python快速排序函数")
]

# 发送请求
response = client.chat(messages)

if not response.error:
    print(f"模型: {response.provider.value}")
    print(f"回复: {response.content}")
    print(f"Token使用: {response.usage}")
else:
    print(f"错误: {response.error}")
```

### 指定模型提供商

```python
# 强制使用 Qwen
response = client.chat(messages, provider="qwen")

# 强制使用 Claude
response = client.chat(messages, provider="claude")
```

### 流式输出

```python
# 流式生成响应
for chunk in client.stream_chat(messages):
    print(chunk, end="", flush=True)
```

### 多轮对话

```python
conversation = [
    Message(role="system", content="你是一个编程助手")
]

# 第一轮
conversation.append(Message(role="user", content="什么是REST API？"))
response = client.chat(conversation)
conversation.append(Message(role="assistant", content=response.content))

# 第二轮
conversation.append(Message(role="user", content="给个例子"))
response = client.chat(conversation)
print(response.content)
```

### 测试连接

```python
# 测试所有提供商
client.test_connection()  # 返回 True/False

# 测试特定提供商
client.test_connection("claude")
client.test_connection("qwen")

# 获取可用提供商列表
providers = client.get_available_providers()
print(f"可用: {providers}")
```

## 配置选项

### 模型选择

**Claude 模型：**
- `claude-3-opus-20240229` (最强)
- `claude-3-sonnet-20240229` (平衡)
- `claude-3-haiku-20240307` (最快)

**Qwen 模型：**
- `qwen-max` (最强)
- `qwen-plus` (平衡)
- `qwen-turbo` (最快)
- `qwen-coder-plus` (编程特化)

### 参数配置

```python
response = client.chat(
    messages,
    temperature=0.7,      # 创造性 (0-1)
    max_tokens=2048,      # 最大输出长度
    provider="auto"       # 自动选择
)
```

### 系统配置

在 `llm_config.py` 中调整：

```python
DEFAULT_MODEL_PROVIDER = "claude"  # 默认模型
AUTO_FALLBACK = True               # 自动切换
TIMEOUT_SECONDS = 30               # 超时时间
MAX_RETRIES = 3                    # 重试次数
RETRY_DELAY = 2                    # 重试延迟
```

## 运行示例

```bash
# 运行交互式示例程序
python llm_examples.py

# 测试连接
python llm_api_client.py
```

## 故障处理

### 自动故障切换流程

1. 尝试使用主模型（默认 Claude）
2. 如果失败，自动重试（最多 3 次）
3. 如果仍然失败且启用了 `AUTO_FALLBACK`
4. 自动切换到备用模型（Qwen）
5. 返回成功的响应或错误信息

### 常见问题

**Q: 连接超时**
```python
# 增加超时时间
TIMEOUT_SECONDS = 60  # 在 llm_config.py 中
```

**Q: API 密钥无效**
```python
# 检查密钥配置
client = LLMClient()
print(client.get_available_providers())  # 查看哪些可用
```

**Q: 特定模型不可用**
```python
# 禁用自动切换，手动处理
client = LLMClient(auto_fallback=False)
response = client.chat(messages, provider="claude")
if response.error:
    # 手动切换
    response = client.chat(messages, provider="qwen")
```

## 日志和调试

日志自动写入 `llm_api.log`：

```python
# 调整日志级别
LOG_LEVEL = "DEBUG"  # 在 llm_config.py 中

# 查看日志
tail -f llm_api.log  # Linux/Mac
type llm_api.log     # Windows
```

## 安全建议

1. **永远不要** 将 API 密钥硬编码在代码中
2. **永远不要** 将包含密钥的文件提交到版本控制
3. **使用** 环境变量或安全的密钥管理服务
4. **定期** 轮换 API 密钥
5. **监控** API 使用情况和异常

## API 获取

### Claude API
1. 访问 [Anthropic Console](https://console.anthropic.com/)
2. 创建账户并获取 API Key
3. 查看 [定价页面](https://www.anthropic.com/pricing)

### Qwen API（阿里云百炼）
1. 访问 [阿里云百炼](https://dashscope.aliyun.com/)
2. 开通服务并获取 API Key
3. 查看 [模型列表](https://help.aliyun.com/zh/dashscope/developer-reference/model-list)

## HTTP 工具配置方式

### 什么是 HTTP 工具配置？

除了直接使用 Python SDK，本项目还支持通过 JSON 配置文件的方式调用模型。这种方式更加灵活，便于配置管理和工具切换。

### 配置文件：qwen_http_tools.json

HTTP 工具配置文件允许您定义多个工具端点和参数模板：

```json
{
  "tools": {
    "qwen-code": {
      "type": "http",
      "endpoint": "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
      "headers": {
        "Authorization": "Bearer YOUR_API_KEY",
        "Content-Type": "application/json"
      },
      "body_template": {
        "model": "qwen3-coder-plus",
        "messages": [
          {
            "role": "system",
            "content": "You are Qwen3 Coder Plus..."
          },
          {
            "role": "user",
            "content": "{{input}}"
          }
        ],
        "temperature": 0.6,
        "max_tokens": 4096,
        "top_p": 0.95
      },
      "response_mapping": {
        "output": "choices[0].message.content"
      },
      "description": "Qwen3 Coder Plus — 专业级编程助手"
    }
  }
}
```

### 使用 HTTP 工具配置

#### 基础用法

```python
from qwen_http_tools_example import QwenHTTPToolsClient

# 创建客户端（自动加载配置）
client = QwenHTTPToolsClient(
    config_path="qwen_http_tools.json",
    tool_name="qwen-code"
)

# 发送请求
response = client.chat("写一个快速排序算法")

if response["success"]:
    print(response["content"])
else:
    print(f"错误: {response['error']}")
```

#### 自定义参数

```python
# 覆盖温度和最大 token 数
response = client.chat(
    "解释什么是装饰器",
    temperature=0.3,  # 更确定性的输出
    max_tokens=2000   # 限制输出长度
)
```

#### 运行示例程序

```bash
# 运行 HTTP 工具配置示例
python qwen_http_tools_example.py

# 可选择多个示例：
# 1. 代码生成
# 2. 代码调试
# 3. 代码优化
# 4. 代码解释
# 5. 自定义配置说明
# 6. 交互式对话
```

### HTTP 工具配置 vs Python SDK

| 特性 | HTTP 工具配置 | Python SDK |
|------|-------------|-----------|
| 灵活性 | ⭐⭐⭐⭐⭐ 可动态切换端点 | ⭐⭐⭐ 需修改代码 |
| 易用性 | ⭐⭐⭐⭐ JSON 配置 | ⭐⭐⭐⭐⭐ API 简洁 |
| 依赖项 | 仅需 requests | 需安装专用 SDK |
| 故障切换 | ❌ 手动管理 | ✅ 自动切换 |
| 适用场景 | 工具集成、配置管理 | 应用开发、快速迭代 |

### 配置要点

1. **API 密钥安全**：
   ```json
   "Authorization": "Bearer sk-your-api-key-here"
   ```
   - 不要将包含真实密钥的配置文件提交到版本控制
   - 建议使用环境变量或密钥管理服务

2. **消息模板**：
   ```json
   "messages": [
     {"role": "system", "content": "系统提示"},
     {"role": "user", "content": "{{input}}"}
   ]
   ```
   - `{{input}}` 会被替换为用户实际输入
   - 可自定义 system prompt 调整模型行为

3. **响应映射**：
   ```json
   "response_mapping": {
     "output": "choices[0].message.content"
   }
   ```
   - 定义如何从响应 JSON 中提取内容
   - 支持路径语法：`field.subfield[index]`

### 多工具配置示例

可以在一个配置文件中定义多个工具：

```json
{
  "tools": {
    "qwen-code": {
      "endpoint": "...",
      "body_template": {
        "model": "qwen3-coder-plus",
        "temperature": 0.6
      }
    },
    "qwen-general": {
      "endpoint": "...",
      "body_template": {
        "model": "qwen-plus",
        "temperature": 0.8
      }
    },
    "qwen-strict": {
      "endpoint": "...",
      "body_template": {
        "model": "qwen3-coder-plus",
        "temperature": 0.1
      }
    }
  }
}
```

切换工具只需修改 `tool_name` 参数：

```python
# 使用编程专用配置
coder = QwenHTTPToolsClient(tool_name="qwen-code")

# 使用通用配置
general = QwenHTTPToolsClient(tool_name="qwen-general")

# 使用严格模式（低温度）
strict = QwenHTTPToolsClient(tool_name="qwen-strict")
```

## 项目结构

```
D:\AI\Claude\
├── llm_api_client.py           # 核心集成模块
├── llm_config.py               # 配置文件
├── llm_examples.py             # 使用示例
├── qwen_http_tools.json        # HTTP 工具配置（新增）
├── qwen_http_tools_example.py  # HTTP 工具使用示例（新增）
├── .env.llm.example            # 环境变量示例
├── llm_api.log                 # 运行日志
└── README_LLM.md               # 本文档
```

## 许可证

MIT License - 自由使用和修改

## 贡献

欢迎提交 Issue 和 Pull Request！

## 更新日志

### v1.1.0 (2025-10-29)
- ✨ 新增 HTTP 工具配置方式（qwen_http_tools.json）
- ✨ 新增 HTTP 工具配置示例程序（qwen_http_tools_example.py）
- 📝 更新文档，添加 HTTP 工具配置使用说明
- 🔧 支持通过 JSON 配置文件动态管理 API 端点和参数
- 💡 提供代码生成、调试、优化等多个实用示例

### v1.0.0 (2025-10-29)
- 初始版本
- 支持 Claude 和 Qwen API
- 实现自动故障切换
- 添加重试机制和日志

---

**注意：** 请妥善保管您的 API 密钥，避免泄露造成经济损失！