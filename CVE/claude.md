# Claude 开发环境配置

## 环境优先级

### 虚拟环境配置
**指令：** 所有涉及代码执行、依赖项检查或环境交互的任务，**必须优先在 `D:\AI\cursor\starone\.venv` 虚拟环境中执行**。

#### 激活虚拟环境
```bash
# Windows PowerShell
D:\AI\cursor\starone\.venv\Scripts\Activate.ps1

# Windows CMD
D:\AI\cursor\starone\.venv\Scripts\activate.bat

# Git Bash / WSL
source D:\AI\cursor\starone\.venv\Scripts\activate
```

#### 验证环境
```bash
# 检查 Python 解释器路径
where python

# 检查 pip 包管理器
pip --version

# 查看已安装的包
pip list
```

## 开发规范

### 目标受众
面向**中高级开发者**，提供：
- 清晰、准确、可操作的**代码示例**
- 深入的**技术参考**
- 最佳实践和性能优化建议
- 高级特性和设计模式应用

### 代码示例标准
1. **完整性**：提供可直接运行的完整代码
2. **注释详尽**：关键逻辑必须有清晰注释
3. **错误处理**：包含异常处理和边界情况
4. **性能考虑**：涉及性能相关的优化说明

## 语言配置

### 文档语言
**配置：** 文档撰写、审查反馈、以及所有用户交互信息，**均使用中文（简体）**。

### 交互规范
- **技术文档**：中文（简体）
- **代码注释**：中文（简体）
- **错误提示**：中文（简体）
- **变量命名**：英文（遵循 PEP8 或相应语言规范）

## 项目结构建议

```
D:\AI\Claude\
├── claude.md                # 环境配置文档
├── .venv/                   # 项目专用虚拟环境（可选）
├── src/                     # 源代码目录
│   ├── __init__.py
│   └── main.py
├── tests/                   # 测试代码目录
│   └── test_main.py
├── docs/                    # 文档目录
│   └── README.md
├── requirements.txt         # 依赖项列表
└── .gitignore              # Git 忽略文件
```

## 依赖管理

### requirements.txt 示例
```txt
# 核心依赖
numpy>=1.21.0
pandas>=1.3.0
requests>=2.26.0

# 开发依赖
pytest>=6.2.0
black>=21.6b0
flake8>=3.9.0
mypy>=0.910

# 可选依赖
jupyter>=1.0.0
ipython>=7.25.0
```

### 依赖安装
```bash
# 激活虚拟环境后安装依赖
pip install -r requirements.txt

# 升级 pip
python -m pip install --upgrade pip

# 安装开发依赖
pip install -e .[dev]
```

## 开发工具配置

### VS Code 设置
```json
{
    "python.defaultInterpreterPath": "D:\\AI\\cursor\\starone\\.venv\\Scripts\\python.exe",
    "python.linting.enabled": true,
    "python.linting.pylintEnabled": false,
    "python.linting.flake8Enabled": true,
    "python.formatting.provider": "black",
    "editor.formatOnSave": true,
    "files.encoding": "utf8",
    "files.eol": "\n"
}
```

### Git 配置
```bash
# 设置用户信息
git config --local user.name "您的名字"
git config --local user.email "your.email@example.com"

# 设置编码
git config --local core.quotepath false
git config --local gui.encoding utf-8
git config --local i18n.commit.encoding utf-8
git config --local i18n.logoutputencoding utf-8
```

## 常用命令速查

### Python 环境
```bash
# 创建虚拟环境
python -m venv .venv

# 查看 Python 版本
python --version

# 查看包详情
pip show package_name

# 导出依赖
pip freeze > requirements.txt
```

### 代码质量检查
```bash
# 代码格式化
black src/

# 代码风格检查
flake8 src/

# 类型检查
mypy src/

# 运行测试
pytest tests/ -v
```

## 注意事项

1. **环境隔离**：始终在虚拟环境中工作，避免污染系统 Python
2. **版本控制**：所有代码变更应通过 Git 进行版本管理
3. **代码审查**：重要功能提交前进行代码审查
4. **文档同步**：代码更新时同步更新相关文档
5. **测试覆盖**：保持合理的测试覆盖率（建议 >80%）

---

*最后更新时间：2025-10-28*
*文档版本：v1.0.0*