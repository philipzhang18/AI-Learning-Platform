# 如何设置 NVD API Key 环境变量

## 为什么需要 API Key？

- **无 API Key：** 10 次请求/分钟（采集 365 天数据需要约 1 小时）
- **有 API Key：** 100 次请求/分钟（采集 365 天数据仅需约 6 分钟）
- **速度提升：** 10 倍！

## 获取 NVD API Key

1. 访问：https://nvd.nist.gov/developers/request-an-api-key
2. 填写申请表单（免费）
3. 接收 API Key（通常几分钟内到达邮箱）

## 设置环境变量

### Windows

**方法 1：PowerShell（临时，当前会话有效）**
```powershell
$env:NVD_API_KEY="your-api-key-here"
```

**方法 2：CMD（临时，当前会话有效）**
```cmd
set NVD_API_KEY=your-api-key-here
```

**方法 3：系统环境变量（永久）**
1. 右键"此电脑" → "属性"
2. 点击"高级系统设置"
3. 点击"环境变量"
4. 在"用户变量"中点击"新建"
5. 变量名：`NVD_API_KEY`
6. 变量值：你的 API Key
7. 点击"确定"
8. **重启终端或程序**

**方法 4：使用 .env 文件**
1. 在项目目录创建 `.env` 文件
2. 添加内容：
   ```
   NVD_API_KEY=your-api-key-here
   ```
3. 在启动脚本中添加：
   ```bash
   export $(cat .env | xargs)
   python cve_integrated_gui.py
   ```

### Linux / macOS

**临时设置（当前会话）：**
```bash
export NVD_API_KEY="your-api-key-here"
```

**永久设置：**

1. 编辑 `~/.bashrc` 或 `~/.zshrc`：
   ```bash
   nano ~/.bashrc
   ```

2. 添加：
   ```bash
   export NVD_API_KEY="your-api-key-here"
   ```

3. 重新加载配置：
   ```bash
   source ~/.bashrc
   ```

## 验证设置

**Windows PowerShell:**
```powershell
echo $env:NVD_API_KEY
```

**Windows CMD:**
```cmd
echo %NVD_API_KEY%
```

**Linux / macOS:**
```bash
echo $NVD_API_KEY
```

应该显示你的 API Key。

## 在程序中使用

启动程序后，界面上会显示：
- ✓ **API Key 已配置**（绿色）- 表示已正确设置
- ⚠ **未配置 API Key（速度较慢）**（橙色）- 表示未设置

## 安全建议

1. **不要公开你的 API Key**
2. **不要提交到 Git 仓库**（添加 `.env` 到 `.gitignore`）
3. **定期更换 API Key**

## 示例完整流程

### Windows 快速设置（PowerShell）

```powershell
# 1. 设置环境变量
$env:NVD_API_KEY="your-api-key-here"

# 2. 激活虚拟环境
D:\AI\cursor\starone\.venv\Scripts\Activate.ps1

# 3. 启动程序
python cve_integrated_gui.py
```

### Linux/macOS 快速设置

```bash
# 1. 设置环境变量
export NVD_API_KEY="your-api-key-here"

# 2. 激活虚拟环境
source /D/AI/cursor/starone/.venv/Scripts/activate

# 3. 启动程序
python cve_integrated_gui.py
```

## 常见问题

### Q: 设置后程序还是显示未配置？
A: 需要重启程序或终端，确保环境变量生效。

### Q: 如何知道 API Key 是否工作？
A: 采集时查看日志，会显示 "✓ 使用环境变量 API Key，采集速度更快"。

### Q: 可以在程序中输入 API Key 吗？
A: 新版本已改为只使用环境变量，更安全且方便。

---

**推荐方式：** 使用系统环境变量（永久设置），一次配置，长期使用。
