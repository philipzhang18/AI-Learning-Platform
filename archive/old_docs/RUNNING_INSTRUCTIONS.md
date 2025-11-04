# CVE 项目启动说明

## 虚拟环境激活方法

每次启动 Python 程序前，需要先激活虚拟环境。

### Windows 系统:

```bash
# 进入项目目录
cd D:\AI\Claude\CVE

# 激活虚拟环境 (根据你实际的虚拟环境路径)
D:\AI\Claude\CVE\venv\Scripts\activate

# 或者如果你的虚拟环境路径是项目根目录下的 .venv
D:\AI\Claude\CVE\.venv\Scripts\activate
```

### 如果虚拟环境不存在，创建并激活:

```bash
# 1. 创建虚拟环境
python -m venv venv

# 2. 激活虚拟环境
D:\AI\Claude\CVE\venv\Scripts\activate

# 或 (如果使用 .venv 作为目录名)
D:\AI\Claude\CVE\.venv\Scripts\activate
```

## 安装依赖

激活虚拟环境后，安装项目依赖:

```bash
# 安装项目依赖
pip install -r requirements.txt
```

## 启动 CVE 项目

### 启动 FastAPI Web 服务:

```bash
# 激活虚拟环境后
python main.py
```

或者使用 uvicorn:

```bash
# 激活虚拟环境后
uvicorn main:app --reload --port 8000
```

### 运行 CVE 数据采集:

```bash
# 激活虚拟环境后
python collect_cves.py
```

### 运行 GUI 程序:

```bash
# 激活虚拟环境后
python cve_integrated_gui.py  # CVE 漏洞监控系统（整合版）
```

或使用快速启动脚本:

```bash
# Windows
start_cve_gui.bat

# Linux/macOS
./start_cve_gui.sh
```

## 环境变量配置

确保 .env 文件中已配置 NVD API Key:

```env
NVD_API_KEY=ca4d6d6b-1816-42f4-b7d8-b755a6565882
```

## 完整启动流程示例

```bash
# 1. 进入项目目录
cd D:\AI\Claude\CVE

# 2. 激活虚拟环境
D:\AI\Claude\CVE\venv\Scripts\activate

# 3. 安装依赖 (首次或依赖有更新时)
pip install -r requirements.txt

# 4. 启动项目
python main.py
```

## 虚拟环境使用完毕后

```bash
# 退出虚拟环境
deactivate
```

## 注意事项

1. 每次运行 Python 脚本前，都需要先激活虚拟环境
2. 确保 .env 文件存在并配置了正确的 API 密钥
3. 虚拟环境路径可能根据实际创建情况有所不同
4. 如果遇到权限问题，可能是虚拟环境路径不正确