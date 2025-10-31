# CSV 文件加载 - 快速指南

## 🚀 三种使用方式

### 方式 1: 环境变量（最灵活）

```bash
# Windows PowerShell
$env:CVE_CSV_FILE="D:\my_data\cves.csv"

# Linux/macOS
export CVE_CSV_FILE="/path/to/cves.csv"
```

### 方式 2: 默认位置（最简单）

将 CSV 文件放在以下任一位置：
- `d:/download/sample_2025_10_30.csv` ✅
- `~/Downloads/sample_2025_10_30.csv` ✅
- `cve_data/sample_2025_10_30.csv` ✅
- `./sample_2025_10_30.csv` ✅

### 方式 3: 手动选择（最直观）

点击 GUI 中的 "📊 加载CSV数据" 按钮，通过对话框选择文件。

---

## 📋 CSV 文件格式

### 示例文件
```csv
cve_id,description,cvss_score,cvss_severity,published_date,last_modified,references,products
CVE-2023-1234,Sample vulnerability,7.5,HIGH,2023-01-15,2023-01-16,https://example.com,"webapp,server"
CVE-2023-5678,Buffer overflow,9.8,CRITICAL,2023-02-20,2023-02-21,https://example.com,"network,router,firewall"
```

### ⚠️ 重要规则

1. **包含逗号的字段必须用双引号包裹**
   - ✅ 正确: `"webapp,server"`
   - ❌ 错误: `webapp,server`

2. **必需列**: `cve_id`（其他列可选）

3. **编码**: UTF-8 或 ASCII

---

## ✅ 验证清单

- [ ] products 列用引号包裹了吗？（如果包含逗号）
- [ ] CSV 文件是 UTF-8 编码吗？
- [ ] 第一行是列名吗？
- [ ] 每行的列数相同吗？

---

## 🐛 常见问题

### 问题: 数据显示不完整

**原因**: products 列没有用引号包裹

**解决**: 
```csv
# 修改前
products
webapp,server

# 修改后
products
"webapp,server"
```

### 问题: 提示"找不到文件"

**解决**: 
1. 检查文件路径是否正确
2. 使用环境变量 `CVE_CSV_FILE` 指定路径
3. 或手动选择文件

---

**详细说明**: 查看 `CSV加载功能修复说明.md`
