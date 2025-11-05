# 设置GitHub默认分支为main

**仓库**: philipzhang18/CVE-Security-Solution
**目标**: 将默认分支从master改为main
**日期**: 2025-11-04

---

## 📋 快速操作指南

### 方法一：通过GitHub网页界面（推荐）⭐

#### 步骤 1: 访问仓库设置
1. 打开浏览器，访问仓库地址：
   ```
   https://github.com/philipzhang18/CVE-Security-Solution
   ```

2. 点击仓库页面顶部的 **Settings（设置）** 标签
   - 如果看不到Settings，确保你已登录并有仓库管理权限

#### 步骤 2: 修改默认分支
1. 在左侧菜单中，找到并点击 **Branches（分支）** 或 **General（常规）**

2. 找到 **Default branch（默认分支）** 部分
   - 通常在页面中间偏上的位置
   - 显示当前默认分支（可能是master）

3. 点击默认分支旁边的 **⇄（切换图标）** 或 **铅笔图标（编辑）**

4. 在弹出的下拉菜单中选择 **main**

5. 点击 **Update（更新）** 按钮

6. 在确认对话框中点击 **I understand, update the default branch（我明白，更新默认分支）**

#### 步骤 3: 验证更改
1. 返回仓库主页面：https://github.com/philipzhang18/CVE-Security-Solution
2. 检查页面顶部的分支切换器，应该显示 **main** 为默认分支
3. 刷新页面，确认显示的是main分支的内容

✅ **完成！** 默认分支已设置为main

---

## 🔧 方法二：使用GitHub CLI（可选）

如果你安装了GitHub CLI (`gh`)，可以使用命令行操作：

### 前置条件
```bash
# 安装GitHub CLI (如果未安装)
# Windows (使用 winget)
winget install --id GitHub.cli

# 或下载安装包
# https://cli.github.com/
```

### 设置默认分支
```bash
# 1. 登录GitHub
gh auth login

# 2. 切换到项目目录
cd /D/AI/Claude/CVE

# 3. 设置默认分支为main
gh repo edit philipzhang18/CVE-Security-Solution --default-branch main

# 4. 验证
gh repo view philipzhang18/CVE-Security-Solution
```

---

## 📱 方法三：使用GitHub API（高级）

如果你有GitHub Personal Access Token：

```bash
# 设置变量
GITHUB_TOKEN="your_personal_access_token"
REPO_OWNER="philipzhang18"
REPO_NAME="CVE-Security-Solution"

# 使用API修改默认分支
curl -X PATCH \
  -H "Accept: application/vnd.github.v3+json" \
  -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/repos/$REPO_OWNER/$REPO_NAME \
  -d '{"default_branch":"main"}'
```

---

## ✅ 验证步骤

### 1. 网页验证
访问仓库主页，检查：
```
https://github.com/philipzhang18/CVE-Security-Solution
```
- ✅ 页面顶部显示 **main** 分支
- ✅ 代码浏览显示的是main分支内容
- ✅ README显示的是最新版本

### 2. Git命令验证
```bash
cd /D/AI/Claude/CVE

# 查看远程仓库信息
git remote show origin

# 应该显示:
# HEAD branch: main  ← 确认这里显示main
```

### 3. 克隆验证
在另一个目录测试克隆：
```bash
cd /tmp
git clone https://github.com/philipzhang18/CVE-Security-Solution.git test-clone
cd test-clone
git branch
# 应该显示: * main
```

---

## 🔄 后续操作（可选）

### 删除旧的master分支（如果不再需要）

**⚠️ 警告**: 删除前确保main分支已包含所有更改！

#### 通过GitHub网页界面删除
1. 访问：https://github.com/philipzhang18/CVE-Security-Solution/branches
2. 找到 **master** 分支
3. 点击垃圾桶图标 🗑️
4. 确认删除

#### 通过命令行删除
```bash
cd /D/AI/Claude/CVE

# 删除本地master分支
git branch -d master

# 删除远程master分支（谨慎操作）
git push origin --delete master
```

### 更新本地Git配置
```bash
cd /D/AI/Claude/CVE

# 设置本地默认分支为main
git config branch.autoSetupMerge simple
git branch --set-upstream-to=origin/main main

# 拉取最新更改
git pull origin main
```

---

## 📊 分支状态检查

### 当前分支情况
```bash
cd /D/AI/Claude/CVE

# 查看本地分支
git branch -vv

# 查看远程分支
git branch -r

# 查看所有分支
git branch -a
```

### 预期输出
```
* main   9391001 [origin/main] feat: v3.7 重大性能优化与项目清理
  master b615b60 [origin/master: behind 2] Merge branch 'master'...
```

---

## ❓ 常见问题

### Q1: 为什么要改为main分支？
**A**:
- GitHub推荐使用`main`作为默认分支名
- 更具包容性的命名
- 你的主要开发工作已在main分支上

### Q2: 改变默认分支会影响现有克隆吗？
**A**:
- 不会影响已克隆的仓库
- 新的克隆会自动检出main分支
- 现有协作者需要更新本地配置

### Q3: master分支会被删除吗？
**A**:
- 改变默认分支**不会**自动删除master
- master分支会继续存在，除非手动删除
- 可以保留master作为备份

### Q4: 如果操作失败怎么办？
**A**:
- 确保你有仓库管理权限
- 确保main分支已推送到GitHub
- 尝试刷新页面或重新登录
- 检查网络连接

---

## 🎯 操作检查清单

执行前检查：
- [ ] 已登录GitHub账号
- [ ] 有仓库管理权限（Owner或Admin）
- [ ] main分支已存在并推送到远程
- [ ] main分支包含最新代码

执行后验证：
- [ ] GitHub仓库页面显示main为默认分支
- [ ] 新克隆自动检出main分支
- [ ] git remote show origin显示HEAD branch: main
- [ ] 仓库README显示最新内容

---

## 📝 详细步骤（图文说明）

### 步骤1: 进入仓库Settings
```
https://github.com/philipzhang18/CVE-Security-Solution
                                    ↓
                            点击顶部 "Settings" 标签
```

### 步骤2: 找到Default branch设置
```
Settings 页面
    ↓
左侧菜单: General 或 Branches
    ↓
找到 "Default branch" 部分
    ↓
当前显示: master 或其他分支
```

### 步骤3: 修改为main
```
点击分支名旁边的切换按钮（⇄ 或 铅笔图标）
    ↓
下拉菜单选择: main
    ↓
点击 "Update" 按钮
    ↓
确认对话框点击: "I understand, update the default branch"
```

### 步骤4: 完成
```
✅ 成功提示: "Default branch updated to main"
    ↓
返回仓库主页验证
```

---

## 🔐 权限要求

需要以下权限之一：
- ✅ **仓库所有者 (Owner)**
- ✅ **管理员 (Admin)**
- ❌ 写入权限 (Write) - 不够
- ❌ 读取权限 (Read) - 不够

检查权限：
1. 访问仓库主页
2. 如果能看到 **Settings** 标签，说明有足够权限
3. 如果看不到，需要联系仓库所有者授权

---

## 📞 需要帮助？

如果在设置过程中遇到问题：

1. **GitHub官方文档**:
   https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-branches-in-your-repository/changing-the-default-branch

2. **GitHub支持**:
   https://support.github.com/

3. **检查权限**:
   确保你是仓库所有者或管理员

---

## ✨ 总结

设置GitHub默认分支为main的步骤：

1. ✅ 访问 https://github.com/philipzhang18/CVE-Security-Solution
2. ✅ 点击 **Settings** 标签
3. ✅ 找到 **Default branch** 部分
4. ✅ 切换为 **main** 分支
5. ✅ 确认更改
6. ✅ 验证成功

**预计耗时**: 1-2分钟
**难度**: ⭐ 简单
**风险**: 🟢 低（不会删除任何代码）

---

**创建日期**: 2025-11-04
**仓库**: philipzhang18/CVE-Security-Solution
**目标分支**: main
**状态**: 等待手动操作
