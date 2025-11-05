# GitHub默认分支设置 - 快速指南

**仓库**: philipzhang18/CVE-Security-Solution
**操作**: 设置main为默认分支

---

## 🚀 快速操作（1分钟完成）

### 步骤 1: 访问Settings
1. 打开浏览器，访问：
   ```
   https://github.com/philipzhang18/CVE-Security-Solution/settings
   ```

   或者手动访问：
   - 打开 https://github.com/philipzhang18/CVE-Security-Solution
   - 点击页面顶部的 **Settings** 标签

### 步骤 2: 修改默认分支
1. 在Settings页面，左侧菜单点击 **General**（通常默认就在这个页面）

2. 向下滚动找到 **Default branch** 部分

3. 点击分支名旁边的 **⇄** 切换按钮

4. 在下拉菜单中选择 **main**

5. 点击 **Update** 按钮

6. 在弹出的确认对话框中，点击 **I understand, update the default branch**

### 步骤 3: 验证
- 返回仓库主页，应该看到默认显示 **main** 分支
- 刷新页面确认

✅ **完成！**

---

## 🔍 当前分支状态

根据Git检查，你的仓库状态：

```
本地分支:
  * main     ← 当前分支
    master

远程分支:
  origin/HEAD -> origin/main  ← 已指向main
  origin/main
  origin/master
```

✅ **好消息**: `origin/HEAD` 已经指向 `main`，这意味着Git层面已经配置正确。

⚠️ **需要操作**: 仍需在GitHub网页界面设置默认分支，这样：
- 新用户访问仓库时会看到main分支
- Pull Request默认合并到main
- 新克隆会自动检出main

---

## 📱 直接链接

**一键访问Settings页面**:
```
https://github.com/philipzhang18/CVE-Security-Solution/settings
```

**一键访问Branches设置页面**:
```
https://github.com/philipzhang18/CVE-Security-Solution/settings/branches
```

---

## 📋 操作检查清单

- [ ] 打开GitHub Settings页面
- [ ] 找到"Default branch"部分
- [ ] 点击切换按钮
- [ ] 选择main分支
- [ ] 确认更改
- [ ] 验证成功（刷新仓库主页）

---

## ❓ 常见问题

**Q: 看不到Settings标签？**
A: 确保已登录GitHub账号，且有仓库管理权限

**Q: 找不到Default branch选项？**
A: 在Settings → General页面，向下滚动即可看到

**Q: 改变会影响现有代码吗？**
A: 不会，只是改变了默认显示的分支，所有代码都保持不变

---

## 📞 需要详细指南？

查看完整指南文档：
```
GITHUB_SET_DEFAULT_BRANCH.md
```

包含：
- 详细步骤说明
- 多种操作方法
- 故障排查指南
- API操作方法

---

**创建时间**: 2025-11-04
**预计耗时**: 1分钟
**难度**: ⭐ 简单
