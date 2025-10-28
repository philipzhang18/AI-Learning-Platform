# 🐍 贪吃蛇游戏 (Snake Game)

![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![Pygame](https://img.shields.io/badge/Pygame-2.0%2B-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

一个使用 Python 和 Pygame 开发的经典贪吃蛇游戏。具有流畅的游戏体验、精美的界面设计和完善的游戏机制。

## ✨ 游戏特性

- 🎮 **经典玩法** - 完整复刻经典贪吃蛇游戏体验
- 🎯 **精确控制** - 流畅的方向控制和响应
- 📊 **分数系统** - 实时显示当前得分
- 🔄 **重新开始** - 游戏结束后可快速重新开始
- 🎨 **视觉效果** - 清晰的蛇头、蛇身和食物区分
- 🚫 **碰撞检测** - 完善的边界和自身碰撞检测

## 🛠️ 技术栈

- **Python 3.7+** - 核心编程语言
- **Pygame 2.0+** - 游戏开发框架
- **Random** - 食物随机生成
- **Vector2** - 二维向量处理

## 📋 安装要求

### 系统要求
- Windows / macOS / Linux
- Python 3.7 或更高版本
- pip 包管理器

### 依赖安装

1. 克隆仓库：
```bash
git clone https://github.com/philipzhang18/snake.git
cd snake
```

2. 创建虚拟环境（推荐）：
```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate
```

3. 安装依赖：
```bash
pip install pygame
```

## 🚀 运行游戏

在项目目录下执行：

```bash
python snake.py
```

或者直接运行：

```bash
python snake/snake.py
```

## 🎮 游戏玩法

### 控制方式
- **↑** - 向上移动
- **↓** - 向下移动
- **←** - 向左移动
- **→** - 向右移动
- **空格键** - 游戏结束后重新开始
- **ESC** - 退出游戏

### 游戏规则
1. 控制蛇吃掉红色的食物来增长身体
2. 每吃到一个食物得 1 分
3. 避免撞到墙壁或自己的身体
4. 尽可能获得更高的分数

### 游戏提示
- 蛇不能立即向相反方向移动（例如正在向右时不能直接向左）
- 食物会随机出现在游戏区域内
- 蛇头为深绿色，便于识别方向

## 📁 项目结构

```
snake/
├── snake.py          # 主游戏文件
├── README.md         # 项目说明文档
└── claude.md         # 开发环境配置文档
```

## 🔧 代码结构

### 主要类

#### `Snake` 类
- 管理蛇的状态和行为
- 处理蛇的移动逻辑
- 绘制蛇的图形
- 检测碰撞

#### `Food` 类
- 管理食物的生成和位置
- 绘制食物
- 确保食物不会生成在蛇身上

#### `Game` 类
- 游戏主控制器
- 管理游戏状态
- 处理游戏逻辑
- 显示分数和游戏结束界面

## 🐛 最近修复

### v1.0.1 (2025-10-28)
- ✅ 修复蛇移动逻辑错误：正确使用 `self.body[0]` 获取蛇头位置
- ✅ 修复食物生成位置检查：使用 while 循环确保食物不在蛇身上
- ✅ 改进初始化逻辑：游戏开始时检查食物位置

## 🎨 游戏截图

### 游戏界面
- 黑色背景
- 深绿色蛇头
- 绿色蛇身
- 红色食物
- 白色分数显示

### 游戏结束界面
- 显示 "Game Over!" 提示
- 显示最终得分
- 提供重新开始选项

## 📊 游戏配置

可在 `snake.py` 中调整的参数：

```python
WINDOW_WIDTH = 800      # 窗口宽度
WINDOW_HEIGHT = 600     # 窗口高度
CELL_SIZE = 20         # 单元格大小
SCREEN_UPDATE = 150    # 游戏速度（毫秒）
```

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！

### 贡献步骤
1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

### 代码规范
- 遵循 PEP 8 编码规范
- 添加必要的注释
- 保持代码简洁清晰
- 测试所有新功能

## 📝 待办事项

- [ ] 添加难度等级选择
- [ ] 添加音效和背景音乐
- [ ] 实现最高分记录功能
- [ ] 添加暂停功能
- [ ] 美化游戏界面
- [ ] 添加多种游戏模式
- [ ] 实现排行榜系统
- [ ] 添加成就系统

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

## 👨‍💻 作者

- **Philip Zhang** - [GitHub](https://github.com/philipzhang18)

## 🙏 致谢

- 感谢 [Pygame](https://www.pygame.org/) 社区提供的游戏开发框架
- 感谢所有贡献者的支持和建议
- 使用 [Claude Code](https://claude.com/claude-code) 协助开发

## 📧 联系方式

如有问题或建议，请通过以下方式联系：
- 提交 [Issue](https://github.com/philipzhang18/snake/issues)
- 发送邮件至 GitHub 个人主页

---

**享受游戏！** 🎮🐍

⭐ 如果您喜欢这个项目，请给个 Star！