import pygame
import random
import sys

# 初始化pygame
pygame.init()

# 游戏配置
WINDOW_WIDTH = 800
WINDOW_HEIGHT = 600
CELL_SIZE = 20
CELL_NUMBER_X = WINDOW_WIDTH // CELL_SIZE
CELL_NUMBER_Y = WINDOW_HEIGHT // CELL_SIZE

# 颜色定义
BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
GREEN = (0, 255, 0)
RED = (255, 0, 0)
DARK_GREEN = (0, 200, 0)
BLUE = (0, 0, 255)

# 创建窗口
screen = pygame.display.set_mode((WINDOW_WIDTH, WINDOW_HEIGHT))
pygame.display.set_caption('贪吃蛇游戏')
clock = pygame.time.Clock()

# 字体
font = pygame.font.Font(None, 36)
small_font = pygame.font.Font(None, 24)

class Snake:
    def __init__(self):
        # 蛇的初始位置（身体由多个方块组成）
        self.body = [
            pygame.Vector2(5, 10),
            pygame.Vector2(4, 10),
            pygame.Vector2(3, 10)
        ]
        self.direction = pygame.Vector2(1, 0)  # 初始向右移动
        self.new_block = False
        
    def draw_snake(self):
        """绘制蛇"""
        for index, block in enumerate(self.body):
            x_pos = int(block.x * CELL_SIZE)
            y_pos = int(block.y * CELL_SIZE)
            block_rect = pygame.Rect(x_pos, y_pos, CELL_SIZE, CELL_SIZE)
            
            if index == 0:  # 蛇头
                pygame.draw.rect(screen, DARK_GREEN, block_rect)
            else:  # 蛇身
                pygame.draw.rect(screen, GREEN, block_rect)
    
    def move_snake(self):
        """移动蛇"""
        if self.new_block:
            body_copy = self.body[:]
            body_copy.insert(0, body_copy[0] + self.direction)
            self.body = body_copy[:]
            self.new_block = False
        else:
            body_copy = self.body[:-1]
            body_copy.insert(0, self.body[0] + self.direction)  # 修复：使用 self.body[0] 而不是 body_copy[0]
            self.body = body_copy[:]
    
    def add_block(self):
        """增加蛇的长度"""
        self.new_block = True
    
    def check_collision(self):
        """检查碰撞"""
        # 检查是否撞墙
        if not 0 <= self.body[0].x < CELL_NUMBER_X or not 0 <= self.body[0].y < CELL_NUMBER_Y:
            return True
        
        # 检查是否撞到自己
        for block in self.body[1:]:
            if block == self.body[0]:
                return True
        
        return False

class Food:
    def __init__(self):
        self.randomize()
    
    def draw_food(self):
        """绘制食物"""
        food_rect = pygame.Rect(
            int(self.pos.x * CELL_SIZE), 
            int(self.pos.y * CELL_SIZE), 
            CELL_SIZE, 
            CELL_SIZE
        )
        pygame.draw.rect(screen, RED, food_rect)
    
    def randomize(self):
        """随机生成食物位置"""
        self.x = random.randint(0, CELL_NUMBER_X - 1)
        self.y = random.randint(0, CELL_NUMBER_Y - 1)
        self.pos = pygame.Vector2(self.x, self.y)

class Game:
    def __init__(self):
        self.snake = Snake()
        self.food = Food()
        self.score = 0
        self.game_over = False

        # 确保初始食物不在蛇身上
        while self.food.pos in self.snake.body:
            self.food.randomize()
    
    def update(self):
        """更新游戏状态"""
        if not self.game_over:
            self.snake.move_snake()
            self.check_collision()
            self.check_fail()
    
    def draw_elements(self):
        """绘制所有元素"""
        screen.fill(BLACK)
        self.food.draw_food()
        self.snake.draw_snake()
        self.draw_score()
        
        if self.game_over:
            self.draw_game_over()
    
    def check_collision(self):
        """检查蛇是否吃到食物"""
        if self.food.pos == self.snake.body[0]:
            self.food.randomize()
            self.snake.add_block()
            self.score += 1

            # 确保食物不会生成在蛇身上（包括蛇头）
            while self.food.pos in self.snake.body:  # 修复：使用 while 循环，检查整个蛇身
                self.food.randomize()
    
    def check_fail(self):
        """检查游戏是否结束"""
        if self.snake.check_collision():
            self.game_over = True
    
    def draw_score(self):
        """绘制分数"""
        score_text = str(self.score)
        score_surface = font.render(score_text, True, WHITE)
        score_x = int(WINDOW_WIDTH - 60)
        score_y = int(WINDOW_HEIGHT - 40)
        score_rect = score_surface.get_rect(center=(score_x, score_y))
        screen.blit(score_surface, score_rect)
        
        # 绘制分数标签
        score_label = small_font.render("Score:", True, WHITE)
        label_rect = score_label.get_rect(center=(score_x - 30, score_y - 20))
        screen.blit(score_label, label_rect)
    
    def draw_game_over(self):
        """绘制游戏结束界面"""
        # 半透明覆盖层
        overlay = pygame.Surface((WINDOW_WIDTH, WINDOW_HEIGHT))
        overlay.set_alpha(128)
        overlay.fill(BLACK)
        screen.blit(overlay, (0, 0))
        
        # 游戏结束文字
        game_over_text = font.render("Game Over!", True, WHITE)
        text_rect = game_over_text.get_rect(center=(WINDOW_WIDTH//2, WINDOW_HEIGHT//2 - 50))
        screen.blit(game_over_text, text_rect)
        
        # 最终分数
        final_score = font.render(f"Final Score: {self.score}", True, WHITE)
        score_rect = final_score.get_rect(center=(WINDOW_WIDTH//2, WINDOW_HEIGHT//2))
        screen.blit(final_score, score_rect)
        
        # 重新开始提示
        restart_text = small_font.render("Press SPACE to restart or ESC to quit", True, WHITE)
        restart_rect = restart_text.get_rect(center=(WINDOW_WIDTH//2, WINDOW_HEIGHT//2 + 50))
        screen.blit(restart_text, restart_rect)
    
    def reset_game(self):
        """重置游戏"""
        self.__init__()

def main():
    """主函数"""
    game = Game()
    
    # 设置游戏循环
    SCREEN_UPDATE = pygame.USEREVENT
    pygame.time.set_timer(SCREEN_UPDATE, 150)  # 控制蛇的移动速度
    
    while True:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                pygame.quit()
                sys.exit()
            
            if event.type == SCREEN_UPDATE:
                game.update()
            
            if event.type == pygame.KEYDOWN:
                if not game.game_over:
                    # 控制蛇的方向
                    if event.key == pygame.K_UP:
                        if game.snake.direction.y != 1:
                            game.snake.direction = pygame.Vector2(0, -1)
                    if event.key == pygame.K_DOWN:
                        if game.snake.direction.y != -1:
                            game.snake.direction = pygame.Vector2(0, 1)
                    if event.key == pygame.K_RIGHT:
                        if game.snake.direction.x != -1:
                            game.snake.direction = pygame.Vector2(1, 0)
                    if event.key == pygame.K_LEFT:
                        if game.snake.direction.x != 1:
                            game.snake.direction = pygame.Vector2(-1, 0)
                else:
                    # 游戏结束后重新开始
                    if event.key == pygame.K_SPACE:
                        game.reset_game()
                    elif event.key == pygame.K_ESCAPE:
                        pygame.quit()
                        sys.exit()
        
        game.draw_elements()
        pygame.display.update()
        clock.tick(60)  # 帧率

if __name__ == "__main__":
    main()
