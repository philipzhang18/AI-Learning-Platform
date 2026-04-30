"""数据访问层 (DAO) - Dell 技术库文章数据操作"""
import sqlite3
import json
from typing import List, Dict, Optional, Any


class DellKbDAO:
    """Dell 技术库文章数据访问对象"""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def get_by_id(self, article_id: str) -> Optional[Dict[str, Any]]:
        """根据文章 ID 获取单条记录"""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT article_id, title, content, solution, url, collected_date "
            "FROM dell_kb_articles WHERE article_id = ?", (article_id,)
        )
        row = cursor.fetchone()
        if row:
            return {
                'article_id': row[0],
                'title': row[1] or '',
                'content': row[2] or '',
                'solution': row[3] or '',
                'url': row[4] or '',
                'collected_date': row[5] or ''
            }
        return None

    def get_all(self, limit: int = 500) -> List[Dict[str, Any]]:
        """获取所有技术库文章"""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT article_id, title, content, solution, url, collected_date "
            "FROM dell_kb_articles ORDER BY collected_date DESC LIMIT ?", (limit,)
        )
        results = []
        for row in cursor.fetchall():
            results.append({
                'article_id': row[0],
                'title': row[1] or '',
                'content': row[2] or '',
                'solution': row[3] or '',
                'url': row[4] or '',
                'collected_date': row[5] or ''
            })
        return results

    def search(self, keyword: str, limit: int = 200) -> List[Dict[str, Any]]:
        """搜索技术库文章"""
        cursor = self.conn.cursor()
        like_term = f'%{keyword}%'
        cursor.execute(
            "SELECT article_id, title, content, solution, url, collected_date "
            "FROM dell_kb_articles "
            "WHERE article_id LIKE ? OR title LIKE ? OR content LIKE ? OR solution LIKE ? "
            "ORDER BY collected_date DESC LIMIT ?",
            (like_term, like_term, like_term, like_term, limit)
        )
        results = []
        for row in cursor.fetchall():
            results.append({
                'article_id': row[0],
                'title': row[1] or '',
                'content': row[2] or '',
                'solution': row[3] or '',
                'url': row[4] or '',
                'collected_date': row[5] or ''
            })
        return results

    def insert(self, article: Dict[str, Any]) -> bool:
        """插入或更新技术库文章"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO dell_kb_articles
                (article_id, title, content, solution, url, collected_date)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                article.get('article_id'),
                article.get('title'),
                article.get('content'),
                article.get('solution'),
                article.get('url'),
                article.get('collected_date')
            ))
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"插入技术库文章失败: {e}")
            return False

    def delete_by_ids(self, article_ids: List[str]) -> int:
        """批量删除技术库文章"""
        if not article_ids:
            return 0
        cursor = self.conn.cursor()
        placeholders = ','.join(['?' for _ in article_ids])
        cursor.execute(f"DELETE FROM dell_kb_articles WHERE article_id IN ({placeholders})", article_ids)
        self.conn.commit()
        return cursor.rowcount

    def count_total(self) -> int:
        """统计文章总数"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM dell_kb_articles")
        return cursor.fetchone()[0]
