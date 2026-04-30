"""数据访问层 (DAO) - CVE 数据操作

将所有 CVE 相关的数据库操作集中到这里，实现关注点分离。
"""
import sqlite3
import json
from typing import List, Dict, Optional, Any
from datetime import datetime


class CveDAO:
    """CVE 数据访问对象"""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def get_by_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """根据 CVE ID 获取单条记录"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT data FROM cves WHERE cve_id = ?", (cve_id,))
        row = cursor.fetchone()
        if row and row[0]:
            return json.loads(row[0])
        return None

    def get_recent(self, limit: int = 500) -> List[Dict[str, Any]]:
        """获取最近的 CVE 记录"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT data FROM cves
            ORDER BY published_date DESC
            LIMIT ?
        """, (limit,))
        results = []
        for (data_str,) in cursor.fetchall():
            if data_str:
                try:
                    results.append(json.loads(data_str))
                except json.JSONDecodeError:
                    continue
        return results

    def search_by_keyword(self, keyword: str, limit: int = 200) -> List[Dict[str, Any]]:
        """使用 FTS5 全文搜索"""
        cursor = self.conn.cursor()
        fts_term = keyword.replace('"', '""')
        try:
            cursor.execute("""
                SELECT c.data FROM cves_fts f
                JOIN cves c ON c.rowid = f.rowid
                WHERE cves_fts MATCH ?
                LIMIT ?
            """, (f'"{fts_term}"', limit))
        except sqlite3.OperationalError:
            # FTS5 不可用，回退到 LIKE
            cursor.execute("""
                SELECT data FROM cves
                WHERE data LIKE ?
                ORDER BY published_date DESC
                LIMIT ?
            """, (f'%{keyword}%', limit))

        results = []
        for (data_str,) in cursor.fetchall():
            if data_str:
                try:
                    data = json.loads(data_str)
                    if data.get("source", "NVD") == "NVD":  # 只返回 NVD 来源
                        results.append(data)
                except json.JSONDecodeError:
                    continue
        return results

    def insert(self, cve_data: Dict[str, Any]) -> bool:
        """插入或更新 CVE 记录"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO cves (cve_id, data, last_modified, published_date)
                VALUES (?, ?, ?, ?)
            """, (
                cve_data.get("cve_id"),
                json.dumps(cve_data, ensure_ascii=False),
                cve_data.get("last_modified"),
                cve_data.get("published_date")
            ))
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"插入 CVE 失败: {e}")
            return False

    def delete_by_ids(self, cve_ids: List[str]) -> int:
        """批量删除 CVE 记录"""
        if not cve_ids:
            return 0
        cursor = self.conn.cursor()
        placeholders = ','.join(['?' for _ in cve_ids])
        cursor.execute(f"DELETE FROM cves WHERE cve_id IN ({placeholders})", cve_ids)
        self.conn.commit()
        return cursor.rowcount

    def count_total(self) -> int:
        """统计 CVE 总数"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM cves")
        return cursor.fetchone()[0]
