"""数据访问层 (DAO) - Dell 安全公告数据操作"""
import sqlite3
import json
from typing import List, Dict, Optional, Any


class DellAdvisoryDAO:
    """Dell 安全公告数据访问对象"""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def get_by_id(self, dsa_id: str) -> Optional[Dict[str, Any]]:
        """根据 DSA ID 获取单条记录"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT data FROM dell_advisories WHERE dsa_id = ?", (dsa_id,))
        row = cursor.fetchone()
        if row and row[0]:
            return json.loads(row[0])
        return None

    def get_all(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """获取所有 Dell 公告"""
        cursor = self.conn.cursor()
        if limit:
            cursor.execute("SELECT data FROM dell_advisories ORDER BY published_date DESC LIMIT ?", (limit,))
        else:
            cursor.execute("SELECT data FROM dell_advisories ORDER BY published_date DESC")

        results = []
        for (data_str,) in cursor.fetchall():
            if data_str:
                try:
                    results.append(json.loads(data_str))
                except json.JSONDecodeError:
                    continue
        return results

    def search_by_keyword(self, keyword: str, limit: int = 100) -> List[Dict[str, Any]]:
        """使用 FTS5 全文搜索"""
        cursor = self.conn.cursor()
        search_upper = f"%{keyword.upper()}%"

        # 第一级：搜索索引列
        cursor.execute("""
            SELECT data FROM dell_advisories
            WHERE UPPER(dsa_id) LIKE ? OR UPPER(title) LIKE ? OR UPPER(cve_ids) LIKE ?
            ORDER BY published_date DESC
            LIMIT ?
        """, (search_upper, search_upper, search_upper, limit))

        results = []
        for (data_str,) in cursor.fetchall():
            if data_str:
                try:
                    results.append(json.loads(data_str))
                except json.JSONDecodeError:
                    continue

        # 第二级：FTS5 全文搜索
        if not results:
            fts_term = keyword.replace('"', '""')
            try:
                cursor.execute("""
                    SELECT d.data FROM dell_fts f
                    JOIN dell_advisories d ON d.rowid = f.rowid
                    WHERE dell_fts MATCH ?
                    LIMIT ?
                """, (f'"{fts_term}"', limit))
                for (data_str,) in cursor.fetchall():
                    if data_str:
                        try:
                            results.append(json.loads(data_str))
                        except json.JSONDecodeError:
                            continue
            except sqlite3.OperationalError:
                pass

        return results

    def insert(self, advisory_data: Dict[str, Any]) -> bool:
        """插入或更新 Dell 公告记录"""
        try:
            cursor = self.conn.cursor()
            cve_ids_str = ", ".join(advisory_data.get("cve_ids", []))
            cursor.execute("""
                INSERT OR REPLACE INTO dell_advisories
                (dsa_id, title, cve_ids, data, published_date, collected_date, link)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                advisory_data.get("dell_security_advisory"),
                advisory_data.get("title"),
                cve_ids_str,
                json.dumps(advisory_data, ensure_ascii=False),
                advisory_data.get("published_date"),
                advisory_data.get("collected_date"),
                advisory_data.get("link")
            ))
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"插入 Dell 公告失败: {e}")
            return False

    def get_all_cve_ids(self) -> set:
        """获取所有 Dell 公告中的 CVE IDs（优化版）"""
        import re
        cursor = self.conn.cursor()
        cursor.execute('SELECT cve_ids FROM dell_advisories WHERE cve_ids IS NOT NULL AND cve_ids != ""')

        all_cve_ids = set()
        for (cve_ids_str,) in cursor.fetchall():
            if cve_ids_str:
                for cve_id in re.split(r'[,\s]+', cve_ids_str):
                    cve_id = cve_id.strip()
                    if cve_id.startswith('CVE-'):
                        all_cve_ids.add(cve_id)
        return all_cve_ids

    def count_total(self) -> int:
        """统计 Dell 公告总数"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM dell_advisories")
        return cursor.fetchone()[0]
