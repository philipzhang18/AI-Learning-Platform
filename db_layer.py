"""
数据库访问层（DAO）v2.0
将数据库操作从 GUI 代码中抽离，提升可维护性

提供的 Repository 类：
    - LearnDAO          学习会话/产物（向后兼容）
    - CVERepository     NVD CVE 数据
    - DellRepository    Dell 安全公告
    - DellKBRepository  Dell 技术库
    - AISolutionRepository  AI 解决方案历史
    - StatsRepository   统计分析

使用示例：
    from db_layer import CVERepository, DellRepository

    cve_repo = CVERepository(conn, db_lock)
    critical_cves = cve_repo.find_by_severity("CRITICAL", limit=100)
    cve_data = cve_repo.find_by_id("CVE-2024-1234")

    dell_repo = DellRepository(conn, db_lock)
    advisory = dell_repo.find_by_dsa_id("DSA-2024-001")
"""
import json
import sqlite3
import threading
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Any


# ==================== 学习模块 DAO ====================

class LearnDAO:
    """学习模块数据库访问对象"""

    def __init__(self, conn: sqlite3.Connection, db_lock: threading.Lock):
        self.conn = conn
        self.db_lock = db_lock

    def save_session(self, topic: str, level: str, source_type: str,
                     source_content: str, conversation: List[Dict],
                     summary: str = "") -> int:
        """保存学习会话"""
        conv_json = json.dumps(conversation, ensure_ascii=False)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.db_lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO learn_sessions "
                "(topic, level, source_type, source_content, conversation, summary, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (topic, level, source_type, source_content, conv_json, summary, ts)
            )
            self.conn.commit()
            return cursor.lastrowid

    def save_artifact(self, session_id: Optional[int], topic: str,
                      artifact_type: str, title: str, content: str,
                      source_refs: str = "") -> int:
        """保存学习产物"""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.db_lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO learn_artifacts "
                "(session_id, topic, artifact_type, title, content, source_refs, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (session_id, topic, artifact_type, title, content, source_refs, ts)
            )
            self.conn.commit()
            return cursor.lastrowid


# ==================== Base Repository ====================

class BaseRepository:
    """Repository 基类，提供通用方法"""

    def __init__(self, conn: sqlite3.Connection,
                 db_lock: Optional[threading.Lock] = None):
        self.conn = conn
        self.db_lock = db_lock or threading.Lock()

    def _execute(self, sql: str, params: Tuple = ()) -> sqlite3.Cursor:
        """执行 SQL 语句"""
        with self.db_lock:
            cursor = self.conn.cursor()
            cursor.execute(sql, params)
            return cursor

    def _execute_many(self, sql: str, params_list: List[Tuple]) -> sqlite3.Cursor:
        """批量执行 SQL"""
        with self.db_lock:
            cursor = self.conn.cursor()
            cursor.executemany(sql, params_list)
            return cursor

    def _fetch_one(self, sql: str, params: Tuple = ()) -> Optional[Tuple]:
        """获取单条记录"""
        cursor = self._execute(sql, params)
        return cursor.fetchone()

    def _fetch_all(self, sql: str, params: Tuple = ()) -> List[Tuple]:
        """获取所有记录"""
        cursor = self._execute(sql, params)
        return cursor.fetchall()

    def _commit(self):
        """提交事务"""
        with self.db_lock:
            self.conn.commit()


# ==================== CVE Repository ====================

class CVERepository(BaseRepository):
    """NVD CVE 数据仓库"""

    def find_by_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """根据 CVE ID 查找记录

        Args:
            cve_id: CVE 编号 (e.g., "CVE-2024-1234")

        Returns:
            CVE 详细数据字典，未找到返回 None
        """
        row = self._fetch_one(
            "SELECT cve_id, data, last_modified, published_date "
            "FROM cves WHERE cve_id = ?",
            (cve_id.upper(),)
        )
        if not row:
            return None

        try:
            return {
                "cve_id": row[0],
                "data": json.loads(row[1]) if row[1] else {},
                "last_modified": row[2],
                "published_date": row[3],
            }
        except json.JSONDecodeError:
            return None

    def find_by_date_range(self, start_date: str, end_date: str,
                           limit: int = 1000) -> List[str]:
        """按时间范围查询 CVE ID 列表

        Args:
            start_date: 开始日期 (YYYY-MM-DD)
            end_date: 结束日期 (YYYY-MM-DD)
            limit: 最大返回数量

        Returns:
            CVE ID 列表
        """
        rows = self._fetch_all(
            "SELECT cve_id FROM cves "
            "WHERE published_date BETWEEN ? AND ? "
            "ORDER BY published_date DESC LIMIT ?",
            (start_date, end_date, limit)
        )
        return [r[0] for r in rows]

    def find_recent(self, days: int = 30, limit: int = 100) -> List[str]:
        """查询最近 N 天的 CVE"""
        from datetime import timedelta
        end = datetime.now().strftime("%Y-%m-%d")
        start = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
        return self.find_by_date_range(start, end, limit)

    def search_fts(self, keyword: str, limit: int = 100) -> List[str]:
        """全文搜索（使用 FTS 索引）"""
        try:
            rows = self._fetch_all(
                "SELECT cve_id FROM cves_fts WHERE cves_fts MATCH ? LIMIT ?",
                (keyword, limit)
            )
            return [r[0] for r in rows]
        except sqlite3.OperationalError:
            # FTS 表不存在，回退到普通搜索
            return self.search_like(keyword, limit)

    def search_like(self, keyword: str, limit: int = 100) -> List[str]:
        """LIKE 搜索（无 FTS 时回退）"""
        pattern = f"%{keyword}%"
        rows = self._fetch_all(
            "SELECT cve_id FROM cves WHERE cve_id LIKE ? OR data LIKE ? LIMIT ?",
            (pattern, pattern, limit)
        )
        return [r[0] for r in rows]

    def count(self) -> int:
        """获取总记录数"""
        row = self._fetch_one("SELECT COUNT(*) FROM cves")
        return row[0] if row else 0

    def delete_by_id(self, cve_id: str) -> bool:
        """删除指定 CVE 记录"""
        try:
            with self.db_lock:
                cursor = self.conn.cursor()
                # 先删除关联记录
                cursor.execute("DELETE FROM collection_history WHERE cve_id = ?",
                               (cve_id.upper(),))
                cursor.execute("DELETE FROM cves WHERE cve_id = ?",
                               (cve_id.upper(),))
                affected = cursor.rowcount
                self.conn.commit()
                return affected > 0
        except sqlite3.Error:
            return False

    def get_severity_distribution(self) -> Dict[str, int]:
        """统计严重等级分布

        Returns:
            {"CRITICAL": N, "HIGH": N, "MEDIUM": N, "LOW": N}
        """
        # 这需要解析 JSON 中的 severity 字段
        rows = self._fetch_all("SELECT data FROM cves")

        distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

        for (data,) in rows:
            try:
                cve_data = json.loads(data) if data else {}
                # 尝试从不同位置提取严重等级
                severity = self._extract_severity(cve_data)
                if severity in distribution:
                    distribution[severity] += 1
                else:
                    distribution["UNKNOWN"] += 1
            except json.JSONDecodeError:
                distribution["UNKNOWN"] += 1

        return distribution

    @staticmethod
    def _extract_severity(cve_data: dict) -> str:
        """从 CVE 数据中提取严重等级"""
        # 尝试 NVD 格式
        metrics = cve_data.get("metrics", {})
        for ver in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            if ver in metrics and metrics[ver]:
                cd = metrics[ver][0].get("cvssData", {})
                sev = cd.get("baseSeverity", "")
                if sev:
                    return sev.upper()

        # CVSS v2
        if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            cd = metrics["cvssMetricV2"][0].get("cvssData", {})
            score = cd.get("baseScore", 0)
            if score >= 7.0:
                return "HIGH"
            elif score >= 4.0:
                return "MEDIUM"
            elif score > 0:
                return "LOW"

        return "UNKNOWN"

    def exists(self, cve_id: str) -> bool:
        """检查 CVE 是否存在"""
        row = self._fetch_one(
            "SELECT 1 FROM cves WHERE cve_id = ? LIMIT 1",
            (cve_id.upper(),)
        )
        return row is not None


# ==================== Dell 安全公告 Repository ====================

class DellRepository(BaseRepository):
    """Dell 安全公告仓库"""

    def find_by_dsa_id(self, dsa_id: str) -> Optional[Dict[str, Any]]:
        """根据 DSA ID 查找"""
        row = self._fetch_one(
            "SELECT dsa_id, title, cve_ids, data, published_date, "
            "collected_date, link FROM dell_advisories WHERE dsa_id = ?",
            (dsa_id.upper(),)
        )
        if not row:
            return None

        return {
            "dsa_id": row[0],
            "title": row[1],
            "cve_ids": json.loads(row[2]) if row[2] else [],
            "data": json.loads(row[3]) if row[3] else {},
            "published_date": row[4],
            "collected_date": row[5],
            "link": row[6],
        }

    def find_by_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        """根据 CVE ID 查找关联的 DSA 公告"""
        rows = self._fetch_all(
            "SELECT dsa_id, title, cve_ids, data, published_date, "
            "collected_date, link FROM dell_advisories WHERE cve_ids LIKE ?",
            (f"%{cve_id.upper()}%",)
        )

        results = []
        for row in rows:
            try:
                cve_list = json.loads(row[2]) if row[2] else []
                # 精确匹配（避免 CVE-2024-1 匹配到 CVE-2024-12）
                if cve_id.upper() in [c.upper() for c in cve_list]:
                    results.append({
                        "dsa_id": row[0],
                        "title": row[1],
                        "cve_ids": cve_list,
                        "data": json.loads(row[3]) if row[3] else {},
                        "published_date": row[4],
                        "collected_date": row[5],
                        "link": row[6],
                    })
            except json.JSONDecodeError:
                continue

        return results

    def find_recent(self, days: int = 30, limit: int = 100) -> List[Dict[str, Any]]:
        """查询最近 N 天的 DSA"""
        from datetime import timedelta
        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")

        rows = self._fetch_all(
            "SELECT dsa_id, title, cve_ids, published_date "
            "FROM dell_advisories WHERE published_date >= ? "
            "ORDER BY published_date DESC LIMIT ?",
            (cutoff, limit)
        )

        return [
            {
                "dsa_id": r[0],
                "title": r[1],
                "cve_ids": json.loads(r[2]) if r[2] else [],
                "published_date": r[3],
            }
            for r in rows
        ]

    def search_title(self, keyword: str, limit: int = 100) -> List[Dict[str, Any]]:
        """按标题搜索"""
        rows = self._fetch_all(
            "SELECT dsa_id, title, published_date FROM dell_advisories "
            "WHERE title LIKE ? ORDER BY published_date DESC LIMIT ?",
            (f"%{keyword}%", limit)
        )
        return [
            {"dsa_id": r[0], "title": r[1], "published_date": r[2]}
            for r in rows
        ]

    def count(self) -> int:
        """总记录数"""
        row = self._fetch_one("SELECT COUNT(*) FROM dell_advisories")
        return row[0] if row else 0

    def delete_by_id(self, dsa_id: str) -> bool:
        """删除指定公告"""
        try:
            with self.db_lock:
                cursor = self.conn.cursor()
                cursor.execute("DELETE FROM dell_advisories WHERE dsa_id = ?",
                               (dsa_id.upper(),))
                affected = cursor.rowcount
                self.conn.commit()
                return affected > 0
        except sqlite3.Error:
            return False

    def get_monthly_counts(self, months: int = 12) -> List[Tuple[str, int]]:
        """按月统计公告数量

        Returns:
            [(年月, 数量), ...]
        """
        rows = self._fetch_all(
            "SELECT substr(published_date, 1, 7) AS ym, COUNT(*) "
            "FROM dell_advisories "
            "WHERE published_date IS NOT NULL "
            "GROUP BY ym ORDER BY ym DESC LIMIT ?",
            (months,)
        )
        return [(r[0], r[1]) for r in rows]


# ==================== Dell 知识库 Repository ====================

class DellKBRepository(BaseRepository):
    """Dell 技术库仓库"""

    def find_by_kb_number(self, kb_number: str) -> Optional[Dict[str, Any]]:
        """根据 KB 编号查找"""
        # 检查表结构以确定使用哪个字段
        row = self._fetch_one(
            "SELECT * FROM dell_kb_articles WHERE kb_number = ? OR title LIKE ? LIMIT 1",
            (kb_number, f"%{kb_number}%")
        )
        if not row:
            return None

        # 获取列名
        cursor = self._execute("SELECT * FROM dell_kb_articles WHERE 1=0")
        columns = [d[0] for d in cursor.description]
        return dict(zip(columns, row))

    def search(self, keyword: str, limit: int = 50) -> List[Dict[str, Any]]:
        """搜索 KB 文章"""
        try:
            rows = self._fetch_all(
                "SELECT title FROM dell_kb_articles WHERE title LIKE ? LIMIT ?",
                (f"%{keyword}%", limit)
            )
            return [{"title": r[0]} for r in rows]
        except sqlite3.OperationalError:
            return []

    def count(self) -> int:
        """总记录数"""
        try:
            row = self._fetch_one("SELECT COUNT(*) FROM dell_kb_articles")
            return row[0] if row else 0
        except sqlite3.OperationalError:
            return 0


# ==================== AI 解决方案 Repository ====================

class AISolutionRepository(BaseRepository):
    """AI 解决方案历史仓库"""

    def save(self, cve_id: str, advisory_id: str, solution: str,
             model: str = "", language: str = "zh_CN") -> int:
        """保存 AI 解决方案"""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.db_lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO ai_solutions "
                "(cve_id, advisory_id, solution, model, language, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (cve_id, advisory_id, solution, model, language, ts)
            )
            self.conn.commit()
            return cursor.lastrowid

    def find_by_cve(self, cve_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """查询指定 CVE 的解决方案历史"""
        try:
            rows = self._fetch_all(
                "SELECT id, cve_id, advisory_id, solution, model, created_at "
                "FROM ai_solutions WHERE cve_id = ? "
                "ORDER BY created_at DESC LIMIT ?",
                (cve_id.upper(), limit)
            )
            return [
                {
                    "id": r[0],
                    "cve_id": r[1],
                    "advisory_id": r[2],
                    "solution": r[3],
                    "model": r[4],
                    "created_at": r[5],
                }
                for r in rows
            ]
        except sqlite3.OperationalError:
            return []

    def find_recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        """查询最近的解决方案"""
        try:
            rows = self._fetch_all(
                "SELECT id, cve_id, advisory_id, solution, model, created_at "
                "FROM ai_solutions ORDER BY created_at DESC LIMIT ?",
                (limit,)
            )
            return [
                {
                    "id": r[0],
                    "cve_id": r[1],
                    "advisory_id": r[2],
                    "solution": r[3][:200] + "..." if r[3] and len(r[3]) > 200 else r[3],
                    "model": r[4],
                    "created_at": r[5],
                }
                for r in rows
            ]
        except sqlite3.OperationalError:
            return []

    def count(self) -> int:
        """总记录数"""
        try:
            row = self._fetch_one("SELECT COUNT(*) FROM ai_solutions")
            return row[0] if row else 0
        except sqlite3.OperationalError:
            return 0


# ==================== 统计 Repository ====================

class StatsRepository(BaseRepository):
    """统计分析仓库"""

    def get_overview(self) -> Dict[str, int]:
        """获取概览统计

        Returns:
            包含 cves, dell, kb, ai_solutions, learn_sessions 等数量
        """
        stats = {}

        for table in ['cves', 'dell_advisories', 'dell_kb_articles',
                      'ai_solutions', 'learn_sessions', 'flashcards',
                      'collection_history', 'news_briefs']:
            try:
                row = self._fetch_one(f"SELECT COUNT(*) FROM {table}")
                stats[table] = row[0] if row else 0
            except sqlite3.OperationalError:
                stats[table] = 0

        return stats

    def get_db_size(self) -> int:
        """获取数据库大小（字节）"""
        row = self._fetch_one(
            "SELECT page_count * page_size "
            "FROM pragma_page_count(), pragma_page_size()"
        )
        return row[0] if row else 0

    def get_table_sizes(self) -> List[Tuple[str, int]]:
        """获取每个表的记录数

        Returns:
            [(表名, 记录数), ...] 按记录数降序
        """
        cursor = self._execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '%_fts%'"
        )
        tables = [r[0] for r in cursor.fetchall()]

        results = []
        for table in tables:
            try:
                row = self._fetch_one(f"SELECT COUNT(*) FROM {table}")
                results.append((table, row[0] if row else 0))
            except sqlite3.OperationalError:
                continue

        return sorted(results, key=lambda x: -x[1])
