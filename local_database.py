"""
CVE 本地数据库管理器
支持数据的保存、加载和离线查询
线程安全的数据库连接管理
"""
import json
import sqlite3
from pathlib import Path
from datetime import datetime
import pickle
import threading
from contextlib import contextmanager
from typing import Optional, List, Dict, Any, Tuple

class CVELocalDatabase:
    """CVE 本地数据库管理器（线程安全）"""

    def __init__(self, db_path="cve_data/cve_database.db"):
        """
        初始化数据库

        Args:
            db_path: 数据库文件路径
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(exist_ok=True)
        self._local = threading.local()  # 线程局部存储
        self.init_database()

    @contextmanager
    def _get_connection(self):
        """
        获取线程安全的数据库连接（上下文管理器）

        Yields:
            sqlite3.Connection: 数据库连接对象
        """
        # 为每个线程创建独立的连接
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
                timeout=10.0
            )
            # 启用 Row 工厂，方便字典访问
            self._local.conn.row_factory = sqlite3.Row

        conn = self._local.conn
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e

    def init_database(self):
        """初始化数据库表结构"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 创建CVE主表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cves (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT UNIQUE NOT NULL,
                    severity TEXT,
                    cvss_score REAL,
                    published_date TEXT,
                    last_modified TEXT,
                    description TEXT,
                    full_description TEXT,
                    solution_brief TEXT,
                    solution_detailed TEXT,
                    source TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # 创建影响产品表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS affected_products (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT,
                    vendor TEXT,
                    product TEXT,
                    version TEXT,
                    FOREIGN KEY (cve_id) REFERENCES cves (cve_id)
                )
            """)

            # 创建引用链接表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cve_references (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT,
                    url TEXT,
                    source TEXT,
                    FOREIGN KEY (cve_id) REFERENCES cves (cve_id)
                )
            """)

            # 创建搜索历史表
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS search_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                search_type TEXT,
                keyword TEXT,
                result_count INTEGER,
                searched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

            # 创建索引以提高查询性能
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_id ON cves (cve_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_severity ON cves (severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cvss_score ON cves (cvss_score)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_published_date ON cves (published_date)")
            # 连接会在上下文管理器退出时自动提交

    def save_cve(self, cve_data: Dict[str, Any], solution_brief: str = "", solution_detailed: str = "") -> bool:
        """
        保存单个CVE数据到数据库

        Args:
            cve_data: CVE数据字典
            solution_brief: 简短解决方案
            solution_detailed: 详细解决方案

        Returns:
            是否保存成功
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                # 检查是否已存在
                cursor.execute("SELECT id FROM cves WHERE cve_id = ?", (cve_data.get("cve_id"),))
                exists = cursor.fetchone()

                if exists:
                    # 更新现有记录
                    cursor.execute("""
                        UPDATE cves SET
                            severity = ?,
                            cvss_score = ?,
                            published_date = ?,
                            last_modified = ?,
                            description = ?,
                            full_description = ?,
                            solution_brief = ?,
                            solution_detailed = ?,
                            source = ?,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE cve_id = ?
                    """, (
                        cve_data.get("severity"),
                        cve_data.get("score"),
                        cve_data.get("published"),
                        cve_data.get("last_modified"),
                        cve_data.get("description"),
                        cve_data.get("full_description", cve_data.get("description")),
                        solution_brief,
                        solution_detailed,
                        cve_data.get("source", "NVD"),
                        cve_data.get("cve_id")
                    ))
                else:
                    # 插入新记录
                    cursor.execute("""
                        INSERT INTO cves (
                            cve_id, severity, cvss_score, published_date,
                            last_modified, description, full_description,
                            solution_brief, solution_detailed, source
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        cve_data.get("cve_id"),
                        cve_data.get("severity"),
                        cve_data.get("score"),
                        cve_data.get("published"),
                        cve_data.get("last_modified"),
                        cve_data.get("description"),
                        cve_data.get("full_description", cve_data.get("description")),
                        solution_brief,
                        solution_detailed,
                        cve_data.get("source", "NVD")
                    ))
                # 连接会在上下文管理器退出时自动提交
            return True

        except Exception as e:
            print(f"保存CVE数据失败: {e}")
            return False

    def save_batch(self, cve_list, solutions=None):
        """
        批量保存CVE数据

        Args:
            cve_list: CVE数据列表
            solutions: 解决方案字典 {cve_id: (brief, detailed)}

        Returns:
            保存成功的数量
        """
        saved_count = 0
        for cve in cve_list:
            cve_id = cve.get("cve_id")
            solution_brief = ""
            solution_detailed = ""

            if solutions and cve_id in solutions:
                solution_brief, solution_detailed = solutions[cve_id]

            if self.save_cve(cve, solution_brief, solution_detailed):
                saved_count += 1

        return saved_count

    def search_offline(
        self,
        search_type: str = "all",
        keyword: str = "",
        severity_filter: Optional[str] = None,
        date_range: Optional[Tuple[str, str]] = None
    ) -> List[Dict[str, Any]]:
        """
        离线搜索CVE数据

        Args:
            search_type: 搜索类型 (all, cve_id, severity, description, solution)
            keyword: 搜索关键字
            severity_filter: 严重等级过滤器
            date_range: 日期范围 (start_date, end_date)

        Returns:
            搜索结果列表
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM cves WHERE 1=1"
            params = []

            # 构建查询条件
            if keyword:
                if search_type == "cve_id":
                    query += " AND cve_id LIKE ?"
                    params.append(f"%{keyword}%")
                elif search_type == "severity":
                    query += " AND severity LIKE ?"
                    params.append(f"%{keyword}%")
                elif search_type == "description":
                    query += " AND (description LIKE ? OR full_description LIKE ?)"
                    params.append(f"%{keyword}%")
                    params.append(f"%{keyword}%")
                elif search_type == "solution":
                    query += " AND (solution_brief LIKE ? OR solution_detailed LIKE ?)"
                    params.append(f"%{keyword}%")
                    params.append(f"%{keyword}%")
                else:  # all
                    query += """ AND (
                        cve_id LIKE ? OR
                        severity LIKE ? OR
                        description LIKE ? OR
                        full_description LIKE ? OR
                        solution_brief LIKE ? OR
                        solution_detailed LIKE ?
                    )"""
                    for _ in range(6):
                        params.append(f"%{keyword}%")

            # 严重等级过滤
            if severity_filter:
                query += " AND severity = ?"
                params.append(severity_filter)

            # 日期范围过滤
            if date_range and len(date_range) == 2:
                start_date, end_date = date_range
                if start_date:
                    query += " AND published_date >= ?"
                    params.append(start_date)
                if end_date:
                    query += " AND published_date <= ?"
                    params.append(end_date)

            # 排序
            query += " ORDER BY published_date DESC, cvss_score DESC"

            cursor.execute(query, params)
            results = cursor.fetchall()

            # 转换为字典列表（使用 Row 工厂更方便）
            cve_list = []
            for row in results:
                cve_dict = dict(row)
                # 格式化以匹配原始数据结构
                cve_dict["score"] = cve_dict.get("cvss_score")
                cve_dict["published"] = cve_dict.get("published_date")
                cve_dict["solution"] = cve_dict.get("solution_brief", "")
                cve_list.append(cve_dict)

        # 记录搜索历史
        self.save_search_history(search_type, keyword, len(cve_list))

        return cve_list

    def get_statistics(self) -> Dict[str, Any]:
        """
        获取数据库统计信息

        Returns:
            统计信息字典
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            stats = {}

            # 总数
            cursor.execute("SELECT COUNT(*) FROM cves")
            stats["total"] = cursor.fetchone()[0]

            # 按严重等级统计
            cursor.execute("""
                SELECT severity, COUNT(*) FROM cves
                GROUP BY severity
            """)
            severity_stats = cursor.fetchall()
            for severity, count in severity_stats:
                if severity:
                    stats[severity.lower()] = count

            # 有解决方案的数量
            cursor.execute("""
                SELECT COUNT(*) FROM cves
                WHERE solution_brief IS NOT NULL AND solution_brief != ''
            """)
            stats["with_solution"] = cursor.fetchone()[0]

            # 最近更新时间
            cursor.execute("SELECT MAX(updated_at) FROM cves")
            last_update = cursor.fetchone()[0]
            stats["last_update"] = last_update if last_update else "从未更新"

            # 数据日期范围
            cursor.execute("""
                SELECT MIN(published_date), MAX(published_date) FROM cves
            """)
            date_range = cursor.fetchone()
            stats["date_range"] = {
                "start": date_range[0] if date_range[0] else "无",
                "end": date_range[1] if date_range[1] else "无"
            }

        return stats

    def save_search_history(self, search_type: str, keyword: str, result_count: int):
        """保存搜索历史"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO search_history (search_type, keyword, result_count)
                    VALUES (?, ?, ?)
                """, (search_type, keyword, result_count))
        except sqlite3.Error:
            # 忽略搜索历史保存失败
            pass

    def get_search_history(self, limit: int = 10) -> List[Tuple]:
        """获取搜索历史"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT search_type, keyword, result_count, searched_at
                FROM search_history
                ORDER BY searched_at DESC
                LIMIT ?
            """, (limit,))
            return cursor.fetchall()

    def export_to_json(self, output_file: str = "cve_export.json") -> int:
        """
        导出数据库到JSON文件

        Args:
            output_file: 输出文件路径

        Returns:
            导出的记录数
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM cves")
            results = cursor.fetchall()

            cve_list = [dict(row) for row in results]

        output_path = Path("cve_data") / output_file
        output_path.parent.mkdir(exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(cve_list, f, ensure_ascii=False, indent=2, default=str)

        return len(cve_list)

    def import_from_json(self, input_file: str) -> int:
        """
        从JSON文件导入数据

        Args:
            input_file: 输入文件路径

        Returns:
            导入的记录数
        """
        input_path = Path(input_file)

        if not input_path.exists():
            return 0

        with open(input_path, "r", encoding="utf-8") as f:
            cve_list = json.load(f)

        imported = 0
        for cve in cve_list:
            if self.save_cve(cve):
                imported += 1

        return imported

    def clear_database(self):
        """清空数据库"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM cves")
            cursor.execute("DELETE FROM affected_products")
            cursor.execute("DELETE FROM cve_references")
            cursor.execute("DELETE FROM search_history")

    def optimize_database(self):
        """优化数据库（压缩和重建索引）"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("VACUUM")
            cursor.execute("ANALYZE")

    def close(self):
        """关闭数据库连接（清理所有线程的连接）"""
        if hasattr(self, '_local') and hasattr(self._local, 'conn') and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    def __del__(self):
        """析构函数，确保关闭数据库连接"""
        self.close()

# 使用示例
if __name__ == "__main__":
    # 创建数据库管理器
    db = CVELocalDatabase()

    # 示例：保存CVE数据
    sample_cve = {
        "cve_id": "CVE-2024-12345",
        "severity": "HIGH",
        "score": 8.5,
        "published": "2024-10-28",
        "description": "Sample SQL injection vulnerability",
        "source": "NVD"
    }

    db.save_cve(sample_cve, "紧急修复", "详细的修复步骤...")

    # 示例：离线搜索
    results = db.search_offline(search_type="severity", keyword="HIGH")
    print(f"找到 {len(results)} 条高危漏洞")

    # 示例：获取统计信息
    stats = db.get_statistics()
    print(f"数据库统计: {stats}")

    db.close()