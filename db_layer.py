"""
数据库访问层（DAO）
将学习相关的数据库操作从 GUI 代码中抽离，提升可维护性

使用示例：
    from db_layer import LearnDAO

    dao = LearnDAO(conn, db_lock)
    dao.save_artifact(session_id, topic, "mindmap", "标题", "内容")
    sessions = dao.search_sessions(keyword="CVE")
"""
import json
import sqlite3
import threading
from datetime import datetime
from typing import List, Dict, Optional, Tuple


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
