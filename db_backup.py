"""
数据库备份模块
提供 SQLite 数据库的一键备份与恢复功能

使用示例：
    from db_backup import backup_database, restore_database, list_backups

    backup_path = backup_database()
    backups = list_backups()
    restore_database("backup_20260426_120000.db")
"""
import shutil
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional


def get_backup_dir() -> Path:
    """获取备份目录，不存在则自动创建"""
    backup_dir = Path("cve_data/backups")
    backup_dir.mkdir(parents=True, exist_ok=True)
    return backup_dir


def backup_database(db_path: str = "cve_data/cve_database.db",
                    note: str = "") -> Optional[str]:
    """备份数据库

    Args:
        db_path: 数据库文件路径
        note: 备份备注（追加到文件名）

    Returns:
        备份文件路径，失败返回 None
    """
    db_file = Path(db_path)
    if not db_file.exists():
        return None

    backup_dir = get_backup_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    note_suffix = f"_{note}" if note else ""
    backup_name = f"cve_database_{timestamp}{note_suffix}.db"
    backup_path = backup_dir / backup_name

    try:
        # 使用 SQLite 自带的备份 API（线上备份，安全）
        src_conn = sqlite3.connect(str(db_file))
        dst_conn = sqlite3.connect(str(backup_path))
        with dst_conn:
            src_conn.backup(dst_conn)
        src_conn.close()
        dst_conn.close()
        return str(backup_path)
    except Exception:
        # 退化到文件复制
        try:
            shutil.copy2(db_file, backup_path)
            return str(backup_path)
        except Exception:
            return None


def list_backups() -> List[Dict[str, any]]:
    """列出所有备份文件

    Returns:
        [{"name": ..., "path": ..., "size_mb": ..., "created_at": ...}, ...]
    """
    backup_dir = get_backup_dir()
    if not backup_dir.exists():
        return []

    backups = []
    for f in sorted(backup_dir.glob("cve_database_*.db"), reverse=True):
        try:
            stat = f.stat()
            backups.append({
                "name": f.name,
                "path": str(f),
                "size_mb": round(stat.st_size / 1024 / 1024, 2),
                "created_at": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            })
        except Exception:
            continue
    return backups


def restore_database(backup_name: str,
                     db_path: str = "cve_data/cve_database.db") -> bool:
    """从备份恢复数据库

    Args:
        backup_name: 备份文件名（仅文件名，不含路径）
        db_path: 目标数据库路径

    Returns:
        恢复成功返回 True
    """
    backup_dir = get_backup_dir()
    backup_path = backup_dir / backup_name

    if not backup_path.exists():
        return False

    db_file = Path(db_path)
    # 先把当前库备份一份（防止误操作）
    if db_file.exists():
        safety_backup = db_file.parent / f"{db_file.stem}_before_restore_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        try:
            shutil.copy2(db_file, safety_backup)
        except Exception:
            pass

    try:
        shutil.copy2(backup_path, db_file)
        return True
    except Exception:
        return False


def cleanup_old_backups(keep_count: int = 10) -> int:
    """清理过旧的备份文件，仅保留最近 N 个

    Args:
        keep_count: 保留的备份数量

    Returns:
        删除的备份数量
    """
    backups = list_backups()
    if len(backups) <= keep_count:
        return 0

    deleted = 0
    for backup in backups[keep_count:]:
        try:
            Path(backup["path"]).unlink()
            deleted += 1
        except Exception:
            continue
    return deleted
