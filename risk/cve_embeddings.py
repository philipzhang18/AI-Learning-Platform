"""
CVE 文本 Embedding 特征层 (risk/cve_embeddings.py)

用途
----
1. DSA 预测: 用相关 CVE 的平均 embedding 作为 ML 特征（384 维）
2. 相似漏洞推荐: "这个新 CVE 和哪些历史 CVE 相似"
3. 产品风险聚类: embedding 空间中的产品聚类 = 共享风险模式

模型
----
sentence-transformers/all-MiniLM-L6-v2 (22MB, 384维, 快速)
存储: SQLite 新表 cve_embeddings (cve_id TEXT PK, embedding BLOB)

依赖
----
pip install sentence-transformers  (~100MB 模型首次下载)
"""
from __future__ import annotations

import json
import sqlite3
import struct
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np


# ────────────────────────────────────────────────────────────────────────────
# Embedding 序列化
# ────────────────────────────────────────────────────────────────────────────

EMBEDDING_DIM = 384
_STRUCT_FMT = f"<{EMBEDDING_DIM}f"  # little-endian float32 array


def _serialize_embedding(vec: np.ndarray) -> bytes:
    """numpy array → bytes (1536 bytes for 384 floats)"""
    return struct.pack(_STRUCT_FMT, *vec.astype(np.float32))


def _deserialize_embedding(blob: bytes) -> np.ndarray:
    """bytes → numpy array"""
    return np.array(struct.unpack(_STRUCT_FMT, blob), dtype=np.float32)


# ────────────────────────────────────────────────────────────────────────────
# CVE Embedding Store
# ────────────────────────────────────────────────────────────────────────────

class CVEEmbeddingStore:
    """
    CVE 描述文本的语义向量存储与查询。

    用法：
        store = CVEEmbeddingStore("cve_data/cve_database.db")
        store.build_index(batch_size=256)  # 首次，约 20 分钟
        similar = store.find_similar("CVE-2024-1234", top_k=10)
        feature = store.get_product_embedding(["CVE-2024-1234", "CVE-2024-5678"])
    """

    MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._model = None  # lazy load

    def _ensure_table(self) -> None:
        """创建 cve_embeddings 表（若不存在）"""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cve_embeddings (
                    cve_id TEXT PRIMARY KEY,
                    embedding BLOB NOT NULL
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def _load_model(self):
        """懒加载 sentence-transformers 模型"""
        if self._model is not None:
            return self._model
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError:
            raise ImportError(
                "需要安装 sentence-transformers: "
                "pip install sentence-transformers"
            )
        self._model = SentenceTransformer("all-MiniLM-L6-v2")
        return self._model

    def _load_cve_descriptions(self) -> List[Tuple[str, str]]:
        """从 cves 表加载所有 (cve_id, description)"""
        conn = sqlite3.connect(self.db_path)
        try:
            cur = conn.cursor()
            cur.execute("SELECT cve_id, data FROM cves WHERE data IS NOT NULL")
            results = []
            for cve_id, data_str in cur.fetchall():
                try:
                    d = json.loads(data_str)
                    desc = d.get("description", "") or ""
                    if not desc:
                        cve_obj = d.get("cve", d)
                        for item in (cve_obj.get("descriptions") or []):
                            if isinstance(item, dict) and item.get("lang") == "en":
                                desc = item.get("value", "")
                                break
                    if desc and len(desc) > 20:  # 忽略太短的描述
                        results.append((cve_id, desc))
                except (json.JSONDecodeError, TypeError):
                    continue
            return results
        finally:
            conn.close()

    def _get_existing_ids(self) -> set:
        """已编码的 CVE ID 集合"""
        conn = sqlite3.connect(self.db_path)
        try:
            cur = conn.cursor()
            cur.execute("SELECT cve_id FROM cve_embeddings")
            return {row[0] for row in cur.fetchall()}
        except sqlite3.OperationalError:
            return set()
        finally:
            conn.close()

    def build_index(
        self,
        batch_size: int = 256,
        skip_existing: bool = True,
        verbose: bool = True,
    ) -> Dict[str, int]:
        """
        批量编码 CVE 描述，写入 cve_embeddings 表。

        skip_existing=True 时只编码新增的 CVE（增量更新）。
        返回 {"total_cves": N, "encoded": M, "skipped": K, "elapsed_s": T}
        """
        self._ensure_table()
        model = self._load_model()

        # 加载数据
        all_cves = self._load_cve_descriptions()
        if skip_existing:
            existing = self._get_existing_ids()
            to_encode = [(cid, desc) for cid, desc in all_cves if cid not in existing]
        else:
            to_encode = all_cves

        if verbose:
            print(f"  CVE 总数: {len(all_cves)}, 待编码: {len(to_encode)}, "
                  f"已存在: {len(all_cves) - len(to_encode)}")

        if not to_encode:
            return {"total_cves": len(all_cves), "encoded": 0,
                    "skipped": len(all_cves), "elapsed_s": 0.0}

        t0 = time.time()
        conn = sqlite3.connect(self.db_path)
        try:
            encoded = 0
            for i in range(0, len(to_encode), batch_size):
                batch = to_encode[i:i + batch_size]
                texts = [desc for _, desc in batch]
                ids = [cid for cid, _ in batch]

                embeddings = model.encode(texts, batch_size=batch_size,
                                          show_progress_bar=False, normalize_embeddings=True)

                rows = [(cid, _serialize_embedding(emb))
                        for cid, emb in zip(ids, embeddings)]
                conn.executemany(
                    "INSERT OR REPLACE INTO cve_embeddings (cve_id, embedding) VALUES (?, ?)",
                    rows
                )
                conn.commit()
                encoded += len(batch)
                if verbose and (i // batch_size) % 10 == 0:
                    elapsed = time.time() - t0
                    rate = encoded / elapsed if elapsed > 0 else 0
                    print(f"    [{encoded}/{len(to_encode)}] {rate:.0f} CVEs/s")
        finally:
            conn.close()

        elapsed = time.time() - t0
        if verbose:
            print(f"  完成: {encoded} CVEs in {elapsed:.1f}s ({encoded/elapsed:.0f}/s)")
        return {"total_cves": len(all_cves), "encoded": encoded,
                "skipped": len(all_cves) - len(to_encode), "elapsed_s": round(elapsed, 1)}

    # ── 查询接口 ──────────────────────────────────────────────────────────

    def get_embedding(self, cve_id: str) -> Optional[np.ndarray]:
        """获取单个 CVE 的 embedding"""
        conn = sqlite3.connect(self.db_path)
        try:
            cur = conn.cursor()
            cur.execute("SELECT embedding FROM cve_embeddings WHERE cve_id = ?", (cve_id,))
            row = cur.fetchone()
            if row:
                return _deserialize_embedding(row[0])
            return None
        finally:
            conn.close()

    def get_product_embedding(self, cve_ids: List[str]) -> Optional[np.ndarray]:
        """
        获取一组 CVE 的平均 embedding（384 维），作为 ML 模型输入特征。

        用于：某产品关联的 CVE 集合 → 聚合为产品级语义向量。
        """
        if not cve_ids:
            return None
        conn = sqlite3.connect(self.db_path)
        try:
            placeholders = ",".join(["?"] * len(cve_ids))
            cur = conn.cursor()
            cur.execute(
                f"SELECT embedding FROM cve_embeddings WHERE cve_id IN ({placeholders})",
                cve_ids,
            )
            embeddings = [_deserialize_embedding(row[0]) for row in cur.fetchall()]
            if not embeddings:
                return None
            return np.mean(embeddings, axis=0)
        finally:
            conn.close()

    def find_similar(
        self,
        cve_id: str,
        top_k: int = 10,
        min_score: float = 0.5,
    ) -> List[Tuple[str, float]]:
        """
        余弦相似度查找与给定 CVE 最相似的 CVE。

        注：当前实现是全表线性扫描（124K embeddings × 384d）。
        对 384 维 float32，一次扫描约 0.5s，足够日常交互使用。
        如需亚秒级 (<50ms)，未来可加 FAISS/Annoy 索引。
        """
        query_vec = self.get_embedding(cve_id)
        if query_vec is None:
            return []

        conn = sqlite3.connect(self.db_path)
        try:
            cur = conn.cursor()
            cur.execute("SELECT cve_id, embedding FROM cve_embeddings")
            results: List[Tuple[str, float]] = []
            for row_id, blob in cur.fetchall():
                if row_id == cve_id:
                    continue
                vec = _deserialize_embedding(blob)
                # 归一化后余弦相似度 = 点积
                score = float(np.dot(query_vec, vec))
                if score >= min_score:
                    results.append((row_id, round(score, 4)))
            results.sort(key=lambda x: -x[1])
            return results[:top_k]
        finally:
            conn.close()

    def embedding_count(self) -> int:
        """已编码的 CVE 数量"""
        conn = sqlite3.connect(self.db_path)
        try:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM cve_embeddings")
            return cur.fetchone()[0]
        except sqlite3.OperationalError:
            return 0
        finally:
            conn.close()


# ────────────────────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────────────────────

def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="CVE Embedding 索引构建与查询")
    parser.add_argument("--db", default="cve_data/cve_database.db")
    sub = parser.add_subparsers(dest="cmd")

    build_p = sub.add_parser("build", help="构建/更新 embedding 索引")
    build_p.add_argument("--batch-size", type=int, default=256)
    build_p.add_argument("--full", action="store_true", help="全量重建（不跳过已有）")

    sim_p = sub.add_parser("similar", help="查找相似 CVE")
    sim_p.add_argument("cve_id", help="查询 CVE ID")
    sim_p.add_argument("--top-k", type=int, default=10)

    sub.add_parser("status", help="显示索引状态")

    args = parser.parse_args()
    store = CVEEmbeddingStore(args.db)

    if args.cmd == "build":
        result = store.build_index(
            batch_size=args.batch_size,
            skip_existing=not args.full,
        )
        print(f"  结果: {result}")
    elif args.cmd == "similar":
        results = store.find_similar(args.cve_id, top_k=args.top_k)
        if not results:
            print(f"  未找到 {args.cve_id} 的 embedding 或无相似结果")
        else:
            print(f"  与 {args.cve_id} 最相似的 CVE:")
            for cid, score in results:
                print(f"    {cid:20s} similarity={score:.4f}")
    elif args.cmd == "status":
        count = store.embedding_count()
        print(f"  已编码 CVE 数: {count}")
    else:
        parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
