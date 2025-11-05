-- PostgreSQL + pgvector 初始化脚本
-- 用于 CVE 向量搜索功能

-- 创建 pgvector 扩展
CREATE EXTENSION IF NOT EXISTS vector;

-- 创建 CVE 向量表
CREATE TABLE IF NOT EXISTS cve_embeddings (
    id SERIAL PRIMARY KEY,
    cve_id TEXT UNIQUE NOT NULL,
    title TEXT,
    description TEXT,
    embedding vector(768),  -- nomic-embed-text 生成 768 维向量
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 创建索引以加速向量搜索
CREATE INDEX IF NOT EXISTS cve_embeddings_embedding_idx 
ON cve_embeddings 
USING ivfflat (embedding vector_cosine_ops)
WITH (lists = 100);

-- 创建 CVE ID 索引
CREATE INDEX IF NOT EXISTS cve_embeddings_cve_id_idx 
ON cve_embeddings (cve_id);

-- 创建更新时间戳触发器
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_cve_embeddings_updated_at 
BEFORE UPDATE ON cve_embeddings 
FOR EACH ROW 
EXECUTE FUNCTION update_updated_at_column();

-- 授予权限
GRANT ALL PRIVILEGES ON TABLE cve_embeddings TO admin;
GRANT USAGE, SELECT ON SEQUENCE cve_embeddings_id_seq TO admin;
