-- PostgreSQL + pgvector 向量数据库初始化脚本
-- 用于存储 CVE 向量嵌入，支持语义搜索

-- 启用 pgvector 扩展
CREATE EXTENSION IF NOT EXISTS vector;

-- 创建 CVE 向量表
CREATE TABLE IF NOT EXISTS cve_embeddings (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) UNIQUE NOT NULL,
    title TEXT,
    description TEXT,
    embedding vector(768),  -- 768 维向量（适配多数嵌入模型）
    severity VARCHAR(20),
    cvss_score FLOAT,
    published_date DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 创建向量索引（HNSW 算法，高性能近似最近邻搜索）
CREATE INDEX IF NOT EXISTS cve_embeddings_vector_idx
ON cve_embeddings
USING hnsw (embedding vector_cosine_ops);

-- 创建普通索引
CREATE INDEX IF NOT EXISTS cve_embeddings_cve_id_idx ON cve_embeddings(cve_id);
CREATE INDEX IF NOT EXISTS cve_embeddings_severity_idx ON cve_embeddings(severity);
CREATE INDEX IF NOT EXISTS cve_embeddings_published_date_idx ON cve_embeddings(published_date);

-- 创建 Dell 安全公告向量表
CREATE TABLE IF NOT EXISTS dell_embeddings (
    id SERIAL PRIMARY KEY,
    dsa_id VARCHAR(20) UNIQUE NOT NULL,
    title TEXT,
    description TEXT,
    embedding vector(768),
    severity VARCHAR(20),
    published_date DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 创建向量索引
CREATE INDEX IF NOT EXISTS dell_embeddings_vector_idx
ON dell_embeddings
USING hnsw (embedding vector_cosine_ops);

CREATE INDEX IF NOT EXISTS dell_embeddings_dsa_id_idx ON dell_embeddings(dsa_id);

-- 创建搜索历史表
CREATE TABLE IF NOT EXISTS search_history (
    id SERIAL PRIMARY KEY,
    query_text TEXT NOT NULL,
    query_embedding vector(768),
    results_count INT,
    search_time_ms FLOAT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 创建向量相似度搜索函数
CREATE OR REPLACE FUNCTION search_similar_cves(
    query_embedding vector(768),
    match_threshold FLOAT DEFAULT 0.7,
    match_count INT DEFAULT 10
)
RETURNS TABLE (
    cve_id VARCHAR(20),
    title TEXT,
    description TEXT,
    similarity FLOAT,
    severity VARCHAR(20),
    cvss_score FLOAT,
    published_date DATE
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        ce.cve_id,
        ce.title,
        ce.description,
        1 - (ce.embedding <=> query_embedding) AS similarity,
        ce.severity,
        ce.cvss_score,
        ce.published_date
    FROM cve_embeddings ce
    WHERE 1 - (ce.embedding <=> query_embedding) > match_threshold
    ORDER BY ce.embedding <=> query_embedding
    LIMIT match_count;
END;
$$ LANGUAGE plpgsql;

-- 创建组合搜索函数（向量 + 关键词）
CREATE OR REPLACE FUNCTION hybrid_search_cves(
    query_embedding vector(768),
    query_keywords TEXT,
    match_threshold FLOAT DEFAULT 0.7,
    match_count INT DEFAULT 10
)
RETURNS TABLE (
    cve_id VARCHAR(20),
    title TEXT,
    description TEXT,
    similarity FLOAT,
    severity VARCHAR(20),
    cvss_score FLOAT,
    published_date DATE
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        ce.cve_id,
        ce.title,
        ce.description,
        1 - (ce.embedding <=> query_embedding) AS similarity,
        ce.severity,
        ce.cvss_score,
        ce.published_date
    FROM cve_embeddings ce
    WHERE
        (1 - (ce.embedding <=> query_embedding) > match_threshold)
        AND (
            ce.title ILIKE '%' || query_keywords || '%'
            OR ce.description ILIKE '%' || query_keywords || '%'
        )
    ORDER BY
        (1 - (ce.embedding <=> query_embedding)) DESC,
        ce.cvss_score DESC
    LIMIT match_count;
END;
$$ LANGUAGE plpgsql;

-- 创建更新时间戳触发器
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_cve_embeddings_updated_at
BEFORE UPDATE ON cve_embeddings
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_dell_embeddings_updated_at
BEFORE UPDATE ON dell_embeddings
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- 插入示例数据（用于测试）
INSERT INTO cve_embeddings (cve_id, title, description, embedding, severity, cvss_score, published_date)
VALUES
    ('CVE-EXAMPLE-001', 'Sample SQL Injection Vulnerability', 'A SQL injection vulnerability exists in the login form',
     array_fill(0.0, ARRAY[768])::vector, 'HIGH', 8.5, '2025-01-01'),
    ('CVE-EXAMPLE-002', 'Sample XSS Vulnerability', 'A cross-site scripting vulnerability allows malicious scripts',
     array_fill(0.0, ARRAY[768])::vector, 'MEDIUM', 6.5, '2025-01-02')
ON CONFLICT (cve_id) DO NOTHING;

-- 显示统计信息
SELECT
    'CVE Embeddings' AS table_name,
    COUNT(*) AS total_records,
    COUNT(DISTINCT severity) AS severity_types,
    AVG(cvss_score) AS avg_cvss_score
FROM cve_embeddings
UNION ALL
SELECT
    'Dell Embeddings' AS table_name,
    COUNT(*) AS total_records,
    COUNT(DISTINCT severity) AS severity_types,
    0 AS avg_cvss_score
FROM dell_embeddings;

-- 创建性能视图
CREATE OR REPLACE VIEW cve_statistics AS
SELECT
    severity,
    COUNT(*) AS count,
    AVG(cvss_score) AS avg_score,
    MIN(published_date) AS first_published,
    MAX(published_date) AS last_published
FROM cve_embeddings
GROUP BY severity
ORDER BY avg_score DESC;

COMMENT ON TABLE cve_embeddings IS 'CVE 漏洞向量嵌入表，支持语义搜索';
COMMENT ON TABLE dell_embeddings IS 'Dell 安全公告向量嵌入表';
COMMENT ON FUNCTION search_similar_cves IS '向量相似度搜索函数';
COMMENT ON FUNCTION hybrid_search_cves IS '混合搜索函数（向量+关键词）';
