// MongoDB 初始化脚本
// 此脚本在MongoDB容器首次启动时自动执行

// 切换到cve_database数据库
db = db.getSiblingDB('cve_database');

print('='.repeat(60));
print('初始化CVE数据库...');
print('='.repeat(60));

// 创建应用用户
db.createUser({
  user: 'cve_app',
  pwd: 'cve_app_password',
  roles: [
    {
      role: 'readWrite',
      db: 'cve_database'
    }
  ]
});

print('✓ 创建应用用户: cve_app');

// 创建Collections
db.createCollection('cve_collection');
db.createCollection('dell_collection');
db.createCollection('collection_history');

print('✓ 创建Collections: cve_collection, dell_collection, collection_history');

// ==================== CVE Collection 索引 ====================

print('创建CVE Collection索引...');

// 唯一索引 - CVE ID
db.cve_collection.createIndex(
  {"cve_id": 1},
  {unique: true, name: "idx_cve_id"}
);
print('  ✓ idx_cve_id (唯一索引)');

// 复合索引 - 发布日期 + 严重程度（优化分页查询）
db.cve_collection.createIndex(
  {"published_date": -1, "cvss_severity": 1},
  {name: "idx_published_severity"}
);
print('  ✓ idx_published_severity (复合索引)');

// 单字段索引 - 严重程度
db.cve_collection.createIndex(
  {"cvss_severity": 1},
  {name: "idx_severity"}
);
print('  ✓ idx_severity');

// 单字段索引 - 采集日期
db.cve_collection.createIndex(
  {"collected_date": -1},
  {name: "idx_collected"}
);
print('  ✓ idx_collected');

// 全文索引 - 描述和CVE ID
db.cve_collection.createIndex(
  {"description": "text", "cve_id": "text"},
  {name: "idx_fulltext"}
);
print('  ✓ idx_fulltext (全文索引)');

// ==================== Dell Collection 索引 ====================

print('创建Dell Collection索引...');

// 唯一索引 - DSA ID
db.dell_collection.createIndex(
  {"dsa_id": 1},
  {unique: true, name: "idx_dsa_id"}
);
print('  ✓ idx_dsa_id (唯一索引)');

// 数组索引 - CVE IDs（支持关联查询）
db.dell_collection.createIndex(
  {"cve_ids": 1},
  {name: "idx_cve_ids"}
);
print('  ✓ idx_cve_ids (数组索引)');

// 单字段索引 - 发布日期
db.dell_collection.createIndex(
  {"published_date": -1},
  {name: "idx_published"}
);
print('  ✓ idx_published');

// 单字段索引 - 采集日期
db.dell_collection.createIndex(
  {"collected_date": -1},
  {name: "idx_collected"}
);
print('  ✓ idx_collected');

// 全文索引 - 标题和摘要
db.dell_collection.createIndex(
  {"title": "text", "summary": "text"},
  {name: "idx_fulltext"}
);
print('  ✓ idx_fulltext (全文索引)');

// ==================== Collection History 索引 ====================

print('创建Collection History索引...');

// 单字段索引 - 开始时间
db.collection_history.createIndex(
  {"start_time": -1},
  {name: "idx_start_time"}
);
print('  ✓ idx_start_time');

// 复合索引 - 类型 + 开始时间
db.collection_history.createIndex(
  {"type": 1, "start_time": -1},
  {name: "idx_type_time"}
);
print('  ✓ idx_type_time (复合索引)');

// ==================== 完成 ====================

print('='.repeat(60));
print('✓ MongoDB初始化完成!');
print('='.repeat(60));

// 显示数据库信息
print('\n数据库信息:');
print('  数据库名: cve_database');
print('  应用用户: cve_app');
print('  Collections:');
print('    - cve_collection (CVE数据)');
print('    - dell_collection (Dell安全公告)');
print('    - collection_history (采集历史)');

print('\n索引统计:');
print('  cve_collection: ' + db.cve_collection.getIndexes().length + '个索引');
print('  dell_collection: ' + db.dell_collection.getIndexes().length + '个索引');
print('  collection_history: ' + db.collection_history.getIndexes().length + '个索引');

print('\n连接信息:');
print('  MongoDB URL: mongodb://cve_app:cve_app_password@localhost:27017/cve_database');
print('  Mongo Express: http://localhost:8081');
print('  Redis Commander: http://localhost:8082');

print('\n' + '='.repeat(60));
