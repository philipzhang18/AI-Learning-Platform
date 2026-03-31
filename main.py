"""
智能知识管理平台 - 主应用入口
"""
import asyncio
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
import uvicorn
from datetime import datetime
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 模拟配置（实际应从 config 模块导入）
class Settings:
    PROJECT_NAME = "智能知识管理平台"
    VERSION = "1.0.0"
    API_V1_STR = "/api/v1"
    BACKEND_CORS_ORIGINS = ["http://localhost:3000", "http://localhost:8000"]
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"  # 从环境变量读取调试模式

settings = Settings()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    # 启动时执行
    logger.info(f"启动 {settings.PROJECT_NAME} v{settings.VERSION}")

    # 这里可以初始化数据库连接、启动后台任务等
    # await connect_to_mongo()
    # await connect_to_redis()

    yield

    # 关闭时执行
    logger.info("正在关闭应用...")
    # await close_mongo_connection()
    # await close_redis_connection()

# 创建 FastAPI 应用实例
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# 配置 CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 配置可信主机
if settings.DEBUG:
    # In development, allow localhost and example.com domain
    allowed_hosts = ["localhost", "127.0.0.1", "*.example.com", "0.0.0.0"]
else:
    # In production, only allow specific domains (should be configured in settings)
    allowed_hosts = ["localhost", "127.0.0.1", "0.0.0.0"]  # Add your production domains here

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=allowed_hosts
)

# 全局异常处理器
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    全局异常处理器
    在生产环境中隐藏详细错误信息，避免信息泄露
    """
    logger.error(f"全局异常: {exc}", exc_info=True)

    # 根据配置决定是否暴露详细错误
    if settings.DEBUG:
        error_detail = {
            "detail": "服务器内部错误",
            "error": str(exc),
            "type": type(exc).__name__
        }
    else:
        error_detail = {
            "detail": "服务器内部错误",
            "message": "请联系系统管理员"
        }

    return JSONResponse(
        status_code=500,
        content=error_detail
    )

# 根路由
@app.get("/")
async def root():
    """API 根路径"""
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "running",
        "timestamp": datetime.now().isoformat(),
        "docs": "/docs",
        "health": "/health"
    }

# 健康检查
@app.get("/health")
async def health_check():
    """健康检查端点"""
    # 这里可以添加数据库、Redis 等服务的健康检查
    health_status = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "services": {
            "api": "running",
            "database": "connected",  # 实际应检查数据库连接
            "cache": "connected",      # 实际应检查 Redis 连接
        }
    }
    return health_status

# API 路由示例
@app.get(f"{settings.API_V1_STR}/cves/latest")
async def get_latest_cves(limit: int = 10):
    """获取最新的 CVE 列表"""
    # 模拟数据
    mock_cves = []
    for i in range(limit):
        mock_cves.append({
            "cve_id": f"CVE-2024-{12345 + i}",
            "title": f"示例漏洞 {i+1}",
            "severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"][i % 4],
            "published_date": datetime.now().isoformat(),
            "description": f"这是一个模拟的 CVE 描述，用于演示 API 功能。",
            "cvss_score": round(10.0 - (i * 0.5), 1),
            "affected_products": [
                {"vendor": "example", "product": f"product_{i}", "version": "1.0.0"}
            ]
        })

    return {
        "total": limit,
        "data": mock_cves,
        "timestamp": datetime.now().isoformat()
    }

@app.get(f"{settings.API_V1_STR}/stats/summary")
async def get_stats_summary():
    """获取统计摘要"""
    return {
        "total_cves": 15234,
        "critical": 234,
        "high": 1567,
        "medium": 5432,
        "low": 8001,
        "last_update": datetime.now().isoformat(),
        "sources": {
            "NVD": 12000,
            "CNVD": 2000,
            "GitHub": 1234
        },
        "trend": {
            "today": 45,
            "this_week": 312,
            "this_month": 1234
        }
    }

# 搜索 API
@app.get(f"{settings.API_V1_STR}/search")
async def search_cves(
    q: str,
    severity: str = None,
    limit: int = 20
):
    """搜索 CVE"""
    # Input validation and sanitization
    if q:
        # Limit query length to prevent extremely long queries
        if len(q) > 100:
            q = q[:100]
        # Basic sanitization to prevent potential XSS in a real implementation
        import html
        q = html.escape(q)
    
    # Validate and limit the search results
    limit = min(max(limit, 1), 100)  # Limit between 1 and 100 results
    
    # Validate severity parameter
    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", None}
    if severity not in valid_severities:
        severity = None

    results = {
        "query": q,
        "filters": {
            "severity": severity
        },
        "count": 0,
        "results": [],
        "suggestions": ["CVE-2024-12345", "CVE-2024-12346"]
    }

    # 模拟搜索结果
    if q:
        results["count"] = 2
        results["results"] = [
            {
                "cve_id": "CVE-2024-12345",
                "title": f"包含 '{q}' 的漏洞 1",
                "severity": severity or "HIGH",
                "score": 0.95
            },
            {
                "cve_id": "CVE-2024-12346",
                "title": f"包含 '{q}' 的漏洞 2",
                "severity": severity or "MEDIUM",
                "score": 0.85
            }
        ]

    return results

# WebSocket 端点示例（用于实时通知）
from fastapi import WebSocket, WebSocketDisconnect

@app.websocket("/ws/notifications")
async def websocket_notifications(websocket: WebSocket):
    """WebSocket 实时通知"""
    await websocket.accept()
    try:
        while True:
            # 接收客户端消息
            data = await websocket.receive_text()

            # 模拟推送新的 CVE 通知
            await asyncio.sleep(5)  # 每5秒推送一次

            notification = {
                "type": "new_cve",
                "data": {
                    "cve_id": f"CVE-2024-{datetime.now().microsecond}",
                    "severity": "HIGH",
                    "message": "发现新的高危漏洞",
                    "timestamp": datetime.now().isoformat()
                }
            }

            await websocket.send_json(notification)

    except WebSocketDisconnect:
        logger.info("WebSocket 连接断开")

# 导入其他路由（当模块存在时取消注释）
# from app.api.v1 import cve, auth, alerts
# app.include_router(cve.router, prefix=settings.API_V1_STR, tags=["cve"])
# app.include_router(auth.router, prefix=settings.API_V1_STR, tags=["auth"])
# app.include_router(alerts.router, prefix=settings.API_V1_STR, tags=["alerts"])

if __name__ == "__main__":
    # 开发模式运行
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )