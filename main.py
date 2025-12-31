"""Main application entry point."""
import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from core.logger import setup_logger
from core.config import AppConfig
from database.connection import DatabaseManager, init_db
from cache.redis_cache import CacheManager
from api.routes import router

logger = setup_logger(__name__)

def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    app = FastAPI(
        title="VulneraAI Backend",
        description="AI-powered vulnerability analysis and reporting engine",
        version="1.0.0",
    )
    
    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Include routes
    app.include_router(router)
    
    @app.on_event("startup")
    async def startup():
        logger.info("VulneraAI Backend starting up...")
        logger.info(f"Environment: {'DEBUG' if AppConfig.debug else 'PRODUCTION'}")
        
        DatabaseManager.init()
        init_db()
        CacheManager.get_client()
    
    @app.on_event("shutdown")
    async def shutdown():
        logger.info("VulneraAI Backend shutting down...")
    
    return app

app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=AppConfig.debug)
