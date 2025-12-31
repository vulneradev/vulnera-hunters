"""Database connection and session management."""
from sqlalchemy import create_engine, pool
from sqlalchemy.orm import sessionmaker, Session
from contextlib import contextmanager
from typing import Generator
from core.config import AppConfig
from core.logger import setup_logger
from .models import Base

logger = setup_logger(__name__)

class DatabaseManager:
    """Manages database connection and session lifecycle."""
    
    _engine = None
    _SessionLocal = None
    
    @classmethod
    def init(cls):
        """Initialize database engine and session factory."""
        if cls._engine is None:
            logger.info("Initializing database connection...")
            
            cls._engine = create_engine(
                AppConfig.db.url,
                poolclass=pool.QueuePool,
                pool_size=AppConfig.db.pool_size,
                max_overflow=20,
                pool_pre_ping=True,
                echo=AppConfig.debug,
                connect_args={"timeout": AppConfig.db.timeout}
            )
            
            cls._SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=cls._engine
            )
            
            logger.info("Database initialized successfully")
    
    @classmethod
    def get_engine(self):
        """Get database engine."""
        if self._engine is None:
            self.init()
        return self._engine
    
    @classmethod
    def get_session_factory(cls):
        """Get session factory."""
        if cls._SessionLocal is None:
            cls.init()
        return cls._SessionLocal
    
    @classmethod
    @contextmanager
    def get_session(cls) -> Generator[Session, None, None]:
        """Get database session with context manager."""
        if cls._SessionLocal is None:
            cls.init()
        
        session = cls._SessionLocal()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database error: {str(e)}")
            raise
        finally:
            session.close()

def get_db_session() -> Generator[Session, None, None]:
    """Dependency for FastAPI to get database session."""
    DatabaseManager.init()
    with DatabaseManager.get_session() as session:
        yield session

def init_db():
    """Create database tables."""
    engine = DatabaseManager.get_engine()
    logger.info("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created successfully")
