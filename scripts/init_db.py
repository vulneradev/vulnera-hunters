"""Database initialization script."""
from database.connection import init_db
from core.logger import setup_logger

logger = setup_logger(__name__)

def main():
    """Initialize database."""
    logger.info("Starting database initialization...")
    try:
        init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        raise

if __name__ == "__main__":
    main()
