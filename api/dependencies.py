"""FastAPI dependency injection."""
from sqlalchemy.orm import Session
from fastapi import Depends, HTTPException, status
from database.connection import DatabaseManager
from database.models import User

def get_db() -> Session:
    """Dependency to get database session."""
    DatabaseManager.init()
    with DatabaseManager.get_session() as session:
        yield session
