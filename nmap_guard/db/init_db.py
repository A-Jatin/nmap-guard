"""
Database initialization script.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base
from ..core.config import settings
from ..utils.logging import get_logger

logger = get_logger(__name__)

def init_db():
    """Initialize the database by creating all tables."""
    try:
        # Create engine
        engine = create_engine(settings.DATABASE_URL)
        
        # Create all tables
        Base.metadata.create_all(bind=engine)
        
        logger.info("Database tables created successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        raise

if __name__ == "__main__":
    init_db() 