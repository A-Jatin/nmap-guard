"""
Configuration settings for the application.
"""

import os
from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./nmap_guard.db")
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "change_me_in_production")
    API_SECRET_KEY: str = os.getenv("API_SECRET_KEY", "change_me_in_production")
    API_ALGORITHM: str = os.getenv("API_ALGORITHM", "HS256")
    API_ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("API_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    
    # Encryption
    ENCRYPTION_KEY: str = os.getenv("ENCRYPTION_KEY", "change_me_in_production")
    ENCRYPTION_SALT: str = os.getenv("ENCRYPTION_SALT", "change_me_in_production")
    
    # CORS
    CORS_ORIGINS: List[str] = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:8000").split(",")
    
    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    
    # Scanner
    MAX_CONCURRENT_SCANS: int = int(os.getenv("MAX_CONCURRENT_SCANS", "5"))
    DEFAULT_SCAN_TIMEOUT: int = int(os.getenv("DEFAULT_SCAN_TIMEOUT", "3600"))
    SCAN_RATE_LIMIT: int = int(os.getenv("SCAN_RATE_LIMIT", "10"))
    
    # Report
    MAX_REPORTS: int = int(os.getenv("MAX_REPORTS", "1000"))
    REPORT_RETENTION_DAYS: int = int(os.getenv("REPORT_RETENTION_DAYS", "90"))
    
    # Admin
    ADMIN_USERNAME: str = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_EMAIL: str = os.getenv("ADMIN_EMAIL", "admin@example.com")
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "change-me-in-production")

    class Config:
        case_sensitive = True

settings = Settings() 