"""
Dependencies for FastAPI application.
"""

import os
from datetime import datetime, timedelta
from typing import Optional, List, Generator
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from passlib.context import CryptContext

from ..db.models import User, ScanConfig, Scan, Host, Report
from .schemas import TokenData
from ..utils.exceptions import AuthenticationError, AuthorizationError
from ..utils.auth import get_password_hash, verify_password
from ..db.session import SessionLocal
from ..core.config import settings
from ..core.security import verify_password, get_password_hash
from ..core.scanner import Scanner
from ..core.report_generator import ReportGenerator
from ..utils.encryption import encrypt_data, decrypt_data
from ..utils.logging import get_logger
from . import schemas

# Security configuration
SECRET_KEY = os.getenv("API_SECRET_KEY", "change_me_in_production")
ALGORITHM = os.getenv("API_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("API_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_db():
    """Database session dependency."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from ..db.init import get_database_url
    
    engine = create_engine(get_database_url())
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a hash."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Get password hash."""
    return pwd_context.hash(password)

def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    """Authenticate a user."""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    """Get current user from token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
        
    user = db.query(User).filter(User.username == token_data.username).first()
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current active user."""
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def check_admin_permission(user: User):
    """Check if user has admin permissions."""
    if not user.is_admin:
        raise AuthorizationError("Admin privileges required")

def get_admin_user(current_user: User = Depends(get_current_active_user)):
    """Get current admin user."""
    check_admin_permission(current_user)
    return current_user

def get_user(db: Session, user_id: int) -> Optional[User]:
    """Get user by ID."""
    return db.query(User).filter(User.id == user_id).first()

def get_user_by_email(db: Session, email: str) -> Optional[User]:
    """Get user by email."""
    return db.query(User).filter(User.email == email).first()

def get_user_by_username(db: Session, username: str) -> Optional[User]:
    """Get user by username."""
    return db.query(User).filter(User.username == username).first()

def get_users(db: Session, skip: int = 0, limit: int = 100) -> List[User]:
    """Get list of users."""
    return db.query(User).offset(skip).limit(limit).all()

def create_user(db: Session, user: schemas.UserCreate) -> User:
    """Create new user."""
    hashed_password = get_password_hash(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        is_active=user.is_active
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def get_scan_config(db: Session, config_id: int) -> Optional[ScanConfig]:
    """Get scan configuration by ID."""
    return db.query(ScanConfig).filter(ScanConfig.id == config_id).first()

def get_user_scan_configs(
    db: Session,
    user_id: int,
    skip: int = 0,
    limit: int = 100
) -> List[ScanConfig]:
    """Get list of scan configurations for a user."""
    return db.query(ScanConfig)\
        .filter(ScanConfig.owner_id == user_id)\
        .offset(skip)\
        .limit(limit)\
        .all()

def create_scan_config(
    db: Session,
    config: schemas.ScanConfigCreate,
    owner_id: int
) -> ScanConfig:
    """Create new scan configuration."""
    db_config = ScanConfig(
        **config.dict(exclude={'credentials'}),
        owner_id=owner_id
    )
    db.add(db_config)
    db.commit()
    db.refresh(db_config)
    return db_config

def get_scan(db: Session, scan_id: int) -> Optional[Scan]:
    """Get scan by ID."""
    return db.query(Scan).filter(Scan.id == scan_id).first()

def get_user_scans(
    db: Session,
    user_id: int,
    skip: int = 0,
    limit: int = 100
) -> List[Scan]:
    """Get list of scans for a user."""
    return db.query(Scan)\
        .filter(Scan.owner_id == user_id)\
        .offset(skip)\
        .limit(limit)\
        .all()

def create_scan(
    db: Session,
    config_id: int,
    owner_id: int
) -> Scan:
    """Create new scan."""
    db_scan = Scan(
        status="pending",
        config_id=config_id,
        owner_id=owner_id
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    return db_scan

def update_scan_results(
    db: Session,
    scan_id: int,
    results: dict
) -> Scan:
    """Update scan with results."""
    db_scan = get_scan(db, scan_id)
    if not db_scan:
        return None
    
    # Update scan status and timing
    db_scan.status = "completed"
    db_scan.end_time = datetime.utcnow()
    if db_scan.start_time:
        db_scan.duration = int((db_scan.end_time - db_scan.start_time).total_seconds())
    
    # Update result summary
    db_scan.result_summary = results.get('summary', {})
    
    # Create host records
    for host_data in results.get('hosts', []):
        db_host = Host(
            scan_id=scan_id,
            address=host_data['address'],
            hostname=host_data.get('hostnames', [{}])[0].get('name'),
            status=host_data['status'],
            ports=host_data.get('protocols', {})
        )
        db.add(db_host)
    
    db.commit()
    db.refresh(db_scan)
    return db_scan

def update_scan_error(
    db: Session,
    scan_id: int,
    error: str
) -> Scan:
    """Update scan with error."""
    db_scan = get_scan(db, scan_id)
    if not db_scan:
        return None
    
    db_scan.status = "failed"
    db_scan.error_message = error
    db_scan.end_time = datetime.utcnow()
    
    db.commit()
    db.refresh(db_scan)
    return db_scan

def generate_report(
    db: Session,
    scan_id: int,
    report_type: str,
    format: str,
    include_details: bool = True
) -> dict:
    """Generate report for a scan."""
    scan = get_scan(db, scan_id)
    if not scan:
        return None
    
    # Get scan data
    hosts = db.query(Host).filter(Host.scan_id == scan_id).all()
    
    # Generate report content based on type
    if report_type == "summary":
        content = {
            "scan_id": scan_id,
            "status": scan.status,
            "start_time": scan.start_time.isoformat() if scan.start_time else None,
            "end_time": scan.end_time.isoformat() if scan.end_time else None,
            "duration": scan.duration,
            "summary": scan.result_summary
        }
    elif report_type == "detailed":
        content = {
            "scan_id": scan_id,
            "status": scan.status,
            "start_time": scan.start_time.isoformat() if scan.start_time else None,
            "end_time": scan.end_time.isoformat() if scan.end_time else None,
            "duration": scan.duration,
            "summary": scan.result_summary,
            "hosts": [
                {
                    "address": host.address,
                    "hostname": host.hostname,
                    "status": host.status,
                    "os_match": host.os_match,
                    "os_accuracy": host.os_accuracy,
                    "ports": host.ports
                }
                for host in hosts
            ]
        }
    else:
        content = {"error": "Invalid report type"}
    
    # Create report record
    db_report = Report(
        scan_id=scan_id,
        report_type=report_type,
        format=format,
        content=content
    )
    db.add(db_report)
    db.commit()
    
    return content 