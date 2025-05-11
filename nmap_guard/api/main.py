"""
Main FastAPI application module for NMAP-Guard.
"""

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta
import logging

from . import schemas, dependencies
from ..scanner.core import NmapScanner
from ..db.session import get_db
from ..utils.auth import (
    create_access_token,
    get_current_user,
    get_password_hash,
    verify_password
)
from ..utils.exceptions import ScanError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="NMAP-Guard API",
    description="Enterprise-grade network scanning and vulnerability assessment system",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Initialize scanner
scanner = NmapScanner()

@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """Authenticate user and return access token."""
    user = dependencies.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/users/", response_model=schemas.UserResponse)
async def create_user(
    user: schemas.UserCreate,
    db: Session = Depends(get_db)
):
    """Create a new user."""
    db_user = dependencies.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    return dependencies.create_user(db=db, user=user)

@app.get("/users/me/", response_model=schemas.UserResponse)
async def read_users_me(
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    """Get current user information."""
    return current_user

@app.post("/scans/configs/", response_model=schemas.ScanConfigResponse)
async def create_scan_config(
    config: schemas.ScanConfigCreate,
    current_user: schemas.UserResponse = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new scan configuration."""
    return dependencies.create_scan_config(db=db, config=config, owner_id=current_user.id)

@app.get("/scans/configs/", response_model=List[schemas.ScanConfigResponse])
async def list_scan_configs(
    skip: int = 0,
    limit: int = 100,
    current_user: schemas.UserResponse = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all scan configurations for the current user."""
    return dependencies.get_user_scan_configs(db=db, user_id=current_user.id, skip=skip, limit=limit)

@app.post("/scans/", response_model=schemas.ScanResponse)
async def create_scan(
    scan: schemas.ScanCreate,
    current_user: schemas.UserResponse = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create and start a new scan."""
    config = dependencies.get_scan_config(db=db, config_id=scan.config_id)
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan configuration not found"
        )
    if config.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to use this scan configuration"
        )
    
    try:
        # Create scan record
        db_scan = dependencies.create_scan(db=db, config_id=scan.config_id, owner_id=current_user.id)
        
        # Execute scan asynchronously
        scan_result = await scanner.scan(
            targets=config.targets,
            ports=config.ports,
            scan_type=config.scan_type,
            timing_template=config.timing_template,
            credentials=config.credentials
        )
        
        # Update scan record with results
        dependencies.update_scan_results(
            db=db,
            scan_id=db_scan.id,
            results=scan_result
        )
        
        return db_scan
    except ScanError as e:
        dependencies.update_scan_error(db=db, scan_id=db_scan.id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@app.get("/scans/", response_model=List[schemas.ScanResponse])
async def list_scans(
    skip: int = 0,
    limit: int = 100,
    current_user: schemas.UserResponse = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all scans for the current user."""
    return dependencies.get_user_scans(db=db, user_id=current_user.id, skip=skip, limit=limit)

@app.get("/scans/{scan_id}", response_model=schemas.ScanResponse)
async def get_scan(
    scan_id: int,
    current_user: schemas.UserResponse = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get detailed information about a specific scan."""
    scan = dependencies.get_scan(db=db, scan_id=scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    if scan.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this scan"
        )
    return scan

@app.post("/reports/", response_model=dict)
async def generate_report(
    report_request: schemas.ReportRequest,
    current_user: schemas.UserResponse = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Generate a report for a specific scan."""
    scan = dependencies.get_scan(db=db, scan_id=report_request.scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    if scan.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this scan"
        )
    
    try:
        report = dependencies.generate_report(
            db=db,
            scan_id=report_request.scan_id,
            report_type=report_request.report_type,
            format=report_request.format,
            include_details=report_request.include_details
        )
        return report
    except Exception as e:
        logger.error(f"Failed to generate report: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate report"
        )

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()} 