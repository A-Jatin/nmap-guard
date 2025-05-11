"""
Router for scan configuration management.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime

from ...db.models import User, ScanConfig
from ..schemas import ScanConfigCreate, ScanConfigResponse
from ..dependencies import get_db, get_current_active_user, get_admin_user
from ...utils.encryption import encrypt_credentials
from ...utils.validators import validate_targets, validate_ports, validate_credentials

router = APIRouter()

@router.post("/", response_model=ScanConfigResponse)
async def create_scan_config(
    config: ScanConfigCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Create a new scan configuration."""
    # Validate targets and ports
    if not validate_targets(config.targets):
        raise HTTPException(status_code=400, detail="Invalid target specification")
    if config.ports and not validate_ports(config.ports):
        raise HTTPException(status_code=400, detail="Invalid port specification")
        
    # Validate and encrypt credentials if provided
    if config.credentials:
        if not validate_credentials(config.credentials):
            raise HTTPException(status_code=400, detail="Invalid credentials format")
        encrypted_creds = encrypt_credentials(config.credentials)
    else:
        encrypted_creds = None
        
    # Create config
    db_config = ScanConfig(
        name=config.name,
        description=config.description,
        targets=config.targets,
        ports=config.ports,
        scan_type=config.scan_type,
        timing_template=config.timing_template,
        service_detection=config.service_detection,
        os_detection=config.os_detection,
        script_scan=config.script_scan,
        credentials=encrypted_creds,
        schedule=config.schedule,
        is_active=config.is_active,
        owner_id=current_user.id
    )
    
    db.add(db_config)
    db.commit()
    db.refresh(db_config)
    
    return db_config

@router.get("/", response_model=List[ScanConfigResponse])
async def list_scan_configs(
    skip: int = 0,
    limit: int = 100,
    active_only: bool = True,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List scan configurations."""
    query = db.query(ScanConfig)
    
    # Filter by user unless admin
    if not current_user.is_admin:
        query = query.filter_by(owner_id=current_user.id)
        
    # Filter active configs if requested
    if active_only:
        query = query.filter_by(is_active=True)
        
    return query.offset(skip).limit(limit).all()

@router.get("/{config_id}", response_model=ScanConfigResponse)
async def get_scan_config(
    config_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get scan configuration details."""
    config = db.query(ScanConfig).filter_by(id=config_id).first()
    if not config:
        raise HTTPException(status_code=404, detail="Configuration not found")
        
    # Check access
    if config.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to access this configuration")
        
    return config

@router.put("/{config_id}", response_model=ScanConfigResponse)
async def update_scan_config(
    config_id: int,
    config_update: ScanConfigCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Update a scan configuration."""
    db_config = db.query(ScanConfig).filter_by(id=config_id).first()
    if not db_config:
        raise HTTPException(status_code=404, detail="Configuration not found")
        
    # Check access
    if db_config.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to modify this configuration")
        
    # Validate targets and ports
    if not validate_targets(config_update.targets):
        raise HTTPException(status_code=400, detail="Invalid target specification")
    if config_update.ports and not validate_ports(config_update.ports):
        raise HTTPException(status_code=400, detail="Invalid port specification")
        
    # Handle credentials update
    if config_update.credentials:
        if not validate_credentials(config_update.credentials):
            raise HTTPException(status_code=400, detail="Invalid credentials format")
        encrypted_creds = encrypt_credentials(config_update.credentials)
    else:
        encrypted_creds = db_config.credentials  # Keep existing credentials
        
    # Update fields
    for field, value in config_update.dict(exclude={'credentials'}).items():
        setattr(db_config, field, value)
    db_config.credentials = encrypted_creds
    db_config.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(db_config)
    
    return db_config

@router.delete("/{config_id}")
async def delete_scan_config(
    config_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Delete a scan configuration."""
    config = db.query(ScanConfig).filter_by(id=config_id).first()
    if not config:
        raise HTTPException(status_code=404, detail="Configuration not found")
        
    # Check access
    if config.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to delete this configuration")
        
    # Check if configuration has associated scans
    if config.scans:
        # Soft delete by deactivating
        config.is_active = False
        db.commit()
        return {"message": "Configuration deactivated"}
    else:
        # Hard delete if no associated scans
        db.delete(config)
        db.commit()
        return {"message": "Configuration deleted"} 