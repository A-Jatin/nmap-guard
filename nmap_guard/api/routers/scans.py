"""
Router for scan operations.
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime

from ...db.models import User, ScanConfig, Scan
from ..schemas import ScanCreate, ScanResponse, ScanStatus
from ..dependencies import get_db, get_current_active_user
from ...scanner.core import NmapScanner
from ...utils.exceptions import ScannerError

router = APIRouter()

@router.post("/", response_model=ScanResponse)
async def create_scan(
    scan: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Create a new scan."""
    # Verify scan config exists and user has access
    config = db.query(ScanConfig).filter_by(id=scan.config_id).first()
    if not config:
        raise HTTPException(status_code=404, detail="Scan configuration not found")
    if config.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to use this configuration")
        
    # Create scan record
    db_scan = Scan(
        status=ScanStatus.PENDING,
        config_id=scan.config_id,
        owner_id=current_user.id,
        result_summary={}
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    
    # Schedule scan execution
    background_tasks.add_task(execute_scan, db_scan.id, db)
    
    return db_scan

@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    skip: int = 0,
    limit: int = 100,
    status: Optional[ScanStatus] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List scans."""
    query = db.query(Scan)
    
    # Filter by user unless admin
    if not current_user.is_admin:
        query = query.filter_by(owner_id=current_user.id)
        
    # Filter by status if specified
    if status:
        query = query.filter_by(status=status)
        
    return query.offset(skip).limit(limit).all()

@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get scan details."""
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    # Check access
    if scan.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to access this scan")
        
    return scan

@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Delete a scan."""
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    # Check access
    if scan.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to delete this scan")
        
    # Only allow deletion of completed or failed scans
    if scan.status not in [ScanStatus.COMPLETED, ScanStatus.FAILED]:
        raise HTTPException(status_code=400, detail="Cannot delete scan in progress")
        
    db.delete(scan)
    db.commit()
    return {"message": "Scan deleted"}

async def execute_scan(scan_id: int, db: Session):
    """Execute a scan in the background."""
    try:
        # Get scan and config
        scan = db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            raise ScannerError("Scan not found")
            
        config = db.query(ScanConfig).filter_by(id=scan.config_id).first()
        if not config:
            raise ScannerError("Scan configuration not found")
            
        # Update scan status
        scan.status = ScanStatus.RUNNING
        scan.start_time = datetime.utcnow()
        db.commit()
        
        # Initialize scanner
        scanner = NmapScanner()
        
        # Execute scan
        results = await scanner.scan(
            targets=config.targets,
            ports=config.ports,
            scan_type=config.scan_type,
            timing_template=config.timing_template,
            credentials=config.credentials  # Will be decrypted by scanner
        )
        
        # Update scan with results
        scan.end_time = datetime.utcnow()
        scan.duration = int((scan.end_time - scan.start_time).total_seconds())
        scan.status = ScanStatus.COMPLETED
        scan.result_summary = results.get('summary', {})
        
        # Create host records
        for host_data in results.get('hosts', []):
            host = Host(
                scan_id=scan.id,
                address=host_data['address'],
                hostname=host_data.get('hostname'),
                status=host_data['status'],
                os_match=host_data.get('os_match'),
                os_accuracy=host_data.get('os_accuracy')
            )
            db.add(host)
            
            # Create port records
            for proto, ports in host_data.get('protocols', {}).items():
                for port_data in ports:
                    port = Port(
                        host_id=host.id,
                        port_number=port_data['port'],
                        protocol=proto,
                        state=port_data['state'],
                        service_name=port_data.get('service'),
                        service_product=port_data.get('product'),
                        service_version=port_data.get('version'),
                        service_extra=port_data.get('extrainfo')
                    )
                    db.add(port)
                    
        db.commit()
        
    except Exception as e:
        # Update scan status on failure
        scan.status = ScanStatus.FAILED
        scan.error_message = str(e)
        scan.end_time = datetime.utcnow()
        if scan.start_time:
            scan.duration = int((scan.end_time - scan.start_time).total_seconds())
        db.commit() 