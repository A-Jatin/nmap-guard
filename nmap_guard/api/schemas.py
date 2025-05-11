"""
Pydantic models for API request/response validation.
"""

from pydantic import BaseModel, EmailStr, Field, validator
from typing import List, Optional, Dict
from datetime import datetime
from enum import Enum

class Token(BaseModel):
    """Token schema."""
    access_token: str
    token_type: str

class TokenData(BaseModel):
    """Token data schema."""
    username: Optional[str] = None

class UserBase(BaseModel):
    """Base user schema."""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    is_active: bool = True

class UserCreate(UserBase):
    """User creation schema."""
    password: str = Field(..., min_length=8)

class UserResponse(UserBase):
    """User response schema."""
    id: int
    is_admin: bool
    created_at: datetime
    
    class Config:
        orm_mode = True

class ScanType(str, Enum):
    """Scan type enumeration."""
    BASIC = "basic"
    STEALTH = "stealth"
    COMPREHENSIVE = "comprehensive"

class ScanStatus(str, Enum):
    """Scan status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class CredentialType(str, Enum):
    """Credential type enumeration."""
    SSH = "ssh"
    WINRM = "winrm"
    SNMP = "snmp"

class ScanConfigBase(BaseModel):
    """Base scan configuration schema."""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str]
    targets: str = Field(..., min_length=1)  # JSON string of target specifications
    ports: Optional[str]  # Port specification
    scan_type: ScanType
    timing_template: int = Field(3, ge=0, le=5)
    service_detection: bool = True
    os_detection: bool = False
    script_scan: bool = False
    schedule: Optional[str]  # Cron expression
    is_active: bool = True

class ScanConfigCreate(ScanConfigBase):
    """Scan configuration creation schema."""
    credentials: Optional[Dict] = None

class ScanConfigResponse(ScanConfigBase):
    """Scan configuration response schema."""
    id: int
    owner_id: int
    created_at: datetime
    updated_at: Optional[datetime]
    
    class Config:
        orm_mode = True

class PortInfo(BaseModel):
    """Port information schema."""
    port_number: int
    protocol: str
    state: str
    service_name: Optional[str]
    service_product: Optional[str]
    service_version: Optional[str]
    service_extra: Optional[str]

class HostInfo(BaseModel):
    """Host information schema."""
    address: str
    hostname: Optional[str]
    status: str
    os_match: Optional[str]
    os_accuracy: Optional[int]
    ports: List[PortInfo]

class VulnerabilityInfo(BaseModel):
    """Vulnerability information schema."""
    cve_id: Optional[str]
    cvss_score: Optional[float]
    title: str
    description: Optional[str]
    solution: Optional[str]
    references: Optional[List[str]]

class ScanCreate(BaseModel):
    """Scan creation schema."""
    config_id: int

class ScanResponse(BaseModel):
    """Scan response schema."""
    id: int
    status: ScanStatus
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    duration: Optional[int]
    result_summary: Optional[Dict]
    error_message: Optional[str]
    config_id: int
    owner_id: int
    created_at: datetime
    hosts: List[HostInfo]
    
    class Config:
        orm_mode = True

class ReportType(str, Enum):
    """Report type enumeration."""
    SUMMARY = "summary"
    DETAILED = "detailed"
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"

class ReportFormat(str, Enum):
    """Report format enumeration."""
    JSON = "json"
    PDF = "pdf"
    CSV = "csv"
    HTML = "html"

class ReportRequest(BaseModel):
    """Report generation request schema."""
    scan_id: int
    report_type: ReportType
    format: ReportFormat
    include_details: bool = True 