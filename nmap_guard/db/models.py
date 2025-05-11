"""
SQLAlchemy models for NMAP-Guard.
"""

from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, DateTime, JSON, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .base import Base

class User(Base):
    """User model."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    email = Column(String(100), unique=True, index=True)
    hashed_password = Column(String(100))
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    scan_configs = relationship("ScanConfig", back_populates="owner")
    scans = relationship("Scan", back_populates="owner")

class ScanConfig(Base):
    """Scan configuration model."""
    __tablename__ = "scan_configs"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100))
    description = Column(Text, nullable=True)
    targets = Column(String(1000))  # JSON string of target specifications
    ports = Column(String(100), nullable=True)
    scan_type = Column(String(20))
    timing_template = Column(Integer, default=3)
    service_detection = Column(Boolean, default=True)
    os_detection = Column(Boolean, default=False)
    script_scan = Column(Boolean, default=False)
    schedule = Column(String(100), nullable=True)  # Cron expression
    is_active = Column(Boolean, default=True)
    credentials = Column(JSON, nullable=True)  # Encrypted credentials
    owner_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    owner = relationship("User", back_populates="scan_configs")
    scans = relationship("Scan", back_populates="config")

class Scan(Base):
    """Scan model."""
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    status = Column(String(20))  # pending, running, completed, failed
    start_time = Column(DateTime(timezone=True), nullable=True)
    end_time = Column(DateTime(timezone=True), nullable=True)
    duration = Column(Integer, nullable=True)  # Duration in seconds
    result_summary = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    config_id = Column(Integer, ForeignKey("scan_configs.id"))
    owner_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    config = relationship("ScanConfig", back_populates="scans")
    owner = relationship("User", back_populates="scans")
    hosts = relationship("Host", back_populates="scan")

class Host(Base):
    """Host model for storing scan results."""
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    address = Column(String(100))
    hostname = Column(String(255), nullable=True)
    status = Column(String(20))
    os_match = Column(String(255), nullable=True)
    os_accuracy = Column(Integer, nullable=True)
    ports = Column(JSON)  # List of port information
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    scan = relationship("Scan", back_populates="hosts")

class Report(Base):
    """Report model."""
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    report_type = Column(String(20))
    format = Column(String(10))
    content = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    scan = relationship("Scan") 