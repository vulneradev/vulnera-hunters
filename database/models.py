"""SQLAlchemy ORM models."""
from sqlalchemy import Column, String, Integer, Float, DateTime, Text, ForeignKey, Enum, Boolean, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

Base = declarative_base()

class User(Base):
    """User account model."""
    __tablename__ = "users"
    
    id = Column(String(36), primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    api_key = Column(String(255), unique=True, nullable=False, index=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")

class Scan(Base):
    """Vulnerability scan record."""
    __tablename__ = "scans"
    
    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    target = Column(String(255), nullable=False)
    language = Column(String(50), nullable=False)
    status = Column(String(50), default="pending", index=True)
    scan_duration = Column(Float, default=0.0)
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)
    metadata = Column(JSON, default={})
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = relationship("User", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")

class Vulnerability(Base):
    """Detected vulnerability record with remediation tracking."""
    __tablename__ = "vulnerabilities"
    
    id = Column(String(36), primary_key=True)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    type = Column(String(100), nullable=False)
    severity = Column(String(50), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    location = Column(String(500), nullable=False)
    proof_of_concept = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    cvss_score = Column(Float, nullable=True)
    references = Column(JSON, default=[])
    metadata = Column(JSON, default={})
    
    remediation_status = Column(String(50), default="pending", index=True)  # pending, in_progress, fixed, failed
    auto_fix_available = Column(Boolean, default=False)
    auto_fix_code = Column(Text, nullable=True)
    fix_confidence = Column(Float, default=0.0)
    fix_applied = Column(Boolean, default=False)
    applied_at = Column(DateTime, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    scan = relationship("Scan", back_populates="vulnerabilities")
    simulations = relationship("AttackSimulation", back_populates="vulnerability", cascade="all, delete-orphan")
    remediations = relationship("RemediationHistory", back_populates="vulnerability", cascade="all, delete-orphan")

class RemediationHistory(Base):
    """Track remediation attempts and history."""
    __tablename__ = "remediation_history"
    
    id = Column(String(36), primary_key=True)
    vulnerability_id = Column(String(36), ForeignKey("vulnerabilities.id"), nullable=False, index=True)
    status = Column(String(50), nullable=False)  # pending, in_progress, completed, failed
    attempt_number = Column(Integer, default=1)
    fix_code = Column(Text, nullable=True)
    ai_reasoning = Column(Text, nullable=True)
    result_message = Column(Text, nullable=True)
    success = Column(Boolean, default=False)
    applied_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    vulnerability = relationship("Vulnerability", back_populates="remediations")

class AttackSimulation(Base):
    """Attack simulation result."""
    __tablename__ = "attack_simulations"
    
    id = Column(String(36), primary_key=True)
    vulnerability_id = Column(String(36), ForeignKey("vulnerabilities.id"), nullable=False, index=True)
    attack_type = Column(String(100), nullable=False)
    payload = Column(Text, nullable=False)
    success = Column(Boolean, default=False, index=True)
    response = Column(Text, nullable=True)
    impact_score = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    vulnerability = relationship("Vulnerability", back_populates="simulations")

class BatchJob(Base):
    """Batch processing job tracking."""
    __tablename__ = "batch_jobs"
    
    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    job_type = Column(String(100), nullable=False)  # scan, remediate, simulate
    status = Column(String(50), default="queued", index=True)  # queued, processing, completed, failed
    total_items = Column(Integer, default=0)
    processed_items = Column(Integer, default=0)
    failed_items = Column(Integer, default=0)
    payload = Column(JSON, nullable=False)
    result = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
