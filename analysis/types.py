"""Type definitions for analysis module."""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum
from datetime import datetime

class SeverityLevel(str, Enum):
    """Severity levels for vulnerabilities."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class VulnerabilityType(str, Enum):
    """Types of vulnerabilities."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    AUTH = "authentication"
    LOGIC = "logic_flaw"
    CRYPTO = "cryptographic"
    INPUT_VALIDATION = "input_validation"
    DEPENDENCY = "dependency"
    CONFIG = "configuration"
    OTHER = "other"

@dataclass
class Vulnerability:
    """Represents a single vulnerability."""
    id: str
    type: VulnerabilityType
    severity: SeverityLevel
    title: str
    description: str
    location: str
    proof_of_concept: str
    remediation: str
    cvss_score: Optional[float] = None
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ScanResult:
    """Result of a security scan."""
    scan_id: str
    target: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scan_duration: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    scanner_version: str = "1.0.0"
    status: str = "completed"
    metadata: Dict[str, Any] = field(default_factory=dict)
