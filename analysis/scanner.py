"""Core security scanner module."""
import re
import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import hashlib
from core.logger import setup_logger
from .types import Vulnerability, VulnerabilityType, SeverityLevel

logger = setup_logger(__name__)

@dataclass
class ScanConfig:
    """Configuration for security scans."""
    check_sql_injection: bool = True
    check_xss: bool = True
    check_dependencies: bool = True
    check_authentication: bool = True
    check_crypto: bool = True
    enable_ai_analysis: bool = True

class SecurityScanner:
    """Performs static and dynamic security analysis."""
    
    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()
        self.vulnerabilities: List[Vulnerability] = []
        logger.info("SecurityScanner initialized")
    
    def scan_code(self, code: str, language: str = "python") -> List[Vulnerability]:
        """Scan code for common vulnerabilities."""
        self.vulnerabilities = []
        
        if self.config.check_sql_injection:
            self._check_sql_injection(code)
        if self.config.check_xss:
            self._check_xss(code)
        if self.config.check_authentication:
            self._check_auth_issues(code)
        if self.config.check_crypto:
            self._check_crypto_issues(code)
        
        logger.info(f"Found {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities
    
    def _check_sql_injection(self, code: str) -> None:
        """Detect SQL injection vulnerabilities."""
        # Pattern for direct SQL concatenation
        patterns = [
            r'query\s*=\s*["\'].*\$',
            r'execute\s*\(\s*f["\'].*\{',
            r'sql\s*=\s*["\'].*[\+\s].*["\']',
        ]
        
        for i, line in enumerate(code.split('\n'), 1):
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vuln = Vulnerability(
                        id=self._generate_id(),
                        type=VulnerabilityType.SQL_INJECTION,
                        severity=SeverityLevel.CRITICAL,
                        title="Potential SQL Injection",
                        description="Direct SQL concatenation detected without parameterized queries",
                        location=f"Line {i}",
                        proof_of_concept=line.strip(),
                        remediation="Use parameterized queries or prepared statements",
                        cvss_score=9.9,
                        references=["https://owasp.org/www-community/attacks/SQL_Injection"]
                    )
                    self.vulnerabilities.append(vuln)
    
    def _check_xss(self, code: str) -> None:
        """Detect XSS vulnerabilities."""
        patterns = [
            r'innerHTML\s*=',
            r'\.html\(',
            r'\.append\(.*request\.',
        ]
        
        for i, line in enumerate(code.split('\n'), 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    vuln = Vulnerability(
                        id=self._generate_id(),
                        type=VulnerabilityType.XSS,
                        severity=SeverityLevel.HIGH,
                        title="Potential XSS Vulnerability",
                        description="Unsanitized user input rendered to DOM",
                        location=f"Line {i}",
                        proof_of_concept=line.strip(),
                        remediation="Use template escaping or sanitization libraries",
                        cvss_score=7.5,
                        references=["https://owasp.org/www-community/attacks/xss/"]
                    )
                    self.vulnerabilities.append(vuln)
    
    def _check_auth_issues(self, code: str) -> None:
        """Detect authentication issues."""
        auth_patterns = [
            (r'password.*=.*["\']', "Hardcoded credentials"),
            (r'auth.*=.*false', "Authentication bypass"),
            (r'verify.*=.*False', "Verification disabled"),
        ]
        
        for i, line in enumerate(code.split('\n'), 1):
            for pattern, issue in auth_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vuln = Vulnerability(
                        id=self._generate_id(),
                        type=VulnerabilityType.AUTH,
                        severity=SeverityLevel.CRITICAL,
                        title=f"Authentication Issue: {issue}",
                        description=issue,
                        location=f"Line {i}",
                        proof_of_concept=line.strip(),
                        remediation="Use environment variables and secure credential storage",
                        cvss_score=9.0,
                    )
                    self.vulnerabilities.append(vuln)
    
    def _check_crypto_issues(self, code: str) -> None:
        """Detect cryptographic weaknesses."""
        weak_patterns = [
            (r'md5', "MD5 is cryptographically broken"),
            (r'sha1', "SHA1 should not be used for passwords"),
            (r'pickle\.loads', "Pickle deserialization vulnerability"),
        ]
        
        for i, line in enumerate(code.split('\n'), 1):
            for pattern, issue in weak_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vuln = Vulnerability(
                        id=self._generate_id(),
                        type=VulnerabilityType.CRYPTO,
                        severity=SeverityLevel.HIGH,
                        title="Weak Cryptography",
                        description=issue,
                        location=f"Line {i}",
                        proof_of_concept=line.strip(),
                        remediation="Use SHA-256 or bcrypt for hashing",
                        cvss_score=7.5,
                    )
                    self.vulnerabilities.append(vuln)
    
    @staticmethod
    def _generate_id() -> str:
        """Generate unique vulnerability ID."""
        import uuid
        return str(uuid.uuid4())[:12]
