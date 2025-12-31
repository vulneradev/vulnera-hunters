"""Tests for security scanner module."""
import pytest
from analysis.scanner import SecurityScanner, ScanConfig
from analysis.types import VulnerabilityType, SeverityLevel

@pytest.fixture
def scanner():
    """Create scanner instance for testing."""
    return SecurityScanner(ScanConfig())

def test_sql_injection_detection(scanner):
    """Test SQL injection vulnerability detection."""
    code = '''
query = "SELECT * FROM users WHERE id = " + user_input
db.execute(query)
'''
    vulnerabilities = scanner.scan_code(code)
    assert any(v.type == VulnerabilityType.SQL_INJECTION for v in vulnerabilities)

def test_xss_detection(scanner):
    """Test XSS vulnerability detection."""
    code = 'element.innerHTML = user_input'
    vulnerabilities = scanner.scan_code(code)
    assert any(v.type == VulnerabilityType.XSS for v in vulnerabilities)

def test_auth_detection(scanner):
    """Test authentication issue detection."""
    code = 'password = "admin123"'
    vulnerabilities = scanner.scan_code(code)
    assert any(v.type == VulnerabilityType.AUTH for v in vulnerabilities)

def test_crypto_detection(scanner):
    """Test cryptographic weakness detection."""
    code = 'import hashlib; hashlib.md5(password).digest()'
    vulnerabilities = scanner.scan_code(code)
    assert any(v.type == VulnerabilityType.CRYPTO for v in vulnerabilities)
