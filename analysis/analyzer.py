"""AI-powered vulnerability analysis engine."""
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime
import json
from core.logger import setup_logger
from core.config import AppConfig
from core.exceptions import AIServiceException, AnalysisException
from .types import Vulnerability, ScanResult, VulnerabilityType, SeverityLevel
from .scanner import SecurityScanner, ScanConfig

logger = setup_logger(__name__)

class VulnerabilityAnalyzer:
    """AI-powered analyzer for vulnerability assessment and enhancement."""
    
    def __init__(self):
        self.scanner = SecurityScanner()
        self.ai_client = self._init_ai_client()
        logger.info("VulnerabilityAnalyzer initialized")
    
    def _init_ai_client(self):
        """Initialize AI client based on provider."""
        try:
            from anthropic import Anthropic
            return Anthropic(api_key=AppConfig.ai.api_key)
        except ImportError:
            logger.warning("Anthropic client not available, using fallback")
            return None
    
    async def analyze_scan_result(self, scan_result: ScanResult) -> ScanResult:
        """Enhance scan results with AI analysis."""
        logger.info(f"Starting AI analysis for scan {scan_result.scan_id}")
        
        try:
            for vuln in scan_result.vulnerabilities:
                enhanced = await self._analyze_single_vulnerability(vuln)
                vuln.description = enhanced.get("description", vuln.description)
                vuln.proof_of_concept = enhanced.get("poc", vuln.proof_of_concept)
                vuln.remediation = enhanced.get("remediation", vuln.remediation)
                vuln.cvss_score = float(enhanced.get("cvss_score", vuln.cvss_score or 0))
                vuln.metadata = enhanced.get("metadata", {})
            
            return scan_result
        except Exception as e:
            logger.error(f"AI analysis failed: {str(e)}")
            raise AnalysisException(f"Failed to analyze vulnerabilities: {str(e)}")
    
    async def _analyze_single_vulnerability(self, vuln: Vulnerability) -> Dict[str, Any]:
        """Use AI to enhance a single vulnerability analysis."""
        if not self.ai_client:
            return self._fallback_analysis(vuln)
        
        try:
            prompt = f"""Analyze this vulnerability and provide enhanced security insights:
            
Type: {vuln.type.value}
Title: {vuln.title}
Description: {vuln.description}
Location: {vuln.location}
Current PoC: {vuln.proof_of_concept}

Provide a JSON response with:
- description: Enhanced technical description
- poc: Improved proof of concept
- remediation: Detailed remediation steps
- cvss_score: CVSS 3.1 score (0-10)
- metadata: Additional security insights as JSON object"""
            
            response = self.ai_client.messages.create(
                model=AppConfig.ai.model,
                max_tokens=AppConfig.ai.max_tokens,
                messages=[{"role": "user", "content": prompt}]
            )
            
            response_text = response.content[0].text
            return self._parse_ai_response(response_text)
        except Exception as e:
            logger.error(f"AI service error: {str(e)}")
            return self._fallback_analysis(vuln)
    
    @staticmethod
    def _parse_ai_response(response_text: str) -> Dict[str, Any]:
        """Parse JSON from AI response."""
        try:
            # Extract JSON from response
            start = response_text.find('{')
            end = response_text.rfind('}') + 1
            if start >= 0 and end > start:
                json_str = response_text[start:end]
                return json.loads(json_str)
        except (json.JSONDecodeError, ValueError):
            pass
        return {}
    
    @staticmethod
    def _fallback_analysis(vuln: Vulnerability) -> Dict[str, Any]:
        """Provide fallback analysis when AI is unavailable."""
        severity_to_cvss = {
            SeverityLevel.CRITICAL: 9.9,
            SeverityLevel.HIGH: 7.5,
            SeverityLevel.MEDIUM: 5.5,
            SeverityLevel.LOW: 3.0,
            SeverityLevel.INFO: 1.0,
        }
        
        return {
            "description": vuln.description,
            "poc": vuln.proof_of_concept,
            "remediation": vuln.remediation,
            "cvss_score": severity_to_cvss.get(vuln.severity, 5.0),
            "metadata": {"analysis_type": "static"}
        }
