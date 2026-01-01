"""AI-powered auto-remediation engine."""
import asyncio
import uuid
from typing import Optional, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from anthropic import Anthropic

from core.logger import setup_logger
from core.config import AppConfig
from core.exceptions import RemediationException
from database.models import Vulnerability, RemediationHistory
from .strategies import RemediationStrategy

logger = setup_logger(__name__)

class RemediationEngine:
    """AI-powered vulnerability remediation engine."""
    
    def __init__(self):
        self.ai_client = Anthropic(api_key=AppConfig.ai.api_key)
        self.strategies = {
            "sql_injection": RemediationStrategy.sql_injection_fix,
            "xss": RemediationStrategy.xss_fix,
            "command_injection": RemediationStrategy.command_injection_fix,
            "authentication": RemediationStrategy.auth_fix,
            "cryptography": RemediationStrategy.crypto_fix,
        }
        logger.info("RemediationEngine initialized")
    
    async def auto_fix_vulnerability(
        self, 
        db: Session, 
        vulnerability_id: str,
        target_code: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generate and apply auto-fix for a vulnerability."""
        try:
            vuln = db.query(Vulnerability).filter(
                Vulnerability.id == vulnerability_id
            ).first()
            
            if not vuln:
                raise RemediationException(f"Vulnerability {vulnerability_id} not found")
            
            logger.info(f"Starting auto-fix for {vuln.type}")
            
            # Generate fix using AI
            fix_result = await self._generate_ai_fix(vuln, target_code)
            
            # Create remediation history record
            history = RemediationHistory(
                id=str(uuid.uuid4())[:12],
                vulnerability_id=vulnerability_id,
                status="completed" if fix_result["success"] else "failed",
                fix_code=fix_result.get("code"),
                ai_reasoning=fix_result.get("reasoning"),
                result_message=fix_result.get("message"),
                success=fix_result["success"],
                applied_at=datetime.utcnow() if fix_result["success"] else None,
            )
            
            # Update vulnerability record
            vuln.remediation_status = "fixed" if fix_result["success"] else "failed"
            vuln.auto_fix_available = True
            vuln.auto_fix_code = fix_result.get("code")
            vuln.fix_confidence = fix_result.get("confidence", 0.0)
            
            db.add(history)
            db.commit()
            
            logger.info(f"Auto-fix completed: {fix_result['success']}")
            return fix_result
            
        except Exception as e:
            logger.error(f"Auto-fix failed: {str(e)}")
            raise RemediationException(f"Remediation failed: {str(e)}")
    
    async def _generate_ai_fix(
        self, 
        vuln: Vulnerability, 
        target_code: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generate fix using Claude AI."""
        try:
            prompt = f"""You are a security expert. Generate a fix for this vulnerability:

Vulnerability Type: {vuln.type}
Severity: {vuln.severity}
Title: {vuln.title}
Description: {vuln.description}
Location: {vuln.location}
Current PoC: {vuln.proof_of_concept}
{"Target Code:\\n" + target_code if target_code else ""}

Generate a JSON response with:
- code: Fixed code snippet
- reasoning: Explanation of the fix
- message: Summary of changes
- confidence: Confidence score (0-1)
- validation: How to validate the fix works

Focus on: Security best practices, input validation, proper encoding, secure libraries."""
            
            response = self.ai_client.messages.create(
                model=AppConfig.ai.model,
                max_tokens=AppConfig.ai.max_tokens,
                messages=[{"role": "user", "content": prompt}]
            )
            
            response_text = response.content[0].text
            return self._parse_fix_response(response_text)
            
        except Exception as e:
            logger.error(f"AI fix generation failed: {str(e)}")
            return {
                "success": False,
                "code": None,
                "reasoning": str(e),
                "message": "AI-based fix generation failed",
                "confidence": 0.0
            }
    
    @staticmethod
    def _parse_fix_response(response_text: str) -> Dict[str, Any]:
        """Parse JSON from AI fix response."""
        import json
        try:
            start = response_text.find('{')
            end = response_text.rfind('}') + 1
            if start >= 0 and end > start:
                json_str = response_text[start:end]
                data = json.loads(json_str)
                return {
                    "success": True,
                    "code": data.get("code"),
                    "reasoning": data.get("reasoning"),
                    "message": data.get("message"),
                    "confidence": float(data.get("confidence", 0.5)),
                    "validation": data.get("validation")
                }
        except (json.JSONDecodeError, ValueError) as e:
            logger.error(f"Failed to parse fix response: {e}")
        
        return {
            "success": False,
            "code": None,
            "reasoning": "Failed to parse AI response",
            "message": "Invalid response format",
            "confidence": 0.0
        }
    
    async def batch_remediate(
        self,
        db: Session,
        vulnerability_ids: list,
        target_code: Optional[str] = None
    ) -> Dict[str, Any]:
        """Batch remediate multiple vulnerabilities."""
        results = []
        
        for vuln_id in vulnerability_ids:
            try:
                result = await self.auto_fix_vulnerability(db, vuln_id, target_code)
                results.append({"id": vuln_id, "result": result})
            except Exception as e:
                results.append({"id": vuln_id, "error": str(e)})
        
        successful = sum(1 for r in results if "result" in r and r["result"]["success"])
        
        return {
            "total": len(vulnerability_ids),
            "successful": successful,
            "failed": len(vulnerability_ids) - successful,
            "results": results
        }
