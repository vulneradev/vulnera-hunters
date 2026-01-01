"""Background worker for processing batch jobs."""
import asyncio
from typing import Dict, Any
from sqlalchemy.orm import Session
from analysis.analyzer import VulnerabilityAnalyzer
from analysis.scanner import SecurityScanner
from remediation.engine import RemediationEngine
from database.repositories import BatchJobRepository
from core.logger import setup_logger

logger = setup_logger(__name__)

class BatchWorker:
    """Background worker for batch job processing."""
    
    def __init__(self):
        self.analyzer = VulnerabilityAnalyzer()
        self.scanner = SecurityScanner()
        self.remediator = RemediationEngine()
        logger.info("BatchWorker initialized")
    
    async def process_scan_batch(self, db: Session, job_id: str) -> Dict[str, Any]:
        """Process batch scan job."""
        try:
            job = BatchJobRepository.get_by_id(db, job_id)
            if not job:
                return {"status": "failed", "error": "Job not found"}
            
            BatchJobRepository.update_status(db, job_id, "processing")
            
            code_samples = job.payload.get("code_samples", [])
            language = job.payload.get("language", "python")
            
            results = []
            for idx, code in enumerate(code_samples):
                try:
                    vulnerabilities = self.scanner.scan_code(code, language)
                    results.append({
                        "sample": idx,
                        "vulnerabilities_found": len(vulnerabilities),
                        "status": "success"
                    })
                    
                    BatchJobRepository.update_status(
                        db, 
                        job_id, 
                        "processing",
                        processed_items=idx + 1
                    )
                except Exception as e:
                    logger.error(f"Failed to scan sample {idx}: {str(e)}")
                    results.append({
                        "sample": idx,
                        "status": "failed",
                        "error": str(e)
                    })
                    BatchJobRepository.update_status(
                        db,
                        job_id,
                        "processing",
                        failed_items=job.failed_items + 1
                    )
            
            BatchJobRepository.update_status(
                db,
                job_id,
                "completed",
                result={"results": results}
            )
            
            logger.info(f"Batch scan job {job_id} completed")
            return {"status": "completed", "results": results}
            
        except Exception as e:
            logger.error(f"Batch scan processing failed: {str(e)}")
            BatchJobRepository.update_status(db, job_id, "failed", error_message=str(e))
            return {"status": "failed", "error": str(e)}
    
    async def process_remediation_batch(self, db: Session, job_id: str) -> Dict[str, Any]:
        """Process batch remediation job."""
        try:
            job = BatchJobRepository.get_by_id(db, job_id)
            if not job:
                return {"status": "failed", "error": "Job not found"}
            
            BatchJobRepository.update_status(db, job_id, "processing")
            
            vulnerability_ids = job.payload.get("vulnerability_ids", [])
            
            results = await self.remediator.batch_remediate(db, vulnerability_ids)
            
            BatchJobRepository.update_status(
                db,
                job_id,
                "completed",
                result=results,
                processed_items=results["total"],
                failed_items=results["failed"]
            )
            
            logger.info(f"Batch remediation job {job_id} completed")
            return results
            
        except Exception as e:
            logger.error(f"Batch remediation processing failed: {str(e)}")
            BatchJobRepository.update_status(db, job_id, "failed", error_message=str(e))
            return {"status": "failed", "error": str(e)}
