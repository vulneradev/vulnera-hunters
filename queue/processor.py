"""Queue processor for batch vulnerability operations."""
import asyncio
import uuid
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from core.logger import setup_logger
from database.repositories import BatchJobRepository
from core.exceptions import QueueException

logger = setup_logger(__name__)

class QueueProcessor:
    """Process batch jobs from queue."""
    
    def __init__(self):
        self.queue: List[Dict[str, Any]] = []
        self.processing = False
        logger.info("QueueProcessor initialized")
    
    async def enqueue_scan_batch(
        self,
        db: Session,
        user_id: str,
        code_samples: List[str],
        language: str = "python"
    ) -> Dict[str, Any]:
        """Enqueue batch scan jobs."""
        try:
            job_id = str(uuid.uuid4())[:12]
            
            # Create batch job record
            job = BatchJobRepository.create(
                db,
                user_id=user_id,
                job_type="scan_batch",
                payload={
                    "code_samples": code_samples,
                    "language": language
                },
                total_items=len(code_samples)
            )
            
            logger.info(f"Enqueued batch scan job: {job.id} with {len(code_samples)} items")
            
            return {
                "job_id": job.id,
                "status": "queued",
                "total_items": len(code_samples),
                "message": "Batch scan queued successfully"
            }
        except Exception as e:
            logger.error(f"Failed to enqueue batch scan: {str(e)}")
            raise QueueException(f"Failed to enqueue batch scan: {str(e)}")
    
    async def enqueue_remediation_batch(
        self,
        db: Session,
        user_id: str,
        vulnerability_ids: List[str]
    ) -> Dict[str, Any]:
        """Enqueue batch remediation jobs."""
        try:
            job = BatchJobRepository.create(
                db,
                user_id=user_id,
                job_type="remediation_batch",
                payload={
                    "vulnerability_ids": vulnerability_ids
                },
                total_items=len(vulnerability_ids)
            )
            
            logger.info(f"Enqueued batch remediation job: {job.id} with {len(vulnerability_ids)} items")
            
            return {
                "job_id": job.id,
                "status": "queued",
                "total_items": len(vulnerability_ids),
                "message": "Batch remediation queued successfully"
            }
        except Exception as e:
            logger.error(f"Failed to enqueue batch remediation: {str(e)}")
            raise QueueException(f"Failed to enqueue batch remediation: {str(e)}")
    
    async def get_job_status(self, db: Session, job_id: str) -> Dict[str, Any]:
        """Get status of a batch job."""
        try:
            job = BatchJobRepository.get_by_id(db, job_id)
            
            if not job:
                raise QueueException(f"Job {job_id} not found")
            
            return {
                "job_id": job.id,
                "status": job.status,
                "total_items": job.total_items,
                "processed_items": job.processed_items,
                "failed_items": job.failed_items,
                "created_at": job.created_at.isoformat(),
                "started_at": job.started_at.isoformat() if job.started_at else None,
                "completed_at": job.completed_at.isoformat() if job.completed_at else None,
                "progress": f"{job.processed_items}/{job.total_items}" if job.total_items > 0 else "0/0"
            }
        except Exception as e:
            logger.error(f"Failed to get job status: {str(e)}")
            raise QueueException(f"Failed to get job status: {str(e)}")
