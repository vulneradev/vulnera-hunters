"""Repository pattern for data access."""
from typing import Optional, List
from sqlalchemy.orm import Session
import uuid
from core.logger import setup_logger
from .models import User, Scan, Vulnerability, RemediationHistory, BatchJob
from core.exceptions import DatabaseException

logger = setup_logger(__name__)

class ScanRepository:
    """Repository for Scan model."""
    
    @staticmethod
    def create(session: Session, user_id: str, target: str, language: str, **kwargs) -> Scan:
        """Create new scan record."""
        try:
            scan = Scan(
                id=str(uuid.uuid4()),
                user_id=user_id,
                target=target,
                language=language,
                **kwargs
            )
            session.add(scan)
            session.flush()
            logger.info(f"Created scan: {scan.id}")
            return scan
        except Exception as e:
            logger.error(f"Failed to create scan: {str(e)}")
            raise DatabaseException(f"Failed to create scan: {str(e)}")
    
    @staticmethod
    def get_by_id(session: Session, scan_id: str) -> Optional[Scan]:
        """Get scan by ID."""
        return session.query(Scan).filter(Scan.id == scan_id).first()
    
    @staticmethod
    def get_by_user(session: Session, user_id: str, limit: int = 50) -> List[Scan]:
        """Get scans for user."""
        return session.query(Scan).filter(
            Scan.user_id == user_id
        ).order_by(Scan.created_at.desc()).limit(limit).all()
    
    @staticmethod
    def update_status(session: Session, scan_id: str, status: str) -> bool:
        """Update scan status."""
        try:
            session.query(Scan).filter(Scan.id == scan_id).update({"status": status})
            return True
        except Exception as e:
            logger.error(f"Failed to update scan status: {str(e)}")
            return False

class VulnerabilityRepository:
    """Repository for Vulnerability model."""
    
    @staticmethod
    def create_batch(session: Session, scan_id: str, vulnerabilities: list) -> List[Vulnerability]:
        """Create multiple vulnerability records."""
        try:
            vuln_records = []
            for vuln in vulnerabilities:
                record = Vulnerability(
                    id=str(uuid.uuid4()),
                    scan_id=scan_id,
                    type=vuln.type.value,
                    severity=vuln.severity.value,
                    title=vuln.title,
                    description=vuln.description,
                    location=vuln.location,
                    proof_of_concept=vuln.proof_of_concept,
                    remediation=vuln.remediation,
                    cvss_score=vuln.cvss_score,
                    references=vuln.references,
                    metadata=vuln.metadata,
                )
                vuln_records.append(record)
            
            session.add_all(vuln_records)
            session.flush()
            logger.info(f"Created {len(vuln_records)} vulnerabilities for scan {scan_id}")
            return vuln_records
        except Exception as e:
            logger.error(f"Failed to create vulnerabilities: {str(e)}")
            raise DatabaseException(f"Failed to create vulnerabilities: {str(e)}")
    
    @staticmethod
    def get_by_scan(session: Session, scan_id: str) -> List[Vulnerability]:
        """Get vulnerabilities for scan."""
        return session.query(Vulnerability).filter(
            Vulnerability.scan_id == scan_id
        ).all()
    
    @staticmethod
    def get_by_severity(session: Session, scan_id: str, severity: str) -> List[Vulnerability]:
        """Get vulnerabilities by severity."""
        return session.query(Vulnerability).filter(
            Vulnerability.scan_id == scan_id,
            Vulnerability.severity == severity
        ).all()

class RemediationRepository:
    """Repository for remediation history and tracking."""
    
    @staticmethod
    def create_history(
        session: Session, 
        vulnerability_id: str,
        status: str,
        fix_code: Optional[str] = None,
        ai_reasoning: Optional[str] = None,
        result_message: Optional[str] = None,
        success: bool = False
    ):
        """Create remediation history record."""
        try:
            history = RemediationHistory(
                id=str(uuid.uuid4())[:12],
                vulnerability_id=vulnerability_id,
                status=status,
                fix_code=fix_code,
                ai_reasoning=ai_reasoning,
                result_message=result_message,
                success=success,
            )
            session.add(history)
            session.flush()
            logger.info(f"Created remediation history: {history.id}")
            return history
        except Exception as e:
            logger.error(f"Failed to create remediation history: {str(e)}")
            raise DatabaseException(f"Failed to create remediation history: {str(e)}")
    
    @staticmethod
    def get_by_vulnerability(session: Session, vulnerability_id: str) -> List:
        """Get remediation history for vulnerability."""
        return session.query(RemediationHistory).filter(
            RemediationHistory.vulnerability_id == vulnerability_id
        ).order_by(RemediationHistory.created_at.desc()).all()

class BatchJobRepository:
    """Repository for batch job tracking."""
    
    @staticmethod
    def create(
        session: Session,
        user_id: str,
        job_type: str,
        payload: dict,
        total_items: int = 0
    ):
        """Create new batch job."""
        try:
            job = BatchJob(
                id=str(uuid.uuid4())[:12],
                user_id=user_id,
                job_type=job_type,
                status="queued",
                total_items=total_items,
                payload=payload
            )
            session.add(job)
            session.flush()
            logger.info(f"Created batch job: {job.id}")
            return job
        except Exception as e:
            logger.error(f"Failed to create batch job: {str(e)}")
            raise DatabaseException(f"Failed to create batch job: {str(e)}")
    
    @staticmethod
    def update_status(session: Session, job_id: str, status: str, **kwargs):
        """Update batch job status."""
        try:
            update_data = {"status": status}
            if status == "processing":
                update_data["started_at"] = kwargs.get("started_at")
            elif status == "completed":
                update_data["completed_at"] = kwargs.get("completed_at")
            
            update_data.update(kwargs)
            session.query(BatchJob).filter(BatchJob.id == job_id).update(update_data)
            session.commit()
            logger.info(f"Updated batch job {job_id} to {status}")
            return True
        except Exception as e:
            logger.error(f"Failed to update batch job: {str(e)}")
            return False
    
    @staticmethod
    def get_by_id(session: Session, job_id: str):
        """Get batch job by ID."""
        return session.query(BatchJob).filter(BatchJob.id == job_id).first()
