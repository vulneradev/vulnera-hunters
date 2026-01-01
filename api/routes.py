"""FastAPI routes for VulneraAI."""
from fastapi import APIRouter, HTTPException, Query, BackgroundTasks, Depends
from sqlalchemy.orm import Session
from typing import Optional, List
import uuid
import time
import asyncio
from analysis.analyzer import VulnerabilityAnalyzer
from analysis.scanner import SecurityScanner, ScanConfig
from analysis.types import ScanResult
from simulation.simulator import AttackSimulator
from reporting.generator import ReportGenerator
from remediation.engine import RemediationEngine
from queue.processor import QueueProcessor
from queue.worker import BatchWorker
from database.connection import DatabaseManager
from database.models import Scan, Vulnerability
from database.repositories import ScanRepository, VulnerabilityRepository, RemediationRepository, BatchJobRepository
from cache.redis_cache import RedisCache, cached
from core.logger import setup_logger
from api.dependencies import get_db

logger = setup_logger(__name__)
router = APIRouter(prefix="/api/v1", tags=["vulnerabilities"])

# Service instances
analyzer = VulnerabilityAnalyzer()
scanner = SecurityScanner()
simulator = AttackSimulator()
report_generator = ReportGenerator()
remediator = RemediationEngine()
queue_processor = QueueProcessor()
batch_worker = BatchWorker()

@router.post("/scan")
async def create_scan(
    code: str, 
    language: str = "python", 
    enable_ai: bool = True,
    enable_auto_fix: bool = False,
    db: Session = Depends(get_db)
):
    """Initiate a new vulnerability scan with optional auto-remediation."""
    try:
        scan_id = str(uuid.uuid4())[:12]
        logger.info(f"Starting scan {scan_id} for {language}")
        
        start_time = time.time()
        
        scan_record = ScanRepository.create(
            db, 
            user_id="system",
            target=language,
            language=language,
            status="processing"
        )
        
        vulnerabilities = scanner.scan_code(code, language)
        
        scan_result = ScanResult(
            scan_id=scan_id,
            target=language,
            vulnerabilities=vulnerabilities,
            scan_duration=time.time() - start_time,
        )
        
        if enable_ai:
            scan_result = await analyzer.analyze_scan_result(scan_result)
        
        if vulnerabilities:
            vuln_records = VulnerabilityRepository.create_batch(db, scan_record.id, vulnerabilities)
            
            if enable_auto_fix:
                for vuln in vuln_records:
                    try:
                        await remediator.auto_fix_vulnerability(db, vuln.id, code)
                    except Exception as e:
                        logger.warning(f"Auto-fix failed for {vuln.id}: {str(e)}")
        
        ScanRepository.update_status(db, scan_record.id, "completed")
        db.commit()
        
        cache_key = f"scan:{scan_id}"
        RedisCache.set(cache_key, {
            "scan_id": scan_id,
            "status": "completed",
            "vulnerabilities_found": len(vulnerabilities),
            "duration": scan_result.scan_duration,
        })
        
        return {
            "scan_id": scan_id,
            "status": "completed",
            "vulnerabilities_found": len(vulnerabilities),
            "duration": scan_result.scan_duration,
            "auto_fix_enabled": enable_auto_fix,
        }
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scan/{scan_id}")
async def get_scan(scan_id: str, db: Session = Depends(get_db)):
    """Retrieve scan results with vulnerability details."""
    try:
        cache_key = f"scan:{scan_id}"
        cached_result = RedisCache.get(cache_key)
        if cached_result:
            return cached_result
        
        scan_record = ScanRepository.get_by_id(db, scan_id)
        if not scan_record:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        vulnerabilities = VulnerabilityRepository.get_by_scan(db, scan_id)
        
        result = {
            "scan_id": scan_record.id,
            "target": scan_record.target,
            "status": scan_record.status,
            "vulnerabilities": [
                {
                    "id": v.id,
                    "type": v.type,
                    "severity": v.severity,
                    "title": v.title,
                    "cvss_score": v.cvss_score,
                    "remediation_status": v.remediation_status,
                    "auto_fix_available": v.auto_fix_available,
                }
                for v in vulnerabilities
            ],
        }
        
        RedisCache.set(cache_key, result)
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/vulnerability/{vuln_id}/auto-fix")
async def auto_fix_vulnerability(
    vuln_id: str,
    target_code: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Generate and apply auto-fix for a vulnerability."""
    try:
        result = await remediator.auto_fix_vulnerability(db, vuln_id, target_code)
        
        return {
            "vulnerability_id": vuln_id,
            "status": "success" if result["success"] else "failed",
            "fix_code": result.get("code"),
            "reasoning": result.get("reasoning"),
            "confidence": result.get("confidence"),
            "message": result.get("message"),
        }
    except Exception as e:
        logger.error(f"Auto-fix failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/vulnerability/{vuln_id}/remediation-history")
async def get_remediation_history(vuln_id: str, db: Session = Depends(get_db)):
    """Get remediation history for a vulnerability."""
    try:
        history = RemediationRepository.get_by_vulnerability(db, vuln_id)
        
        return {
            "vulnerability_id": vuln_id,
            "remediation_history": [
                {
                    "id": h.id,
                    "status": h.status,
                    "attempt": h.attempt_number,
                    "success": h.success,
                    "message": h.result_message,
                    "created_at": h.created_at.isoformat(),
                }
                for h in history
            ],
        }
    except Exception as e:
        logger.error(f"Failed to retrieve remediation history: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/batch/scan")
async def batch_scan(
    code_samples: List[str],
    language: str = "python",
    db: Session = Depends(get_db)
):
    """Enqueue batch scan jobs."""
    try:
        result = await queue_processor.enqueue_scan_batch(
            db,
            user_id="system",
            code_samples=code_samples,
            language=language
        )
        
        return result
    except Exception as e:
        logger.error(f"Batch scan enqueue failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/batch/remediate")
async def batch_remediate(
    vulnerability_ids: List[str],
    db: Session = Depends(get_db)
):
    """Enqueue batch remediation jobs."""
    try:
        result = await queue_processor.enqueue_remediation_batch(
            db,
            user_id="system",
            vulnerability_ids=vulnerability_ids
        )
        
        return result
    except Exception as e:
        logger.error(f"Batch remediation enqueue failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/batch/{job_id}")
async def get_batch_status(job_id: str, db: Session = Depends(get_db)):
    """Get status of a batch job."""
    try:
        status = await queue_processor.get_job_status(db, job_id)
        return status
    except Exception as e:
        logger.error(f"Failed to get batch status: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/batch/{job_id}/process")
async def process_batch_job(
    job_id: str,
    job_type: str = Query("auto-detect"),
    db: Session = Depends(get_db)
):
    """Process a pending batch job."""
    try:
        job = BatchJobRepository.get_by_id(db, job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        
        if job.job_type == "scan_batch":
            result = await batch_worker.process_scan_batch(db, job_id)
        elif job.job_type == "remediation_batch":
            result = await batch_worker.process_remediation_batch(db, job_id)
        else:
            raise HTTPException(status_code=400, detail=f"Unknown job type: {job.job_type}")
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Batch processing failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan/{scan_id}/report")
async def generate_report(scan_id: str, format: str = Query("json", regex="^(json|html|markdown)$"), db: Session = Depends(get_db)):
    """Generate report for completed scan."""
    try:
        scan_record = ScanRepository.get_by_id(db, scan_id)
        if not scan_record:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        vulnerabilities = VulnerabilityRepository.get_by_scan(db, scan_id)
        
        result = {
            "scan_id": scan_record.id,
            "target": scan_record.target,
            "status": scan_record.status,
            "vulnerabilities": [
                {
                    "id": v.id,
                    "type": v.type,
                    "severity": v.severity,
                    "title": v.title,
                    "cvss_score": v.cvss_score,
                }
                for v in vulnerabilities
            ],
        }
        
        report = report_generator.generate_report(result, format)
        return {"report": report, "format": format}
    except Exception as e:
        logger.error(f"Report generation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan/{scan_id}/simulate")
async def simulate_attack(scan_id: str, vulnerability_id: str, attack_type: str, depth: int = Query(2, ge=1, le=5), db: Session = Depends(get_db)):
    """Simulate attack against vulnerability."""
    try:
        scan_record = ScanRepository.get_by_id(db, scan_id)
        if not scan_record:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        results = await simulator.simulate_attack(
            vulnerability_id, 
            attack_type, 
            scan_record.target,
            depth
        )
        
        return {
            "simulations": [
                {
                    "attack_type": r.attack_type,
                    "success": r.success,
                    "impact_score": r.impact_score,
                }
                for r in results
            ]
        }
    except Exception as e:
        logger.error(f"Attack simulation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
async def health_check(db: Session = Depends(get_db)):
    """Health check endpoint."""
    try:
        db.execute("SELECT 1")
        
        RedisCache.set("health_check", "ok")
        
        return {
            "status": "healthy",
            "service": "VulneraAI Backend",
            "database": "ok",
            "cache": "ok"
        }
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return {
            "status": "degraded",
            "service": "VulneraAI Backend",
            "error": str(e)
        }
