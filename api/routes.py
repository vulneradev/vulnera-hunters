"""FastAPI routes for VulneraAI."""
from fastapi import APIRouter, HTTPException, Query, BackgroundTasks, Depends
from sqlalchemy.orm import Session
from typing import Optional
import uuid
import time
import asyncio
from analysis.analyzer import VulnerabilityAnalyzer
from analysis.scanner import SecurityScanner, ScanConfig
from analysis.types import ScanResult
from simulation.simulator import AttackSimulator
from reporting.generator import ReportGenerator
from database.connection import DatabaseManager
from database.models import Scan, Vulnerability
from database.repositories import ScanRepository, VulnerabilityRepository
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

@router.post("/scan")
async def create_scan(
    code: str, 
    language: str = "python", 
    enable_ai: bool = True,
    db: Session = Depends(get_db)
):
    """Initiate a new vulnerability scan."""
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
        
        # Run static analysis
        vulnerabilities = scanner.scan_code(code, language)
        
        # Create scan result
        scan_result = ScanResult(
            scan_id=scan_id,
            target=language,
            vulnerabilities=vulnerabilities,
            scan_duration=time.time() - start_time,
        )
        
        # Run AI analysis if enabled
        if enable_ai:
            scan_result = await analyzer.analyze_scan_result(scan_result)
        
        if vulnerabilities:
            VulnerabilityRepository.create_batch(db, scan_record.id, vulnerabilities)
        
        # Update scan status
        ScanRepository.update_status(db, scan_record.id, "completed")
        
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
        }
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scan/{scan_id}")
async def get_scan(scan_id: str, db: Session = Depends(get_db)):
    """Retrieve scan results."""
    try:
        cache_key = f"scan:{scan_id}"
        cached_result = RedisCache.get(cache_key)
        if cached_result:
            return cached_result
        
        # Query database
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
        
        # Cache result
        RedisCache.set(cache_key, result)
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan/{scan_id}/report")
async def generate_report(scan_id: str, format: str = Query("json", regex="^(json|html|markdown)$"), db: Session = Depends(get_db)):
    """Generate report for completed scan."""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    try:
        result = scan_results[scan_id]
        report = report_generator.generate_report(result, format)
        return {"report": report, "format": format}
    except Exception as e:
        logger.error(f"Report generation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan/{scan_id}/simulate")
async def simulate_attack(scan_id: str, vulnerability_id: str, attack_type: str, depth: int = Query(2, ge=1, le=5), db: Session = Depends(get_db)):
    """Simulate attack against vulnerability."""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    try:
        results = await simulator.simulate_attack(
            vulnerability_id, 
            attack_type, 
            scan_results[scan_id].target,
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
        # Test database
        db.execute("SELECT 1")
        
        # Test cache
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
