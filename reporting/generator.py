"""Report generation engine."""
import json
from typing import List, Dict, Any
from datetime import datetime
from dataclasses import asdict
from core.logger import setup_logger
from core.exceptions import ReportGenerationException
from analysis.types import ScanResult, Vulnerability, SeverityLevel

logger = setup_logger(__name__)

class ReportGenerator:
    """Generate comprehensive security reports."""
    
    def __init__(self):
        logger.info("ReportGenerator initialized")
    
    def generate_report(self, scan_result: ScanResult, format: str = "json") -> str:
        """Generate report in specified format."""
        logger.info(f"Generating {format} report for scan {scan_result.scan_id}")
        
        try:
            if format == "json":
                return self._generate_json_report(scan_result)
            elif format == "html":
                return self._generate_html_report(scan_result)
            elif format == "markdown":
                return self._generate_markdown_report(scan_result)
            else:
                raise ReportGenerationException(f"Unsupported format: {format}")
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")
            raise ReportGenerationException(f"Failed to generate report: {str(e)}")
    
    def _generate_json_report(self, scan_result: ScanResult) -> str:
        """Generate JSON report."""
        report = {
            "scan_id": scan_result.scan_id,
            "target": scan_result.target,
            "timestamp": scan_result.timestamp.isoformat(),
            "duration_seconds": scan_result.scan_duration,
            "status": scan_result.status,
            "summary": self._generate_summary(scan_result),
            "vulnerabilities": [self._vuln_to_dict(v) for v in scan_result.vulnerabilities],
            "statistics": self._generate_statistics(scan_result),
        }
        return json.dumps(report, indent=2)
    
    def _generate_html_report(self, scan_result: ScanResult) -> str:
        """Generate HTML report."""
        summary = self._generate_summary(scan_result)
        stats = self._generate_statistics(scan_result)
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>VulneraAI Security Report - {scan_result.scan_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #1a1a1a; color: white; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; }}
        .vulnerability {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .critical {{ border-left: 5px solid #d32f2f; }}
        .high {{ border-left: 5px solid #f57c00; }}
        .medium {{ border-left: 5px solid #fbc02d; }}
        .low {{ border-left: 5px solid #388e3c; }}
        .severity {{ font-weight: bold; padding: 5px 10px; border-radius: 3px; }}
        .severity.critical {{ background: #d32f2f; color: white; }}
        .severity.high {{ background: #f57c00; color: white; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>VulneraAI Security Report</h1>
        <p>Scan ID: {scan_result.scan_id}</p>
        <p>Target: {scan_result.target}</p>
        <p>Timestamp: {scan_result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <ul>
            <li>Total Vulnerabilities: {summary['total_vulnerabilities']}</li>
            <li>Critical: {summary['critical_count']}</li>
            <li>High: {summary['high_count']}</li>
            <li>Medium: {summary['medium_count']}</li>
            <li>Risk Score: {summary['risk_score']:.1f}/10</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>Vulnerabilities</h2>
        {"".join(f'''
        <div class="vulnerability {v.severity.value}">
            <h3>{v.title}</h3>
            <p><strong>Type:</strong> {v.type.value}</p>
            <p><strong>Severity:</strong> <span class="severity {v.severity.value}">{v.severity.value.upper()}</span></p>
            <p><strong>Location:</strong> {v.location}</p>
            <p><strong>Description:</strong> {v.description}</p>
            <p><strong>Remediation:</strong> {v.remediation}</p>
        </div>
        ''' for v in scan_result.vulnerabilities)}
    </div>
</body>
</html>
"""
        return html
    
    def _generate_markdown_report(self, scan_result: ScanResult) -> str:
        """Generate Markdown report."""
        summary = self._generate_summary(scan_result)
        
        md = f"""# VulneraAI Security Report

**Scan ID:** {scan_result.scan_id}  
**Target:** {scan_result.target}  
**Timestamp:** {scan_result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}  
**Duration:** {scan_result.scan_duration:.2f}s

## Executive Summary

- **Total Vulnerabilities:** {summary['total_vulnerabilities']}
- **Critical:** {summary['critical_count']}
- **High:** {summary['high_count']}
- **Medium:** {summary['medium_count']}
- **Low:** {summary['low_count']}
- **Risk Score:** {summary['risk_score']:.1f}/10

## Vulnerabilities

"""
        for v in scan_result.vulnerabilities:
            md += f"""### {v.title}

**Type:** `{v.type.value}`  
**Severity:** **{v.severity.value.upper()}**  
**Location:** {v.location}  
**CVSS Score:** {v.cvss_score or 'N/A'}

**Description:**  
{v.description}

**Proof of Concept:**
