# services/scan_service.py
import uuid
import datetime
from fastapi import BackgroundTasks
from database.db_manager import update_scan_findings

from models.schemas import ScanRequest, ScanResult
from database.db_manager import insert_scan, get_scan
from scanners.nmap_runner import NmapRunner
from config import setup_logging

logger = setup_logging()
def run_scan(scan_id: str, targets: list):
    """Background task to run the vulnerability scan"""
    # Import logger here to avoid circular imports
   
    
    logger.info(f"Running scan {scan_id} on targets: {targets}")
    logger.debug(f"Running scan {scan_id} on targets: {targets}")
    try:
        scanner = NmapRunner(targets)
        findings = scanner.run()
        logger.debug(f"Findings for scan {scan_id}: {findings}")
        # Update findings in the database
        update_scan_findings(scan_id, findings)
        logger.info(f"Scan {scan_id} completed successfully with {len(findings)} findings")
    except Exception as e:
        logger.error(f"Error during scan {scan_id}: {str(e)}", exc_info=True)

def start_scan_task(req: ScanRequest, background_tasks: BackgroundTasks = None) -> ScanResult:
    """Start a new scan as a background task"""
    if background_tasks:
        scan_id = str(uuid.uuid4())
        now = datetime.datetime.utcnow()
    
        # Insert initial scan record
        insert_scan(scan_id, req.targets, now)
    
        # Add scan task to background tasks
        logger.debug(f"Starting scan task for scan ID {scan_id} with targets: {req.targets}")
        background_tasks.add_task(run_scan, scan_id, req.targets)
    
        return ScanResult(
            id=scan_id,
            targets=req.targets,
            findings=[],
            started_at=now,
            completed_at=None
        )

def get_scan_details(scan_id: str):
    """Get details for a specific scan"""
    return get_scan(scan_id)

