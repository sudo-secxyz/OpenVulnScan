# services/scheduler.py
from models.scheduled_scan import ScheduledScan
from database import SessionLocal
from datetime import datetime
from services.scan_service import run_scan  # Import the run_scan function from scan_service.py
from celery import Celery
from config import setup_logging

logger = setup_logging()

@celery.task
def run_scheduled_scans():
    db = SessionLocal()
    now = datetime.utcnow()
    scans = db.query(ScheduledScan).filter(ScheduledScan.start_datetime <= now, ScheduledScan.status == "queued").all()
    
    for scan in scans:
        try:
            # Extract scan details
            scan_id = scan.id  # Assuming 'id' is the identifier for the scan
            targets = scan.get_targets()  # Get the list of IPs from the 'target_ip' field
            
            # Trigger the scan (initiate the scan by calling run_scan)
            run_scan(scan_id, targets)  # This triggers the scan
            
            # Update the scan status after running
            scan.status = "completed"
            db.commit()
        except Exception as e:
            # If there's an error, set the status to 'failed'
            scan.status = "failed"
            db.commit()
            logger.error(f"Error running scheduled scan {scan.id}: {str(e)}")
    
    db.close()
