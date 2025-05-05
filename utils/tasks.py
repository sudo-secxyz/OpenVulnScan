#utils/tasks.py
from celery_app import shared_task
from celery_app import celery_app
import _asyncio
from datetime import datetime, timedelta
from config import setup_logging
from services.scan_service import start_scan_task, run_scan as rs 
from database.ops import insert_scan , SessionLocal 
from models.scheduled_scan import ScheduledScan
from models.scan import Scan
from models.finding import Finding
import pytz
from utils.get_system_time import get_system_timezone
from models.schemas import ScanRequest
import json

logger = setup_logging()

@shared_task
def run_scan(scan_data: dict):
    try:
        scan_id = scan_data['scan_id']
        targets = scan_data['targets']
        logger.info(f"Running scan {scan_id} on targets: {targets}")

        # Run the scan
        findings = rs(scan_id, targets)  # Call the `run_scan` function from `scan_service.py`

        # Log findings
        logger.info(f"Findings for scan {scan_id}: {findings}")

        # Save findings to the database
        db = SessionLocal()
        try:
            for finding in findings:
                # Flatten vulnerabilities into a single string for easier access
                vulnerabilities = finding["raw_data"].get("vulnerabilities", [])
                flattened_vulnerabilities = [
                    vuln["description"] for vuln in vulnerabilities if "description" in vuln
                ]

                db_finding = Finding(
                    scan_id=scan_id,
                    ip_address=finding["ip_address"],
                    hostname=finding["hostname"],
                    raw_data=json.dumps(finding["raw_data"]),  # Save raw_data as JSON
                    description=", ".join(flattened_vulnerabilities)  # Save descriptions as a single string
                )
                db.add(db_finding)
            db.commit()
        finally:
            db.close()

        logger.info(f"Findings for scan {scan_id} saved successfully")
        return findings
    except Exception as e:
        logger.error(f"Error in run_scan: {e}", exc_info=True)


@shared_task
def schedule_scan(scan_data: dict):
    scan_id = scan_data['scan_id']
    targets = scan_data['targets']
    insert_scan(scan_id, targets, datetime.now(pytz.timezone(get_system_timezone())))
    run_scan.delay({"scan_id": scan_id, "targets": targets})


@shared_task
def process_scheduled_scans():
    db = SessionLocal()
    try:
        local_tz = pytz.timezone(get_system_timezone())
        now = datetime.now(local_tz)
        scheduled_scans = db.query(ScheduledScan).filter(ScheduledScan.start_datetime <= now).all()
        for sscan in scheduled_scans:
            logger.info(f"Queuing scheduled scan {sscan.id} for execution")

            # Reuse the scheduled scan ID
            scan_id = f"scheduled-{sscan.id}-{now.strftime('%Y%m%d%H%M%S')}"
            targets = sscan.get_targets()  # Assuming this method returns a list of targets
            if isinstance(targets, str):
                targets = [targets]  # Ensure it's a list

            insert_scan(scan_id, targets, now)

            # Queue scan with Celery
            run_scan.delay({"scan_id": scan_id, "targets": sscan.get_targets()})
            logger.info(f"Queued scan ID: {scan_id}")

            # Update status or next run time if applicable
            # You could parse `sscan.days` for cron-style rescheduling in the future
            # For now, let's mark it as completed
            sscan.start_datetime = now + timedelta(days=7)  # or however you want to reschedule
            db.commit()
    except Exception as e:
        logger.error(f"Error in processing scheduled scans: {e}", exc_info=True)
    finally:
        db.close()

