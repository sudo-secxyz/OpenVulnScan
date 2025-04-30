#utils/tasks.py
from celery_app import shared_task
from celery_app import celery_app
import _asyncio
from datetime import datetime
from services.scan_service import start_scan_task, run_scan as rs 
from database.db_manager import insert_scan  
@shared_task
def run_scan(scan_data: dict):
    result = rs(scan_data['scan_id'],scan_data["targets"])
    print(result)
    insert_scan(
        targets=scan_data["targets"],
        findings=result,
        started_at=datetime.utcnow()
    )
    return {"status": "done"}

@shared_task
def schedule_scan(scan_data: dict):
    return  start_scan_task(scan_data)
