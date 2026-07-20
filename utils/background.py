# utils/background.py
from datetime import datetime, timezone
import time
from sqlalchemy.orm import Session
from utils.tasks import run_scan  # Your existing scan runner

def handle_scan(req_data: dict, db: Session):
    scheduled_for = req_data.get('scheduled_for')
    if scheduled_for:
        # Wait until scheduled time
        now = datetime.now(timezone.utc)
        delay_seconds = (scheduled_for - now).total_seconds()
        if delay_seconds > 0:
            time.sleep(delay_seconds)
    # Actually run the scan
    run_scan.delay(req_data)
