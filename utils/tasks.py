# utils/tasks.py

import json
import requests
import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from urllib.parse import urlparse, urlunparse
from services.asset_service import ensure_asset_exists
import pytz
from zapv2 import ZAPv2

from celery_app import shared_task
from config import setup_logging, ZAP_RESULTS_DIR
from database.ops import insert_scan, SessionLocal
from models.cve import CVE
from models.discovery import DiscoveryHost
from models.finding import Finding
from models.scheduled_scan import ScheduledScan
from models.scan import Scan
from models.web_alert import WebAlert
from services.cve_service import get_cve_details
from services.scan_service import run_scan as rs
from utils.get_system_time import get_system_timezone
from scanners.nmap_runner import NmapRunner
from utils.settings import get_system_timezone
from utils.syslog import send_syslog_message
from database.db_manager import get_db


logger = setup_logging()

# ZAP configuration
ZAP_API_URL = os.getenv("ZAP_API_URL", "http://localhost:8090")
ZAP_API_KEY = ""
zap = ZAPv2(apikey=ZAP_API_KEY, proxies={'http': ZAP_API_URL, 'https': ZAP_API_URL})

# === Helper Functions ===

def normalize_url(target: str) -> str:
    """Ensure the target URL includes a valid scheme."""
    parsed = urlparse(target)
    if not parsed.scheme:
        # Default to http if no scheme is provided
        return urlunparse(("http", parsed.netloc or parsed.path, "", "", "", ""))
    return target


def validate_target_url(zap: ZAPv2, base_url: str) -> str | None:
    """
    Validate the target URL by checking accessibility via HTTPS and HTTP.
    If the URL does not start with http/https, try both schemes.
    Returns the first working URL, or None if inaccessible.
    """
    session = requests.Session()
    session.verify = False  # In case of self-signed certs

    schemes = []
    parsed = urlparse(base_url)

    if parsed.scheme:
        # If scheme is given (http or https), try it as-is
        schemes.append(parsed.scheme)
    else:
        # Try https first, then http
        schemes = ['https', 'http']

    hostname = parsed.hostname or base_url

    for scheme in schemes:
        test_url = f"{scheme}://{hostname}"
        try:
            resp = session.get(test_url, timeout=5)
            if resp.status_code < 400:
                # Ask ZAP to start crawling this URL
                zap.spider.scan(test_url)
                return test_url
        except Exception as e:
            continue  # Try the next scheme

    return None

def run_parallel_scans(scan_id, targets):
    """Run Nmap scans in parallel for multiple targets."""
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(lambda target: rs(scan_id, [target]), targets))
    # Flatten any nested results
    return [item for sublist in results for item in (sublist if isinstance(sublist, list) else [sublist])]

def process_cves(finding):
    """Extract CVE IDs from finding raw data and insert into the database."""
    session = SessionLocal()
    try:
        raw_data = json.loads(finding.raw_data)
        cve_ids = list({vuln['id'] for vuln in raw_data.get('vulnerabilities', [])})
        for cve_id in cve_ids:
            cve_entry = CVE(cve_id=cve_id, finding_id=finding.id)
            session.add(cve_entry)
        session.commit()
        logger.info(f"Committed {len(cve_ids)} CVEs for finding {finding.id}")
    except Exception as e:
        logger.error(f"Error committing CVEs for finding {finding.id}: {e}")
        session.rollback()
    finally:
        session.close()

def enrich_cve_descriptions():
    """Fetch and update CVE descriptions for CVEs missing summaries."""
    session = SessionLocal()
    try:
        cves = session.query(CVE).filter(CVE.summary == None).all()
        logger.info(f"Found {len(cves)} CVEs missing descriptions")
        for cve in cves:
            for attempt in range(3):
                details = get_cve_details(cve.cve_id.strip())
                if details.get("error") == 429:
                    time.sleep(10)  # Wait 10 seconds and retry
                    continue
                break

            try:
                if details and details["description"]:
                    cve.summary = details["description"]
                    cve.severity = details.get("severity")
                    cve.remediation = details.get("remediation")
                    session.add(cve)
                else:
                    logger.warning(f"No description found for CVE {cve.cve_id}")
            except Exception as e:
                logger.error(f"Error fetching description for CVE {cve.cve_id}: {e}")
        session.commit()
    except Exception as e:
        logger.error(f"Error committing CVE descriptions: {e}")
        session.rollback()
    finally:
        session.close()

def get_scan_status(scan_id=None):
    params = {}
    if scan_id:
        params['scanId'] = scan_id
    response = zap._request(zap.base + 'ascan/view/status/', params)
    return response.get('status')

# === Celery Tasks ===

def scan_to_dict(scan):
    return {
        "id": scan.id,
        "targets": scan.targets,
        "status": scan.status,
        "started_at": str(scan.started_at),
        "completed_at": str(scan.completed_at)
    }

@shared_task
def run_scan(scan_data: dict):
    """
    Run scan on given targets, store findings, process CVEs,
    update scan status, and enrich CVE descriptions.
    """
    scan_id = scan_data['scan_id']
    targets = scan_data['targets']
    logger.info(f"Running scan {scan_id} on targets: {targets}")

    findings = run_parallel_scans(scan_id, targets)
    for target in targets:
        ensure_asset_exists(target, last_scanned=datetime.utcnow())
    # Ensure findings is a flat list
    if any(isinstance(f, list) for f in findings):
        findings = [item for sublist in findings for item in sublist]

    logger.info(f"Findings for scan {scan_id}: {findings}")

    db = SessionLocal()
    try:
        for finding in findings:
            if not isinstance(finding, dict):
                logger.error(f"Skipping finding because it is not a dict: {finding}")
                continue
            db_finding = Finding(
                scan_id=scan_id,
                ip_address=finding.get("ip"),
                hostname=finding.get("hostname"),
                raw_data=json.dumps(finding),
                description=", ".join(vuln.get("description", "") for vuln in finding.get("vulnerabilities", []))
            )
            db.add(db_finding)
            db.commit()  # Commit to get finding ID for CVE linking
            process_cves(db_finding)

        # Update scan status to completed
        db_scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if db_scan:
            db_scan.status = 'completed'
            db_scan.completed_at = datetime.now(pytz.timezone(get_system_timezone()))
            db.commit()
            
    except Exception as e:
        logger.error(f"Error saving findings or updating scan status: {e}", exc_info=True)
        db.rollback()
    finally:
        send_syslog_message(json.dumps(findings), db)
        db.close()

    enrich_cve_descriptions()

@shared_task
def schedule_scan(scan_data: dict):
    """Insert scan into DB and trigger async scan task."""
    scan_id = scan_data['scan_id']
    targets = scan_data['targets']
    insert_scan(scan_id, targets, datetime.now(pytz.timezone(get_system_timezone())))
    run_scan.delay({"scan_id": scan_id, "targets": targets})

@shared_task
def process_scheduled_scans():
    """
    Query scheduled scans that are due, queue them for execution,
    and update their next scheduled run.
    """
    db = SessionLocal()
    try:
        local_tz = pytz.timezone(get_system_timezone())
        now = datetime.now(local_tz)
        scheduled_scans = db.query(ScheduledScan).filter(ScheduledScan.start_datetime <= now).all()

        for sscan in scheduled_scans:
            logger.info(f"Queuing scheduled scan {sscan.id} for execution")
            scan_id = f"scheduled-{sscan.id}-{now.strftime('%Y%m%d%H%M%S')}"
            targets = sscan.get_targets()
            for target in targets:
                ensure_asset_exists(target, last_scanned=datetime.utcnow())
            if isinstance(targets, str):
                targets = json.loads(targets)
            scan_type = "full"  # or "discovery", "web", etc. -- set as appropriate
            insert_scan(scan_id, targets, now, scan_type=scan_type)  # <-- Pass scan_type!
            run_scan.delay({"scan_id": scan_id, "targets": targets})

            # Reschedule for one week later (customize as needed)
            sscan.start_datetime = now + timedelta(days=7)
            db.commit()
            send_syslog_message(json.dumps(targets), db)
    except Exception as e:
        logger.error(f"Error in processing scheduled scans: {e}", exc_info=True)
        db.rollback()
    finally:
        db.close()

@shared_task
def run_nmap_discovery(scan_id: int, target: str):
    """
    Run Nmap discovery (-sn) scan and save discovered hosts.
    """
    session = SessionLocal()
    try:
        scan = session.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error(f"Nmap discovery scan ID {scan_id} not found.")
            return
        scan.status = "running"
        session.commit()
        if isinstance(target, str):
            ensure_asset_exists(target)
        elif isinstance(target, list):
            for t in target:
                ensure_asset_exists(t)
        result = subprocess.run(
            ["nmap", "-sn", target, "-oX", "-"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            scan.status = "failed"
            session.commit()
            logger.error(f"Nmap discovery scan failed for target {target}")
            return

        import xml.etree.ElementTree as ET
        root = ET.fromstring(result.stdout)
        discovered_hosts = []
        for host in root.findall("host"):
            status = host.find("status").get("state")
            addr = host.find("address")
            ip = addr.get("addr") if addr is not None else None
            if ip:
                discovery = DiscoveryHost(ip_address=ip, status=status, scan_id=scan.id)
                session.add(discovery)
                discovered_hosts.append({"ip": ip, "status": status})

        # Save discovered hosts to scan.raw_data
        scan.raw_data = discovered_hosts
        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        session.commit()

        send_syslog_message(json.dumps({
            "id": scan.id,
            "targets": scan.targets,
            "status": scan.status,
            "started_at": str(scan.started_at),
            "completed_at": str(scan.completed_at),
            "discovered_hosts": discovered_hosts
        }), session)
    except Exception as e:
        logger.error(f"Error during Nmap discovery scan {scan_id}: {e}", exc_info=True)
        if scan:
            scan.status = "failed"
            session.commit()
    finally:
        session.close()

@shared_task
def run_nmap_scan(scan_id: str, target: str, ports: str = None):
    """
    Run full Nmap scan and hand off results to run_scan task.
    """
    session = SessionLocal()
    try:
        scan = session.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error(f"Scan ID {scan_id} not found.")
            return

        scan.status = "running"
        session.commit()

        # Always decode scan.targets to a list
        targets = scan.targets
        if isinstance(targets, str):
            try:
                targets = json.loads(targets)
            except Exception:
                targets = [targets]
        logger.info(f"Decoded targets for scan {scan_id}: {targets} (type: {type(targets)})")
        logger.info(f"Running Nmap scan for targets: {targets}")

        nmap_runner = NmapRunner(targets, ports=ports)  # Pass the full list
        findings = nmap_runner.run()

        for t in targets:
            ensure_asset_exists(t)

        # Pass all targets to run_scan
        run_scan.delay({"scan_id": scan_id, "targets": targets})

        send_syslog_message(json.dumps({
            "id": scan.id,
            "targets": scan.targets,
            "status": scan.status,
            "started_at": str(scan.started_at),
            "completed_at": str(scan.completed_at),
            "findings": findings
        }), session)

    except Exception as e:
        logger.error(f"Error during Nmap scan for {scan_id}: {e}", exc_info=True)
        if scan:
            scan.status = "failed"
            session.commit()
    finally:
        session.close()

@shared_task
def run_zap_scan(scan_id: int, zap_output_path: str = None, target_url: str = None):
    session = SessionLocal()
    scan = None
    try:
        os.makedirs(ZAP_RESULTS_DIR, exist_ok=True)
        if not zap_output_path:
            zap_output_path = os.path.join(ZAP_RESULTS_DIR, f"{scan_id}.json")

        scan = session.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error(f"Scan ID {scan_id} not found for ZAP scan.")
            return

        scan.status = "running"
        session.commit()

        if not target_url:
            raise ValueError("Target URL is required for ZAP scan.")

        # Normalize and validate the target URL
        normalized_target = normalize_url(target_url)
        logger.info(f"Starting ZAP active scan for target: {normalized_target}")

        # Create new context for this scan
        context_name = f"scan_{scan_id}"
        context_id = zap.context.new_context(context_name)
        logger.info(f"Created new context {context_name} with ID {context_id}")

        # Add target URL to context
        zap.context.include_in_context(context_name, f".*{re.escape(normalized_target)}.*")
        logger.info(f"Added {normalized_target} to context {context_name}")

        # Start spider scan first
        logger.info(f"Starting spider scan for {normalized_target}")
        spider_scan_id = zap.spider.scan(url=normalized_target, contextname=context_name)
        
        # Wait for spider to complete
        while int(zap.spider.status(spider_scan_id)) < 100:
            logger.info(f"Spider progress: {zap.spider.status(spider_scan_id)}%")
            time.sleep(2)

        logger.info("Spider scan completed, starting active scan")

        # Start active scan using context
        zap_scan_id = zap.ascan.scan(
            url=normalized_target,
            contextid=context_id,
            recurse=True
        )

        if not zap_scan_id or zap_scan_id == "url_not_found":
            raise ValueError(f"Failed to start ZAP scan for target: {normalized_target}")

        logger.info(f"Active scan started with ID: {zap_scan_id}")

        timeout_seconds = 600
        poll_interval = 5
        waited = 0

        # Wait for scan completion
        while waited < timeout_seconds:
            time.sleep(poll_interval)
            status = zap.ascan.status(zap_scan_id)
            if status and status.isdigit():
                progress = int(status)
                logger.info(f"ZAP scan progress: {progress}%")
                if progress >= 100:
                    break
            waited += poll_interval

        # Get scan results
        alerts = zap.core.alerts(baseurl=normalized_target)
        if isinstance(target_url, list):
            target_url = target_url[0]
        # Format results similar to nmap findings
        findings = [{
            "ip": target_url,
            "hostname": urlparse(target_url).netloc,
            "vulnerabilities": [
                {
                    "id": alert.get('alertRef', 'ZAP-' + str(idx)),
                    "description": alert.get('description', ''),
                    "severity": alert.get('risk', 'Unknown')
                }
                for idx, alert in enumerate(alerts)
            ]
        }]

        # Save results to file
        with open(zap_output_path, "w") as f:
            json.dump(findings, f)
        
        # Update scan record
        scan.raw_data = findings
        scan.status = "completed"
        scan.completed_at = datetime.now(pytz.timezone(get_system_timezone()))
        session.commit()

        # Create findings records
        for finding in findings:
            db_finding = Finding(
                scan_id=scan_id,
                ip_address=finding['ip'],
                hostname=finding['hostname'],
                raw_data=json.dumps(finding),
                description="\n".join(v['description'] for v in finding['vulnerabilities'])
            )
            session.add(db_finding)
            send_syslog_message(json.dumps(finding), session)
        session.commit()

    except Exception as e:
        logger.error(f"Error running ZAP scan for scan_id {scan_id}: {e}", exc_info=True)
        if scan:
            scan.status = "failed"
            session.commit()
    finally:
        session.close()
