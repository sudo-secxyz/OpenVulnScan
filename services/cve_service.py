# services/cve_service.py
import requests
import os
from database.ops import get_cve_by_id, Session
from utils.config import CVE_API_URL
from config import setup_logging
logger = setup_logging()

def get_cve_details(cve_id: str) -> dict:
    """Fetch CVE details from the OSV API."""
    if not cve_id or not cve_id.startswith("CVE-"):
        return {
            "description": "Invalid CVE ID.",
            "severity": None,
            "remediation": None
        }
    try:
        res = requests.get(f"https://api.osv.dev/v1/vulns/{cve_id}", timeout=10)
        if res.status_code == 200:
            vuln = res.json()
            description = vuln.get("details", "No description available.")
            severity = None
            remediation = None

            if "severity" in vuln and vuln["severity"]:
                severity = vuln["severity"][0].get("type") + ": " + vuln["severity"][0].get("score")
            if "references" in vuln and vuln["references"]:
                remediation = vuln["references"][0].get("url")

            return {
                "description": description,
                "severity": severity,
                "remediation": remediation
            }
        elif res.status_code == 404:
            logger.warning(f"OSV API: CVE {cve_id} not found")
        else:
            logger.warning(f"OSV API error for {cve_id}: HTTP {res.status_code}")
    except Exception as e:
        logger.error(f"Exception fetching CVE {cve_id} from OSV: {e}")
    return {
        "description": "CVE not found in OSV.",
        "severity": None,
        "remediation": None
    }

def get_cve_description_from_db(db: Session, cve_id: str) -> str:
    cve = get_cve_by_id(db, cve_id)
    if cve and cve.description:
        return cve.description
    return "Description not found in database."