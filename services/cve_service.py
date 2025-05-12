# services/cve_service.py
import requests
from database.ops import get_cve_by_id, Session

def get_cve_description(cve_id: str) -> str:
    """Fetch CVE description from the NVD API v2.0"""
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        headers = {"User-Agent": "OpenVulnScan/1.0"}
        res = requests.get(url, headers=headers, timeout=10)
        if res.status_code == 200:
            data = res.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if vulnerabilities:
                descriptions = vulnerabilities[0].get("cve", {}).get("descriptions", [])
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        return desc.get("value", "No description available.")
                return "English description not found."
            else:
                print(f"No vulnerabilities found in response for {cve_id}")
        else:
            print(f"NVD API error for {cve_id}: HTTP {res.status_code}")
    except Exception as e:
        print(f"Exception fetching CVE {cve_id}: {e}")
    return "Description not found."

def get_cve_description_from_db(db: Session, cve_id: str) -> str:
    cve = get_cve_by_id(db, cve_id)
    if cve and cve.description:
        return cve.description
    return "Description not found in database."