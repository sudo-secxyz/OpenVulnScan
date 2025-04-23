# OpenVulnScan/utils/cve_checker.py

import requests
from utils.settings import CVE_API_URL

OSV_API_URL = CVE_API_URL

def check_cves_for_package(name: str, version: str):
    payload = {
        "package": {
            "name": name,
            "ecosystem": "Debian"
        },
        "version": version
    }

    try:
        response = requests.post(OSV_API_URL, json=payload)
        if response.status_code == 200:
            data = response.json()
            return data.get("vulns", [])
        else:
            print(f"Failed to fetch CVEs for {name}: {response.text}")
            return []
    except Exception as e:
        print(f"Error checking CVEs for {name}: {e}")
        return []
