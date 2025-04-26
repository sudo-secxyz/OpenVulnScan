# OpenVulnScan/utils/cve_checker.py

import requests
import httpx
from utils import config  # Direct import of config, not settings

async def check_cve_api(package_name, version):
    query = {
        "package": {"name": package_name, "ecosystem": "Debian"},
        "version": version
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(config.CVE_API_URL, json=query)
        response.raise_for_status()
        data = response.json()
        return data.get("vulns", [])
