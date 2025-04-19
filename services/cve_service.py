# services/cve_service.py
import requests

def get_cve_description(cve_id: str) -> str:
    """Fetch CVE description from the NVD API"""
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
        res = requests.get(url, timeout=5)
        if res.status_code == 200:
            data = res.json()
            return data['result']['CVE_Items'][0]['cve']['description']['description_data'][0]['value']
    except Exception as e:
        print(f"Error fetching CVE description: {e}")
        return "Description not available."
    return "Description not found."