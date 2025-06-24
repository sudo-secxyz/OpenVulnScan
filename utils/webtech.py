# utils/webtech.py
import subprocess
import json

def whatweb_fingerprint(url):
    result = subprocess.run(
        ["whatweb", "--log-json=-", url],
        capture_output=True, text=True
    )
    try:
        return json.loads(result.stdout)
    except Exception:
        return []