import subprocess
import re

def get_system_timezone() -> str:
    try:
        output = subprocess.check_output(["timedatectl"], text=True)
        match = re.search(r'Time zone:\s+([^\s]+)', output)
        if match:
            return match.group(1)  # e.g., 'America/Phoenix'
    except Exception as e:
        print(f"Failed to get system timezone: {e}")
    return "UTC"  # Fallback