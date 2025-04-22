import requests
import json
import os
import platform
import subprocess

# Define the OpenVulnScan API URL (adjust this if using a different host or port)
API_URL = "http://<your_openvulnscan_host>:8000/agent/report"

def get_installed_packages():
    """Get installed packages based on OS."""
    packages = []

    # For Linux (Debian/Ubuntu-based)
    if platform.system() == "Linux":
        try:
            # Get installed packages via dpkg for Debian/Ubuntu
            result = subprocess.run(['dpkg', '-l'], stdout=subprocess.PIPE)
            output = result.stdout.decode('utf-8').splitlines()

            for line in output:
                if line.startswith("ii"):
                    parts = line.split()
                    package_name = parts[1]
                    package_version = parts[2]
                    packages.append({"name": package_name, "version": package_version})

        except Exception as e:
            print(f"Error fetching packages: {e}")

    return packages

def get_system_info():
    """Collect system information."""
    system_info = {
        "hostname": platform.node(),
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine()
    }
    return system_info

def report_to_server():
    """Send the system data to the OpenVulnScan server."""
    data = {
        **get_system_info(),
        "packages": get_installed_packages()
    }

    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(API_URL, json=data, headers=headers)
        if response.status_code == 200:
            print("Report successfully sent to OpenVulnScan.")
        else:
            print(f"Failed to send report. Status code: {response.status_code}")
            print(response.text)
    except requests.exceptions.RequestException as e:
        print(f"Error sending report: {e}")

if __name__ == "__main__":
    report_to_server()
