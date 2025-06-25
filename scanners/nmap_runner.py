# scanners/nmap_runner.py
import subprocess
import re
import ipaddress
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Union, Optional
from utils.webtech import whatweb_fingerprint
from services.update_asset import update_asset
import logging

logger = logging.getLogger(__name__)



class NmapRunner:
    def __init__(self, targets: List[str], ports= None):
        """
        Initialize the NmapRunner with a list of target IPs or hostnames
        
        Args:
            targets: List of IP addresses, hostnames, or CIDR notations to scan
        """
        self.targets = targets
        self.ports = ports
        
    def run(self, options: Optional[List[str]] = None) -> List[str]:
        """
        Run an Nmap scan on the specified targets with optional parameters
        
        Args:
            options: Additional Nmap options as a list of strings
            
        Returns:
            List of findings from the scan
        """
        if not self.targets:
            return ["No targets specified"]
        
        if self.ports is None:
            self.ports = "1-1000"  # Default to top 1000 ports if none specified
            
        # Convert list of targets to comma-separated string
        target_str = ','.join(self.targets)
        
        # Build the nmap command with XML output for easier parsing
        cmd = ["nmap", "-oX", "-"]  # Output XML to stdout
        
        # Add user specified options if provided
        if options:
            cmd.extend(options)
        else:
            # Default options if none specified
            cmd.extend(["-sV", "-O", "--script=vulners"])
            if self.ports:
                cmd.extend(["-p", str(self.ports)])
            cmd.extend(["-T4", "-A", "-R"])  # Version detection and vulnerability scanning
            
        # Add targets
        cmd.append(target_str)
        
        try:
            # Execute nmap and capture output
            
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Nmap scan failed: {stderr}")
                return []
                
            # Parse the output to get findings
            return self._parse_nmap_output(stdout)
            
        except FileNotFoundError:
            return ["Error: Nmap not found. Please ensure Nmap is installed and in your PATH."]
        except Exception as e:
            return [f"Error executing Nmap scan: {str(e)}"]
    
    def _parse_nmap_output(self, output: str) -> List[Dict[str, Any]]:
        results = []

        try:
            root = ET.fromstring(output)
            if root.tag != 'nmaprun':
                return []

            for host in root.findall('./host'):
                status = host.find('./status')
                if status is None or status.get('state') != 'up':
                    continue

                addr = host.find('./address').get('addr', 'unknown')
                hostname_elem = host.find('./hostnames/hostname')
                hostname = hostname_elem.get('name') if hostname_elem is not None else ""

                open_ports = []
                for port in host.findall('./ports/port'):
                    if port.find('./state').get('state') == 'open':
                        open_ports.append({
                            "port": port.get("portid"),
                            "protocol": port.get("protocol"),
                            "service": port.find('./service').get('name', 'unknown')
                        })
                
                # OS detection
                os_elem = host.find('.//osmatch')
                os_name = os_elem.get('name') if os_elem is not None else None

                vulnerabilities = []
                for script in host.findall('.//script'):
                    script_id = script.get('id', '')
                    output = script.get('output', '').strip()
                    if script_id == 'vulners' and output:
                        # Try to extract CVEs from the output
                        cves = re.findall(r'CVE-\d{4}-\d{4,7}', output)
                        for cve in cves:
                            vulnerabilities.append({
                                "id": cve,
                                "description": f"Detected by vulners script: {cve}"
                            })
                services = []
                for port in host.findall(".//port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        service = port.find("service")
                        services.append({
                            "port": int(port.get("portid")),
                            "service": service.get("name") if service is not None else "",
                            "product": service.get("product") if service is not None else ""
                        })
                web_tech = None
                for svc in services:
                    if svc["service"] in ("http", "https"):
                        web_tech = whatweb_fingerprint(f"http://{addr}")
                        break
                update_asset(addr, os_name, services, web_tech=web_tech)
                results.append({
                    "ip": addr,
                    "hostname": hostname,
                    "os": os_name,
                    "open_ports": open_ports,
                    "vulnerabilities": vulnerabilities,
                    "services": services,
                    "web_tech": web_tech
                })
            
            return results

        except ET.ParseError:
            return []
