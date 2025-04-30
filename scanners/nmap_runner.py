# scanners/nmap_runner.py
import subprocess
import re
import ipaddress
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Union, Optional


class NmapRunner:
    def __init__(self, targets: List[str]):
        """
        Initialize the NmapRunner with a list of target IPs or hostnames
        
        Args:
            targets: List of IP addresses, hostnames, or CIDR notations to scan
        """
        self.targets = targets
        
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
            
        # Convert list of targets to comma-separated string
        target_str = ','.join(self.targets)
        
        # Build the nmap command with XML output for easier parsing
        cmd = ["nmap", "-oX", "-"]  # Output XML to stdout
        
        # Add user specified options if provided
        if options:
            cmd.extend(options)
        else:
            # Default options if none specified
            cmd.extend(["-sV", "--script vulners"])  # Version detection and vulnerability scanning
            
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
                return [f"Nmap scan failed: {stderr}"]
                
            # Parse the output to get findings
            return self._parse_nmap_output(stdout)
            
        except FileNotFoundError:
            return ["Error: Nmap not found. Please ensure Nmap is installed and in your PATH."]
        except Exception as e:
            return [f"Error executing Nmap scan: {str(e)}"]
    
    def _parse_nmap_output(self, output: str) -> List[str]:
        """
        Parse the nmap XML output to extract findings
        
        Args:
            output: The XML output from Nmap
            
        Returns:
            List of findings from the scan
        """
        findings = []
        
        try:
            # Parse XML output
            root = ET.fromstring(output)
            
            # Check if we have scan results
            if root.tag != 'nmaprun':
                return ["Invalid Nmap output format"]
                
            # Extract host information
            for host in root.findall('./host'):
                # Get address
                addr = host.find('./address').get('addr', 'unknown')
                
                # Check if host is up
                status = host.find('./status')
                if status is None or status.get('state') != 'up':
                    findings.append(f"Host {addr} appears to be down")
                    continue
                    
                findings.append(f"Host {addr} is up")
                
                # Extract hostname if available
                hostnames = host.findall('./hostnames/hostname')
                if hostnames:
                    for hostname in hostnames:
                        findings.append(f"Hostname: {hostname.get('name', 'unknown')}")
                
                # Extract ports and services
                for port in host.findall('./ports/port'):
                    port_id = port.get('portid', 'unknown')
                    protocol = port.get('protocol', 'unknown')
                    
                    # Get port state
                    state = port.find('./state')
                    if state is not None and state.get('state') == 'open':
                        findings.append(f"Open port {port_id}/{protocol} found on {addr}")
                        
                        # Get service information
                        service = port.find('./service')
                        if service is not None:
                            service_name = service.get('name', 'unknown')
                            product = service.get('product', '')
                            version = service.get('version', '')
                            
                            if product or version:
                                service_detail = f"Service on port {port_id}: {service_name}"
                                if product:
                                    service_detail += f" ({product}"
                                    if version:
                                        service_detail += f" {version}"
                                    service_detail += ")"
                                findings.append(service_detail)
                
                # Extract script output (vulnerabilities)
                for script in host.findall('.//script'):
                    script_id = script.get('id', '')
                    output = script.get('output', '').strip()
                    
                    if script_id and 'vuln' in script_id and output:
                        # Format vulnerability output - limit to first line for brevity
                        vuln_output = output.split('\n')[0]
                        findings.append(f"Vulnerability: {script_id} - {vuln_output}")
            
            # If no findings were added, add a default message
            if not findings:
                findings.append("No significant findings from the scan")
                
        except ET.ParseError:
            # If XML parsing fails, try to extract basic information using regex
            findings.append("Warning: Could not parse XML output, falling back to basic parsing")
            
            # Extract open ports using regex
            port_pattern = r"(\d+)/(\w+)\s+(\w+)\s+(.+)"
            for line in output.split('\n'):
                if 'open' in line:
                    match = re.search(port_pattern, line)
                    if match:
                        port, proto, state, service = match.groups()
                        findings.append(f"Open port {port}/{proto} found with service {service}")
        
        return findings