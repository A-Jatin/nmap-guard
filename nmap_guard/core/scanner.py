"""
Scanner module for NMAP-Guard.
"""

import nmap
import json
from typing import Dict, List, Optional
from ..core.config import settings
from ..utils.logging import get_logger

logger = get_logger(__name__)

class Scanner:
    """Scanner class for running NMAP scans."""
    
    def __init__(self):
        self.max_concurrent_scans = settings.MAX_CONCURRENT_SCANS
        self.default_timeout = settings.DEFAULT_SCAN_TIMEOUT
        self.nm = nmap.PortScanner()
    
    def run_scan(self, target: str, options: Optional[Dict] = None) -> Dict:
        """
        Run an NMAP scan with the given options.
        
        Args:
            target: The target to scan (IP address or hostname)
            options: Dictionary of NMAP options
            
        Returns:
            Dictionary containing scan results
        """
        try:
            # Build scan arguments
            arguments = "-sS "  # Default to SYN scan
            if options:
                if options.get("ports"):
                    arguments += f"-p {options['ports']} "
                if options.get("timing"):
                    arguments += f"-T{str(options['timing'])} " # Ensure timing is a string
                if options.get("script"):
                    arguments += f"--script {options['script']} "
                if options.get("os_detection"):
                    arguments += "-O "
                if options.get("service_detection"):
                    arguments += "-sV "

            # CRITICAL FIX: Ensure "-oX -" is not passed to python-nmap, 
            # as it handles XML output internally for parsing via get_nmap_last_output().
            if "-oX -" in arguments:
                logger.warning("Detected potentially problematic '-oX -' in arguments. Removing it to allow python-nmap to manage XML output.")
                arguments = arguments.replace("-oX -", "")
                arguments = ' '.join(arguments.split()) # Clean up any extra spaces resulting from replacement
            
            logger.info(f"Starting scan of {target} with final arguments: {arguments}")
            self.nm.scan(target, arguments=arguments)
            
            # Get scan results using the method suggested in the error message
            scan_data = self.nm.get_nmap_last_output()
            
            # Get structured data from the scan
            scan_results = {}
            for host in self.nm.all_hosts():
                host_data = self.nm[host]
                scan_results[host] = {
                    'status': host_data.state(),
                    'hostnames': host_data.get('hostnames', []),
                    'ports': {}
                }
                
                # Get port information
                for proto in host_data.all_protocols():
                    ports = host_data[proto]
                    for port, port_data in ports.items():
                        scan_results[host]['ports'][port] = {
                            'state': port_data['state'],
                            'name': port_data.get('name', ''),
                            'product': port_data.get('product', ''),
                            'version': port_data.get('version', '')
                        }
            
            return {
                "status": "completed",
                "raw_output": scan_data,
                "results": scan_results
            }
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            raise
    
    def _parse_nmap_output(self, output: str) -> Dict:
        """Parse NMAP output into a structured format."""
        try:
            # Basic parsing of NMAP output
            lines = output.split('\n')
            hosts_up = 0
            ports_open = 0
            services_found = 0
            current_host = None
            
            for line in lines:
                line = line.strip()
                if "Nmap scan report for" in line:
                    hosts_up += 1
                    current_host = line.split("for")[-1].strip()
                elif "open" in line and "tcp" in line:
                    ports_open += 1
                    if "service" in line:
                        services_found += 1
            
            return {
                "status": "completed",
                "raw_output": output,
                "summary": {
                    "hosts_up": hosts_up,
                    "ports_open": ports_open,
                    "services_found": services_found
                }
            }
        except Exception as e:
            logger.error(f"Failed to parse NMAP output: {str(e)}")
            raise 