"""
Core scanner module for NMAP-Guard.
Provides the main scanning functionality using python-nmap.
"""

import logging
import nmap
from typing import Dict, List, Optional, Union
from datetime import datetime
from ..utils.exceptions import ScanError
from ..utils.validators import validate_targets, validate_ports
from ..utils.encryption import decrypt_data

logger = logging.getLogger(__name__)

class NmapScanner:
    """
    Core NMAP scanner class that handles scan execution and result parsing.
    """
    
    def __init__(self):
        """Initialize the NmapScanner with a new PortScanner instance."""
        try:
            self.nm = nmap.PortScanner()
            logger.info("NmapScanner initialized successfully")
        except nmap.PortScannerError as e:
            logger.error(f"Failed to initialize NmapScanner: {e}")
            raise ScanError("NMAP not found or not accessible")

    def validate_scan_params(self, targets: str, ports: Optional[str] = None) -> None:
        """
        Validate scan parameters before execution.
        
        Args:
            targets: Target specification (IP addresses, hostnames, networks)
            ports: Port specification
            
        Raises:
            ValueError: If parameters are invalid
        """
        if not validate_targets(targets):
            raise ValueError("Invalid target specification")
        if ports and not validate_ports(ports):
            raise ValueError("Invalid port specification")

    def build_scan_arguments(self, 
                           scan_type: str = "basic",
                           timing_template: int = 3,
                           service_detection: bool = True,
                           os_detection: bool = False,
                           script_scan: bool = False) -> str:
        """
        Build NMAP command arguments based on scan configuration.
        
        Args:
            scan_type: Type of scan ("basic", "stealth", "comprehensive")
            timing_template: NMAP timing template (0-5)
            service_detection: Whether to detect service versions
            os_detection: Whether to perform OS detection
            script_scan: Whether to run default NSE scripts
            
        Returns:
            str: NMAP command arguments
        """
        args = []
        
        # Base scan type
        if scan_type == "stealth":
            args.append("-sS")  # SYN scan
        elif scan_type == "comprehensive":
            args.append("-sS -A")  # SYN scan with advanced options
        else:  # basic
            args.append("-sS")  # Default to SYN scan
            
        # Timing template
        timing_template = max(0, min(timing_template, 5))  # Ensure valid range
        args.append(f"-T{timing_template}")
        
        # Service detection
        if service_detection:
            args.append("-sV")
            
        # OS detection
        if os_detection:
            args.append("-O")
            
        # Script scan
        if script_scan:
            args.append("-sC")  # Equivalent to --script=default
            
        # Always output in XML format
        args.append("-oX -")
        
        return " ".join(args)

    async def scan(self,
                  targets: str,
                  ports: Optional[str] = None,
                  scan_type: str = "basic",
                  timing_template: int = 3,
                  credentials: Optional[Dict] = None) -> Dict:
        """
        Execute an NMAP scan with the specified parameters.
        
        Args:
            targets: Target specification
            ports: Port specification (optional)
            scan_type: Type of scan
            timing_template: NMAP timing template
            credentials: Optional credentials for authenticated scans
            
        Returns:
            Dict: Scan results
        """
        try:
            # Validate parameters
            self.validate_scan_params(targets, ports)
            
            # Build scan arguments
            args = self.build_scan_arguments(
                scan_type=scan_type,
                timing_template=timing_template
            )
            
            # Add port specification if provided
            if ports:
                args += f" -p {ports}"
                
            # Handle credentials if provided
            if credentials:
                decrypted_creds = decrypt_data(credentials)
                # Add credential-specific arguments based on protocol
                # This is a placeholder - actual implementation would depend on scan type
                
            logger.info(f"Starting scan of {targets} with arguments: {args}")
            scan_start_time = datetime.utcnow()
            
            # Execute the scan
            result = self.nm.scan(hosts=targets, arguments=args)
            
            scan_end_time = datetime.utcnow()
            scan_duration = (scan_end_time - scan_start_time).total_seconds()
            
            # Process and structure the results
            processed_results = self.process_scan_results(result)
            
            # Add metadata
            processed_results['metadata'] = {
                'start_time': scan_start_time.isoformat(),
                'end_time': scan_end_time.isoformat(),
                'duration': scan_duration,
                'targets': targets,
                'scan_type': scan_type,
                'arguments': args
            }
            
            logger.info(f"Scan completed successfully in {scan_duration} seconds")
            return processed_results
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            raise ScanError(f"Scan failed: {str(e)}")

    def process_scan_results(self, raw_results: Dict) -> Dict:
        """
        Process and structure raw NMAP scan results.
        
        Args:
            raw_results: Raw scan results from NMAP
            
        Returns:
            Dict: Processed and structured results
        """
        processed_results = {
            'hosts': [],
            'summary': {
                'total_hosts': 0,
                'up_hosts': 0,
                'down_hosts': 0
            }
        }
        
        try:
            # Process each host
            for host in self.nm.all_hosts():
                host_info = {
                    'address': host,
                    'status': self.nm[host].state(),
                    'hostnames': self.nm[host].hostnames(),
                    'protocols': {}
                }
                
                # Process protocols (tcp, udp, etc.)
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    host_info['protocols'][proto] = []
                    
                    # Process ports
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        port_data = {
                            'port': port,
                            'state': port_info['state'],
                            'service': port_info.get('name', ''),
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', '')
                        }
                        host_info['protocols'][proto].append(port_data)
                
                processed_results['hosts'].append(host_info)
                
                # Update summary
                if self.nm[host].state() == 'up':
                    processed_results['summary']['up_hosts'] += 1
                else:
                    processed_results['summary']['down_hosts'] += 1
                    
            processed_results['summary']['total_hosts'] = len(self.nm.all_hosts())
            
            return processed_results
            
        except Exception as e:
            logger.error(f"Error processing scan results: {str(e)}")
            raise ScanError(f"Failed to process scan results: {str(e)}")

    def get_available_scripts(self) -> List[str]:
        """
        Get a list of available NSE scripts.
        
        Returns:
            List[str]: List of available script names
        """
        try:
            # This is a placeholder - actual implementation would need to parse
            # the output of 'nmap --script-help all' or read from the scripts directory
            return ["http-title", "ssl-cert", "banner", "vuln-basic"]
        except Exception as e:
            logger.error(f"Failed to get available scripts: {str(e)}")
            return [] 