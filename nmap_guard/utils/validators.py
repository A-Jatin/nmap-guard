"""
Input validation utilities for NMAP-Guard.
"""

import re
import ipaddress
from typing import Union, List, Optional
from .exceptions import ValidationError

def validate_ip_address(ip: str) -> bool:
    """
    Validate an IP address (IPv4 or IPv6).
    
    Args:
        ip: IP address to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_ip_network(network: str) -> bool:
    """
    Validate an IP network (CIDR notation).
    
    Args:
        network: Network in CIDR notation
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        ipaddress.ip_network(network, strict=False)
        return True
    except ValueError:
        return False

def validate_hostname(hostname: str) -> bool:
    """
    Validate a hostname.
    
    Args:
        hostname: Hostname to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    hostname_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return bool(hostname_pattern.match(hostname))

def validate_port(port: Union[str, int]) -> bool:
    """
    Validate a port number or port range.
    
    Args:
        port: Port number or range (e.g., "80" or "80-443")
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        if isinstance(port, int):
            return 1 <= port <= 65535
        
        if '-' in port:
            start, end = map(int, port.split('-'))
            return 1 <= start <= end <= 65535
        
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False

def validate_ports(ports: str) -> bool:
    """
    Validate port specification.
    
    Args:
        ports: Port specification (e.g., "80,443,8000-8080")
        
    Returns:
        bool: True if valid, False otherwise
    """
    if not ports:
        return False
    
    # Split ports by comma
    port_list = [p.strip() for p in ports.split(',')]
    
    for port in port_list:
        # Check if it's a port range
        if '-' in port:
            try:
                start, end = map(int, port.split('-'))
                if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                    return False
            except ValueError:
                return False
        # Check if it's a single port
        else:
            try:
                port_num = int(port)
                if not 1 <= port_num <= 65535:
                    return False
            except ValueError:
                return False
    
    return True

def validate_targets(targets: str) -> bool:
    """
    Validate target specification.
    
    Args:
        targets: Target specification (IP addresses, hostnames, networks)
        
    Returns:
        bool: True if valid, False otherwise
    """
    if not targets:
        return False
    
    # Split targets by comma
    target_list = [t.strip() for t in targets.split(',')]
    
    for target in target_list:
        # Check if it's a valid IP address or network
        try:
            ipaddress.ip_network(target, strict=False)
            continue
        except ValueError:
            pass
        
        # Check if it's a valid hostname
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', target):
            return False
    
    return True

def validate_scan_type(scan_type: str) -> bool:
    """
    Validate scan type.
    
    Args:
        scan_type: Type of scan ("basic", "stealth", "comprehensive")
        
    Returns:
        bool: True if valid, False otherwise
    """
    return scan_type in ["basic", "stealth", "comprehensive"]

def validate_timing_template(timing: int) -> bool:
    """
    Validate timing template.
    
    Args:
        timing: NMAP timing template (0-5)
        
    Returns:
        bool: True if valid, False otherwise
    """
    return 0 <= timing <= 5

def validate_schedule(schedule: Optional[str]) -> bool:
    """
    Validate cron schedule expression.
    
    Args:
        schedule: Cron expression
        
    Returns:
        bool: True if valid, False otherwise
    """
    if not schedule:
        return True
    
    # Basic cron expression validation
    parts = schedule.split()
    if len(parts) != 5:
        return False
    
    # Validate each part
    for part in parts:
        if not re.match(r'^(\*|[0-9]{1,2}(-[0-9]{1,2})?(,[0-9]{1,2})*|\*/[0-9]{1,2})$', part):
            return False
    
    return True

def validate_credentials(credentials: dict) -> bool:
    """
    Validate scan credentials.
    
    Args:
        credentials: Dictionary containing credential information
        
    Returns:
        bool: True if valid, False otherwise
    """
    required_fields = {'type', 'username'}
    
    if not all(field in credentials for field in required_fields):
        return False
        
    # Validate credential type
    valid_types = {'ssh', 'winrm', 'snmp'}
    if credentials['type'] not in valid_types:
        return False
        
    # Type-specific validation
    if credentials['type'] in {'ssh', 'winrm'}:
        if 'password' not in credentials and 'key_file' not in credentials:
            return False
            
    elif credentials['type'] == 'snmp':
        if 'community' not in credentials and 'version' not in credentials:
            return False
            
    return True 