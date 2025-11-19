"""Sanitization utilities for security data."""

import re
from typing import Any, Dict

def sanitize_account_id(account_id: str) -> str:
    """Mask AWS account ID keeping only last 4 digits.
    
    Args:
        account_id: AWS account ID to sanitize
        
    Returns:
        Masked account ID like ACCOUNT_****1234
    """
    if not account_id or len(account_id) < 4:
        return "ACCOUNT_UNKNOWN"
    
    # Extract last 4 digits
    last_four = account_id[-4:]
    return f"ACCOUNT_****{last_four}"

def label_ip(ip: str) -> str:
    """Replace IP addresses with generic labels.
    
    Args:
        ip: IP address string
        
    Returns:
        'PUBLIC_IP' for public IPs, 'PRIVATE_IP' for RFC1918 IPs
    """
    if not ip:
        return "UNKNOWN_IP"
    
    # Check for special cases
    if ip == "0.0.0.0/0":
        return "0.0.0.0/0"  # Keep this as-is (it's the "anywhere" CIDR)
    
    # RFC1918 private IP ranges
    private_patterns = [
        r'^10\.',
        r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
        r'^192\.168\.',
        r'^127\.',
    ]
    
    # Check if it's a private IP
    for pattern in private_patterns:
        if re.match(pattern, ip):
            return "PRIVATE_IP"
    
    return "PUBLIC_IP"

def sanitize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize a security finding dictionary.
    
    Args:
        finding: Finding dictionary with potential sensitive data
        
    Returns:
        Sanitized copy of the finding
    """
    if not finding:
        return {}
    
    # Create a copy to avoid modifying the original
    sanitized = finding.copy()
    
    # Sanitize resource IDs that might contain account IDs
    if 'resource' in sanitized:
        resource = sanitized['resource']
        # Check if it looks like it contains an account ID (12 digits)
        if re.search(r'\d{12}', resource):
            # Replace the account ID portion
            sanitized['resource'] = re.sub(
                r'\d{12}',
                'ACCOUNT_MASKED',
                resource
            )
    
    # Sanitize details
    if 'details' in sanitized and isinstance(sanitized['details'], dict):
        details = sanitized['details'].copy()
        
        # Sanitize IPs in details
        for key in ['ip', 'source_ip', 'dest_ip', 'ip_address']:
            if key in details:
                details[key] = label_ip(details[key])
        
        # Keep CIDR as-is if it's 0.0.0.0/0
        if 'cidr' in details and details['cidr'] != '0.0.0.0/0':
            details['cidr'] = label_ip(details['cidr'])
            
        sanitized['details'] = details
    
    return sanitized

def sanitize_log_context(context: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize log context data.
    
    Args:
        context: Dictionary of log context fields
        
    Returns:
        Sanitized copy of the context
    """
    if not context:
        return {}
    
    sanitized = context.copy()
    
    # List of keys that might contain sensitive data
    sensitive_keys = ['account_id', 'aws_account', 'account']
    
    for key in sensitive_keys:
        if key in sanitized:
            sanitized[key] = sanitize_account_id(sanitized[key])
    
    # Sanitize any IP addresses
    ip_keys = ['ip', 'ip_address', 'source_ip', 'dest_ip']
    for key in ip_keys:
        if key in sanitized:
            sanitized[key] = label_ip(sanitized[key])
    
    return sanitized
