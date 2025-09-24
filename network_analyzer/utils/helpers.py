"""
Helper functions for network analysis.
"""

import re
from datetime import datetime, timezone
from typing import Dict, Any
from ipaddress import ip_address

def is_private_ip(ip: str) -> bool:
    """Check if an IP address is private."""
    try:
        addr = ip_address(ip)
        return addr.is_private
    except Exception:
        return False

def now_iso() -> str:
    """Get current time in ISO format with UTC timezone."""
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

def safe_decode_bytes(data: bytes) -> str:
    """Safely decode bytes to string, ignoring errors."""
    try:
        return data.decode('utf-8', errors='ignore')
    except Exception:
        return ''

def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    
    from collections import Counter
    from math import log2
    
    counts = Counter(s)
    total = float(len(s))
    entropy = 0.0
    
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * log2(p)
    
    return entropy

def get_memory_usage() -> float:
    """Get current memory usage in MB."""
    import psutil
    return psutil.Process().memory_info().rss / (1024 * 1024)
            
    return entropy

def format_bytes(bytes: int) -> str:
    """Format bytes into human readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes < 1024:
            return f"{bytes:.2f} {unit}"
        bytes /= 1024
    return f"{bytes:.2f} PB"

def format_duration(seconds: float) -> str:
    """Format duration in seconds to human readable string."""
    units = [('d', 86400), ('h', 3600), ('m', 60), ('s', 1)]
    parts = []
    
    for unit, div in units:
        amount = int(seconds / div)
        if amount > 0:
            parts.append(f"{amount}{unit}")
            seconds %= div
            
    return ' '.join(parts) if parts else '0s'
