"""
This module contains models for various network traffic alerts.
"""

from dataclasses import dataclass
from typing import Dict, List
from datetime import datetime, timezone

@dataclass
class PortScanAlert:
    """Alert for detected port scanning behavior."""
    timestamp: float
    source_ip: str
    destination_ip: str
    unique_ports_in_window: int
    window_seconds: int
    reason: str = 'Port scanning behavior detected'

@dataclass
class CredentialLeakAlert:
    """Alert for detected credential leaks."""
    timestamp: float
    source_ip: str
    destination_ip: str
    protocol: str
    indicator: str
    reason: str = 'Cleartext credentials or auth indicators found'

@dataclass
class SuspiciousDNSAlert:
    """Alert for suspicious DNS activity."""
    timestamp: float
    source_ip: str
    destination_ip: str
    query: str
    length: int
    entropy: float
    reason: str = 'Suspicious DNS query likely DGA or randomized'

@dataclass
class DataExfilAlert:
    """Alert for potential data exfiltration."""
    host: str
    bytes_out: int
    bytes_in: int
    upload_download_ratio: float
    threshold_ratio: float
    min_out_bytes: int
    reason: str = 'Abnormally high upload-to-download ratio'

@dataclass
class UncommonPortAlert:
    """Alert for connections on uncommon ports."""
    timestamp: float
    source_ip: str
    destination_ip: str
    protocol: str
    port: int
    observed_count: int
    reason: str = 'Connection on uncommon/non-standard port'

@dataclass
class MalwareAlert:
    """Alert for potential malware indicators in traffic payloads."""
    timestamp: float
    source_ip: str
    destination_ip: str
    indicator: str
    signature: str
    severity: str = 'HIGH'

@dataclass
class DetectionReport:
    """Container for all detection results."""
    timestamp: str
    stats: Dict[str, int]
    protocol_stats: Dict[str, Dict]
    port_scan_alerts: List[dict]
    credential_alerts: List[dict]
    suspicious_dns_alerts: List[dict]
    data_exfil_alerts: List[dict]
    uncommon_port_alerts: List[dict]
    malware_alerts: List[dict]
    flows: List[Dict]
    metrics: Dict[str, any]
    http_requests: List[Dict]
