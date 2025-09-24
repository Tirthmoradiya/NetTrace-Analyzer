"""
Threat intelligence integration module.
"""

import aiohttp
import json
from typing import Dict, List, Optional, Set
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class ThreatIntelligence:
    """Integrates with threat intelligence sources."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.cache: Dict[str, Dict] = {}
        self.cache_expiry: Dict[str, datetime] = {}
        self.known_malicious: Set[str] = set()
        self.cache_duration = timedelta(hours=24)
        
    async def check_ip(self, ip: str) -> Dict:
        """Check if an IP is known to be malicious."""
        # Check cache first
        if ip in self.cache:
            if datetime.now() < self.cache_expiry[ip]:
                return self.cache[ip]
            else:
                del self.cache[ip]
                del self.cache_expiry[ip]
        
        try:
            # Example API call to AbuseIPDB
            if self.api_key:
                async with aiohttp.ClientSession() as session:
                    params = {
                        'ipAddress': ip,
                        'maxAgeInDays': 30,
                        'verbose': True
                    }
                    headers = {
                        'Key': self.api_key,
                        'Accept': 'application/json'
                    }
                    async with session.get(
                        'https://api.abuseipdb.com/api/v2/check',
                        params=params,
                        headers=headers
                    ) as response:
                        if response.status == 200:
                            result = await response.json()
                            self._cache_result(ip, result)
                            return result
            
            # Fallback to local threat intelligence
            return self._check_local_intel(ip)
            
        except Exception as e:
            logger.error(f"Error checking threat intelligence for {ip}: {e}")
            return {'error': str(e)}
    
    def _cache_result(self, ip: str, result: Dict) -> None:
        """Cache the threat intelligence result."""
        self.cache[ip] = result
        self.cache_expiry[ip] = datetime.now() + self.cache_duration
        
        # Update known malicious IPs
        if self._is_malicious(result):
            self.known_malicious.add(ip)
    
    def _is_malicious(self, result: Dict) -> bool:
        """Determine if an IP is malicious based on threat intel."""
        # Example logic - customize based on your needs
        confidence_threshold = 80
        return (
            result.get('abuseConfidenceScore', 0) > confidence_threshold or
            result.get('totalReports', 0) > 10
        )
    
    def _check_local_intel(self, ip: str) -> Dict:
        """Check IP against local threat intelligence."""
        return {
            'ip': ip,
            'isKnownMalicious': ip in self.known_malicious,
            'source': 'local',
            'timestamp': datetime.now().isoformat()
        }
    
    def add_local_intel(self, ip: str, intel: Dict) -> None:
        """Add local threat intelligence data."""
        self.cache[ip] = intel
        self.cache_expiry[ip] = datetime.now() + self.cache_duration
        if intel.get('malicious', False):
            self.known_malicious.add(ip)
            
    def load_blocklist(self, filepath: str) -> None:
        """Load IPs from a blocklist file."""
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if ip and not ip.startswith('#'):
                        self.known_malicious.add(ip)
        except Exception as e:
            logger.error(f"Error loading blocklist {filepath}: {e}")
            
    def load_whitelist(self, filepath: str) -> None:
        """Load IPs from a whitelist file."""
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if ip and not ip.startswith('#'):
                        if ip in self.known_malicious:
                            self.known_malicious.remove(ip)
        except Exception as e:
            logger.error(f"Error loading whitelist {filepath}: {e}")
            
    async def bulk_check(self, ips: List[str]) -> Dict[str, Dict]:
        """Check multiple IPs in bulk."""
        results = {}
        for ip in ips:
            results[ip] = await self.check_ip(ip)
        return results
