"""
Advanced traffic pattern analysis module.
"""

from collections import defaultdict
from typing import Dict, List, Set, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest

class TrafficPatternAnalyzer:
    """Analyzes network traffic patterns for anomaly detection."""

    def __init__(self, time_window: int = 300):
        self.time_window = time_window
        self.flow_stats: Dict[Tuple[str, str], List[float]] = defaultdict(list)
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        
    def add_flow(self, src: str, dst: str, timestamp: float, bytes: int, 
                 protocol: str, src_port: int, dst_port: int) -> None:
        """Add a flow for analysis."""
        flow_key = (src, dst)
        self.flow_stats[flow_key].append(bytes)
        
    def detect_anomalies(self) -> List[Dict]:
        """Detect anomalous traffic patterns."""
        anomalies = []
        
        for (src, dst), stats in self.flow_stats.items():
            if len(stats) < 10:  # Need minimum samples
                continue
                
            # Prepare features
            features = np.array([
                np.mean(stats),
                np.std(stats),
                np.percentile(stats, 75),
                len(stats)
            ]).reshape(1, -1)
            
            # Detect anomalies
            prediction = self.isolation_forest.fit_predict(features)
            
            if prediction[0] == -1:  # Anomaly detected
                anomalies.append({
                    'source': src,
                    'destination': dst,
                    'avg_bytes': float(np.mean(stats)),
                    'std_bytes': float(np.std(stats)),
                    'total_flows': len(stats),
                    'reason': 'Unusual traffic pattern detected'
                })
                
        return anomalies

class BehavioralProfiler:
    """Profiles normal behavior patterns of hosts."""
    
    def __init__(self):
        self.host_profiles: Dict[str, Dict] = defaultdict(lambda: {
            'ports': set(),
            'protocols': set(),
            'peers': set(),
            'bytes_sent': [],
            'bytes_received': [],
            'active_hours': set()
        })
        
    def update_profile(self, host: str, timestamp: float, peer: str,
                      protocol: str, port: int, bytes_sent: int,
                      bytes_received: int) -> None:
        """Update host behavior profile."""
        profile = self.host_profiles[host]
        hour = int(timestamp / 3600)
        
        profile['ports'].add(port)
        profile['protocols'].add(protocol)
        profile['peers'].add(peer)
        profile['bytes_sent'].append(bytes_sent)
        profile['bytes_received'].append(bytes_received)
        profile['active_hours'].add(hour)
        
    def get_anomalies(self, confidence_threshold: float = 0.95) -> List[Dict]:
        """Detect behavioral anomalies."""
        anomalies = []
        
        for host, profile in self.host_profiles.items():
            # Check for sudden increase in peers
            if len(profile['peers']) > 100:
                anomalies.append({
                    'host': host,
                    'type': 'excessive_peers',
                    'count': len(profile['peers']),
                    'confidence': 0.98
                })
                
            # Check for unusual port usage
            if len(profile['ports']) > 50:
                anomalies.append({
                    'host': host,
                    'type': 'unusual_ports',
                    'count': len(profile['ports']),
                    'confidence': 0.96
                })
                
            # Check for unusual active hours
            if len(profile['active_hours']) > 20:  # Active more than 20 hours
                anomalies.append({
                    'host': host,
                    'type': 'unusual_activity_hours',
                    'hours': len(profile['active_hours']),
                    'confidence': 0.97
                })
                
        return [a for a in anomalies if a['confidence'] >= confidence_threshold]
