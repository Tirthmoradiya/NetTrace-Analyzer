import time
from datetime import datetime
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
import pandas as pd
import networkx as nx
import plotly.graph_objects as go
import plotly.express as px
from scapy.all import IP, TCP, UDP, DNS, Raw
import psutil
from netaddr import IPNetwork, IPAddress

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def now_iso() -> str:
    """Return current timestamp in ISO format."""
    return datetime.utcnow().isoformat()

def get_memory_usage() -> float:
    """Get current memory usage in MB."""
    return psutil.Process().memory_info().rss / (1024 * 1024)

def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0
    import numpy as np
    for x in range(256):
        p_x = data.count(chr(x))/len(data)
        if p_x > 0:
            entropy += - p_x * np.log2(p_x)
    return entropy

@dataclass
class Alert:
    """Base class for security alerts."""
    timestamp: float
    source_ip: str
    destination_ip: str
    reason: str
    severity: str

@dataclass
class PortScanAlert(Alert):
    """Alert for detected port scanning activity."""
    num_ports: int
    ports_accessed: List[int]

@dataclass
class DNSAlert(Alert):
    """Alert for suspicious DNS activity."""
    query: str
    entropy: float

@dataclass
class DataExfilAlert(Alert):
    """Alert for potential data exfiltration."""
    bytes_transferred: int
    transfer_rate: float

@dataclass
class CredentialLeakAlert(Alert):
    """Alert for potential credential leakage."""
    protocol: str
    credentials: str

@dataclass
class DetectionReport:
    """Comprehensive detection report."""
    pcap_file: str
    generated_at: str
    stats: Dict[str, Any]
    alerts: Dict[str, List[Dict[str, Any]]]
    performance_metrics: Dict[str, Any]

class PortScanDetector:
    """Detect potential port scanning activity."""
    
    def __init__(self, window_seconds: int = 60, unique_ports_threshold: int = 20):
        self.window_seconds = window_seconds
        self.unique_ports_threshold = unique_ports_threshold
        self.port_access = {}  # {source_ip: {timestamp: set(ports)}}
        self.alerts = []
    
    def analyze_packet(self, packet, current_time: float):
        """Analyze a packet for port scanning behavior."""
        if not (IP in packet and (TCP in packet or UDP in packet)):
            return

        src_ip = packet[IP].src
        dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
        
        if src_ip not in self.port_access:
            self.port_access[src_ip] = {}
            
        self.port_access[src_ip][current_time] = {dst_port}
        
        # Check recent activity
        recent_ports = set()
        for timestamp, ports in list(self.port_access[src_ip].items()):
            if current_time - timestamp > self.window_seconds:
                del self.port_access[src_ip][timestamp]
            else:
                recent_ports.update(ports)
        
        if len(recent_ports) > self.unique_ports_threshold:
            self.alerts.append(PortScanAlert(
                timestamp=current_time,
                source_ip=src_ip,
                destination_ip=packet[IP].dst,
                reason=f"Port scan detected: {len(recent_ports)} unique ports in {self.window_seconds}s",
                severity="HIGH",
                num_ports=len(recent_ports),
                ports_accessed=sorted(list(recent_ports))
            ))

class DNSAnalyzer:
    """Analyze DNS queries for suspicious patterns."""
    
    def __init__(self, entropy_threshold: float = 3.5, length_threshold: int = 12):
        self.entropy_threshold = entropy_threshold
        self.length_threshold = length_threshold
        self.queries = {}  # {domain: count}
        self.alerts = []
    
    def analyze_packet(self, packet, current_time: float):
        """Analyze a DNS packet for suspicious patterns."""
        if DNS not in packet:
            return
            
        if packet[DNS].qr == 0:  # DNS query
            query = packet[DNS].qd.qname.decode('utf-8')
            
            # Check for suspicious patterns
            entropy = shannon_entropy(query)
            if (entropy > self.entropy_threshold and 
                len(query) > self.length_threshold):
                self.alerts.append(DNSAlert(
                    timestamp=current_time,
                    source_ip=packet[IP].src,
                    destination_ip=packet[IP].dst,
                    reason=f"Suspicious DNS query: high entropy ({entropy:.2f})",
                    severity="MEDIUM",
                    query=query,
                    entropy=entropy
                ))
    
    def cleanup_old_data(self, current_time: float):
        """Clean up old data to prevent memory bloat."""
        pass  # Implement if needed

class DataExfilDetector:
    """Detect potential data exfiltration."""
    
    def __init__(self, ratio_threshold: float = 3.0, min_bytes: int = 1000000):
        self.ratio_threshold = ratio_threshold
        self.min_bytes = min_bytes
        self.transfers = {}  # {(src_ip, dst_ip): [bytes]}
        self.alerts = []
    
    def process_packet(self, packet, current_time: float):
        """Process a packet for data exfiltration detection."""
        if IP not in packet:
            return
            
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        pair = (src_ip, dst_ip)
        
        if pair not in self.transfers:
            self.transfers[pair] = []
            
        bytes_sent = len(packet)
        self.transfers[pair].append(bytes_sent)
        
        # Check for suspicious data transfer
        total_bytes = sum(self.transfers[pair])
        if total_bytes > self.min_bytes:
            avg_bytes = total_bytes / len(self.transfers[pair])
            if avg_bytes > self.ratio_threshold * 1500:  # 1500 is typical MTU
                self.alerts.append(DataExfilAlert(
                    timestamp=current_time,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    reason=f"Large data transfer: {total_bytes/1e6:.2f}MB",
                    severity="HIGH",
                    bytes_transferred=total_bytes,
                    transfer_rate=avg_bytes
                ))
    
    def cleanup_old_data(self, current_time: float):
        """Clean up old data to prevent memory bloat."""
        self.transfers.clear()

class CredentialLeakDetector:
    """Detect potential credential leakage in network traffic."""
    
    def __init__(self):
        self.alerts = []
        self.patterns = {
            'ftp': rb'USER|PASS',
            'http': rb'Authorization: Basic',
            'telnet': rb'login:|password:',
            'smtp': rb'AUTH LOGIN|AUTH PLAIN'
        }
    
    def analyze_packet(self, packet, current_time: float):
        """Analyze packet for potential credential leakage."""
        if not (IP in packet and Raw in packet):
            return
            
        data = bytes(packet[Raw])
        proto = packet.proto
        
        for protocol, pattern in self.patterns.items():
            if pattern.search(data):
                self.alerts.append(CredentialLeakAlert(
                    timestamp=current_time,
                    source_ip=packet[IP].src,
                    destination_ip=packet[IP].dst,
                    reason=f"Potential credential leak via {protocol}",
                    severity="HIGH",
                    protocol=protocol,
                    credentials="[REDACTED]"
                ))
    
    def cleanup_old_data(self, current_time: float):
        """Clean up old data to prevent memory bloat."""
        pass

class NetworkVisualizer:
    """Network traffic visualization tools."""
    
    def __init__(self):
        self.traffic_data = []
        self.port_data = {}
        self.protocol_data = {}
        self.graph = nx.DiGraph()
    
    def add_packet(self, packet):
        """Process a packet for visualization."""
        if IP not in packet:
            return
            
        timestamp = pd.Timestamp.fromtimestamp(float(packet.time))
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet.proto
        size = len(packet)
        
        # Traffic timeline data
        self.traffic_data.append({
            'timestamp': timestamp,
            'size': size,
            'protocol': protocol
        })
        
        # Port distribution
        if TCP in packet:
            port = packet[TCP].dport
            self.port_data[port] = self.port_data.get(port, 0) + 1
        
        # Protocol distribution
        self.protocol_data[protocol] = self.protocol_data.get(protocol, 0) + 1
        
        # Network graph
        self.graph.add_edge(src_ip, dst_ip, weight=size)
    
    def plot_traffic_timeline(self) -> go.Figure:
        """Plot traffic volume over time."""
        df = pd.DataFrame(self.traffic_data)
        fig = px.line(df, x='timestamp', y='size',
                     title='Network Traffic Timeline')
        return fig
    
    def plot_port_distribution(self) -> go.Figure:
        """Plot distribution of destination ports."""
        ports = sorted(self.port_data.items())
        fig = go.Figure(data=[
            go.Bar(x=[p[0] for p in ports],
                  y=[p[1] for p in ports])
        ])
        fig.update_layout(title='Port Distribution',
                         xaxis_title='Port',
                         yaxis_title='Count')
        return fig
    
    def plot_protocol_distribution(self) -> go.Figure:
        """Plot distribution of protocols."""
        protocols = sorted(self.protocol_data.items())
        fig = go.Figure(data=[go.Pie(
            labels=[p[0] for p in protocols],
            values=[p[1] for p in protocols]
        )])
        fig.update_layout(title='Protocol Distribution')
        return fig
    
    def plot_ip_network_graph(self) -> go.Figure:
        """Plot network topology graph."""
        pos = nx.spring_layout(self.graph)
        edge_trace = go.Scatter(
            x=[], y=[], line=dict(width=0.5, color='#888'),
            hoverinfo='none', mode='lines')
        
        node_trace = go.Scatter(
            x=[], y=[], text=[], mode='markers+text',
            hoverinfo='text', marker=dict(size=10))
        
        for edge in self.graph.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_trace['x'] += (x0, x1, None)
            edge_trace['y'] += (y0, y1, None)
        
        for node in self.graph.nodes():
            x, y = pos[node]
            node_trace['x'] += (x,)
            node_trace['y'] += (y,)
            node_trace['text'] += (node,)
        
        fig = go.Figure(data=[edge_trace, node_trace],
                       layout=go.Layout(
                           title='Network Topology',
                           showlegend=False,
                           hovermode='closest',
                           margin=dict(b=20,l=5,r=5,t=40)
                       ))
        return fig
