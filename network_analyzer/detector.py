"""
Main detector class for network traffic analysis.
"""

import re
import os
import time
import base64
import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Set, Tuple, AsyncIterator
from collections import Counter, defaultdict, deque
from io import BytesIO
from dataclasses import asdict

from scapy.all import PcapReader, DNS, DNSQR, IP, IPv6, TCP, UDP, Raw, Packet
from netaddr import IPAddress

from .config import config
from .models import (
    PortScanAlert, CredentialLeakAlert, SuspiciousDNSAlert,
    DataExfilAlert, UncommonPortAlert, MalwareAlert, DetectionReport
)
from .utils.helpers import (
    is_private_ip, now_iso, safe_decode_bytes, shannon_entropy
)
from scapy.layers.http import HTTP

logger = logging.getLogger(__name__)

class NetworkLogAnomalyDetector:
    """Main class for detecting network traffic anomalies."""

    def __init__(self, pcap_path: str):
        """Initialize the detector with configuration."""
        if not os.path.exists(pcap_path):
            raise ValueError(f"PCAP file does not exist: {pcap_path}")
        if not os.access(pcap_path, os.R_OK):
            raise PermissionError(f"Cannot read PCAP file: {pcap_path}")
        
        self.pcap_path = pcap_path
        self.last_cleanup = time.time()
        
        # Load and validate configuration
        self.portscan_window_seconds = self._validate_config(
            config.get(['portscan', 'window_seconds']), 'window_seconds', min_value=1)
        self.portscan_unique_port_threshold = self._validate_config(
            config.get(['portscan', 'unique_port_threshold']), 'unique_port_threshold', min_value=1)
        self.portscan_syn_threshold = self._validate_config(
            config.get(['portscan', 'syn_threshold']), 'syn_threshold', min_value=1)
        self.portscan_threshold = self.portscan_syn_threshold
        
        self.dns_length_threshold = config.get(['dns', 'length_threshold'])
        self.dns_entropy_threshold = config.get(['dns', 'entropy_threshold'])
        
        self.exfil_ratio_threshold = config.get(['data_exfil', 'ratio_threshold'])
        self.min_out_bytes_threshold = config.get(['data_exfil', 'min_out_bytes'])
        self.exfil_baseline_window = config.get(['data_exfil', 'baseline_window'])
        self.exfil_alert_multiplier = config.get(['data_exfil', 'alert_multiplier'])
        
        self.uncommon_port_min_occurrences = config.get(['ports', 'uncommon_min_occurrences'])
        self.top_common_ports = config.get(['ports', 'top_common'])
        
        self._max_port_samples = config.get(['memory', 'max_port_samples'])
        self._cleanup_interval = config.get(['memory', 'cleanup_interval'])

        # Initialize state
        self._initialize_state()

    def _validate_config(self, value: any, name: str, min_value: int = None, max_value: int = None) -> any:
        """Validate configuration values."""
        if value is None:
            raise ValueError(f"Configuration value '{name}' is required")
        if min_value is not None and value < min_value:
            raise ValueError(f"Configuration value '{name}' must be >= {min_value}")
        if max_value is not None and value > max_value:
            raise ValueError(f"Configuration value '{name}' must be <= {max_value}")
        return value

    def _cleanup_resources(self):
        """Periodic cleanup of internal data structures."""
        current_time = time.time()
        
        # Only cleanup every _cleanup_interval seconds
        if current_time - self.last_cleanup < self._cleanup_interval:
            return
            
        logger.debug("Performing periodic cleanup")
        self.last_cleanup = current_time
        
        # Clean up port scan windows
        for key in list(self._portscan_windows.keys()):
            if not self._portscan_windows[key] or \
               current_time - max(self._portscan_windows[key]) > self.portscan_window_seconds:
                del self._portscan_windows[key]
                if key in self._port_sequence:
                    del self._port_sequence[key]
                if key in self._syn_counts:
                    del self._syn_counts[key]
        
        # Clean up port tracking
        if len(self._port_counts) > self._max_port_samples:
            self._port_counts = Counter(dict(
                self._port_counts.most_common(self._max_port_samples)
            ))
        
        # Clean up baseline transfer data
        for key in list(self._baseline_transfer.keys()):
            if not self._baseline_transfer[key]:
                del self._baseline_transfer[key]
        
        # Clean up alert deduplication set
        self._alert_dedup = {alert for alert in self._alert_dedup
                            if current_time - float(alert.split('|')[0]) < self.portscan_window_seconds}

    def _initialize_state(self):
        """Initialize internal state tracking."""
        # Packet counts
        self.total_packets = 0
        self.total_tcp = 0
        self.total_udp = 0
        self.total_dns = 0
        self.total_http = 0
        self.total_https = 0
        self.total_ftp = 0
        self.total_smtp = 0
        self.total_ssh = 0
        self.total_telnet = 0
        self.total_icmp = 0
        self.total_arp = 0
        self.total_other = 0
        self.processed_bytes = 0
        
        # Protocol-specific statistics
        self.protocol_stats = {
            'tcp': {'packets': 0, 'bytes': 0, 'ports': set()},
            'udp': {'packets': 0, 'bytes': 0, 'ports': set()},
            'icmp': {'packets': 0, 'bytes': 0, 'types': set()},
            'http': {'packets': 0, 'bytes': 0, 'ports': set(), 'methods': set(), 'status_codes': set()},
            'https': {'packets': 0, 'bytes': 0, 'ports': set()},
            'dns': {'packets': 0, 'bytes': 0, 'ports': set(), 'queries': set(), 'responses': 0},
            'ftp': {'packets': 0, 'bytes': 0, 'ports': set(), 'commands': set()},
            'smtp': {'packets': 0, 'bytes': 0, 'ports': set(), 'commands': set()},
            'ssh': {'packets': 0, 'bytes': 0, 'ports': set(), 'versions': set()},
            'telnet': {'packets': 0, 'bytes': 0, 'ports': set(), 'commands': set()},
            'arp': {'packets': 0, 'bytes': 0, 'operations': set()}
        }

        # Deep HTTP analysis storage
        self.http_requests: List[Dict[str, Any]] = []

        # Deep DNS analysis storage
        self.dns_queries_and_responses: List[Dict[str, Any]] = []

        # TLS/SSL handshake information
        self.tls_handshakes: List[Dict[str, Any]] = []

        # Port scan detection
        self._syn_counts = defaultdict(int)
        self._port_sequence = defaultdict(lambda: deque(maxlen=5))
        self._portscan_windows = defaultdict(lambda: deque(maxlen=1000))
        self._portscan_flagged = set()

        # Data exfiltration
        self._baseline_transfer = defaultdict(lambda: deque(maxlen=100))
        self._current_transfer = defaultdict(float)
        self._bytes_out = defaultdict(int)
        self._bytes_in = defaultdict(int)

        # Port tracking
        self._port_counts = Counter()
        self._port_sample_flow = {}

        # Alert deduplication
        self._alert_dedup = set()
        self.portscan_alerts: List[PortScanAlert] = []
        self.credential_alerts: List[CredentialLeakAlert] = []
        self.suspicious_dns_alerts: List[SuspiciousDNSAlert] = []
        self.data_exfil_alerts: List[DataExfilAlert] = []
        self.uncommon_port_alerts: List[UncommonPortAlert] = []
        self.malware_alerts: List[MalwareAlert] = []
        
        # Network flows and metrics
        self.flows: List[Dict[str, Any]] = []
        self.metrics: Dict[str, Any] = {}

    async def process_chunk(self, pcap_io: BytesIO) -> None:
        """Process a chunk of PCAP data."""
        chunk_start = time.time()
        packets_in_chunk = 0
        
        try:
            async with asyncio.timeout(300):  # 5-minute timeout
                reader = PcapReader(pcap_io)
                for pkt in reader:
                    try:
                        packets_in_chunk += 1
                        self.total_packets += 1
                        ts = float(pkt.time)
                        
                        # Periodic cleanup
                        self._cleanup_resources()
                        
                        # Log progress for large chunks
                        if packets_in_chunk % 10000 == 0:
                            elapsed = time.time() - chunk_start
                            rate = packets_in_chunk / elapsed
                            logger.info(f"Processed {packets_in_chunk:,} packets at {rate:.0f} packets/sec")
                        
                        # Process packet (rest of the original code)
                        ip_layer = None
                        if IP in pkt:
                            ip_layer = pkt[IP]
                        elif IPv6 in pkt:
                            ip_layer = pkt[IPv6]
                        else:
                            continue

                        src = ip_layer.src
                        dst = ip_layer.dst

                        # Handle TCP/UDP packets
                        if TCP in pkt:
                            await self._handle_tcp_udp_packet(ts, src, dst, pkt[TCP], len(pkt[TCP].payload), pkt)
                        elif UDP in pkt:
                            l4 = pkt[UDP]

                        # Calculate payload length and bytes
                        payload_len = len(bytes(pkt)) - (ip_layer.ihl * 4 if hasattr(ip_layer, 'ihl') else 40)
                        payload_bytes = bytes(pkt[Raw].load) if Raw in pkt else b""

                        if l4 is not None:
                            await self._handle_tcp_udp_packet(ts, src, dst, l4, max(payload_len, 0))
                            if payload_bytes:
                                await self._handle_credentials(
                                    ts, src, dst, payload_bytes,
                                    "TCP" if isinstance(l4, TCP) else "UDP"
                                )

                        if DNS in pkt:
                            await self._handle_dns(ts, src, dst, pkt[DNS])

                        self.processed_bytes += len(pkt)

                    except asyncio.TimeoutError:
                        logger.warning("Processing chunk timed out after 5 minutes.")
                        break
                    except Exception as e:
                        logger.error(f"Error processing packet: {e}")
                        continue
        except Exception as e:
            logger.error(f"Error reading PCAP chunk: {e}")

    async def _handle_tcp_udp_packet(self, ts: float, src: str, dst: str, l4, payload_len: int, packet: Packet) -> None:
        """Handle TCP/UDP packet processing with enhanced protocol detection."""
        protocol = "TCP" if isinstance(l4, TCP) else "UDP"
        sport = l4.sport
        dport = l4.dport
        
        if protocol == "TCP":
            self.total_tcp += 1
            self.protocol_stats['tcp']['packets'] += 1
            self.protocol_stats['tcp']['bytes'] += payload_len
            self.protocol_stats['tcp']['ports'].add(sport)
            self.protocol_stats['tcp']['ports'].add(dport)
            is_syn = l4.flags & 0x02 and not (l4.flags & 0x10)
            await self._check_port_scan(ts, src, dst, l4, is_syn)
        else:
            self.total_udp += 1
            self.protocol_stats['udp']['packets'] += 1
            self.protocol_stats['udp']['bytes'] += payload_len
            self.protocol_stats['udp']['ports'].add(sport)
            self.protocol_stats['udp']['ports'].add(dport)
            await self._check_port_scan(ts, src, dst, l4, False)
        
        # Detect application layer protocols
        await self._detect_application_protocols(ts, src, dst, sport, dport, protocol, payload_len, packet)

        # Track bytes for data exfiltration detection
        if is_private_ip(src) and not is_private_ip(dst):
            self._bytes_out[src] += payload_len
            await self._update_data_exfil(ts, src, payload_len, 0)

        if is_private_ip(dst) and not is_private_ip(src):
            self._bytes_in[dst] += payload_len
            await self._update_data_exfil(ts, dst, 0, payload_len)

    async def _detect_application_protocols(self, ts: float, src: str, dst: str, 
                                          sport: int, dport: int, protocol: str, 
                                          payload_len: int, packet: Packet) -> None:
        """Detect application layer protocols based on ports and patterns."""
        # HTTP/HTTPS detection
        if dport == 80 or sport == 80:
            self.total_http += 1
            self.protocol_stats['http']['packets'] += 1
            self.protocol_stats['http']['bytes'] += payload_len
            self.protocol_stats['http']['ports'].add(dport)
            
            # Deep HTTP analysis
            if HTTP in packet:
                http_layer = packet[HTTP]
                http_info = {
                    "timestamp": ts,
                    "source_ip": src,
                    "destination_ip": dst,
                    "source_port": sport,
                    "destination_port": dport,
                    "method": http_layer.Method.decode(errors='ignore') if hasattr(http_layer, 'Method') and http_layer.Method else '',
                    "host": http_layer.Host.decode(errors='ignore') if hasattr(http_layer, 'Host') and http_layer.Host else '',
                    "uri": http_layer.Path.decode(errors='ignore') if hasattr(http_layer, 'Path') and http_layer.Path else '',
                    "user_agent": http_layer.User_Agent.decode(errors='ignore') if hasattr(http_layer, 'User_Agent') and http_layer.User_Agent else '',
                    "content_type": http_layer.Content_Type.decode(errors='ignore') if hasattr(http_layer, 'Content_Type') and http_layer.Content_Type else '',
                    "content_length": http_layer.Content_Length.decode(errors='ignore') if hasattr(http_layer, 'Content_Length') and http_layer.Content_Length else '',
                    "status_code": http_layer.Status_Code.decode(errors='ignore') if hasattr(http_layer, 'Status_Code') and http_layer.Status_Code else '',
                    "raw_headers": bytes(http_layer).decode(errors='ignore', encoding='latin1')[:1024]  # Limit to first 1KB
                }
                self.http_requests.append(http_info)
                
                # Track HTTP methods and status codes
                if http_info['method']:
                    self.protocol_stats['http']['methods'].add(http_info['method'])
                if http_info['status_code']:
                    self.protocol_stats['http']['status_codes'].add(http_info['status_code'])
                    
        elif dport == 443 or sport == 443:
            self.total_https += 1
            self.protocol_stats['https']['packets'] += 1
            self.protocol_stats['https']['bytes'] += payload_len
            self.protocol_stats['https']['ports'].add(dport)

            # Deep TLS/SSL analysis
            if TLS in packet:
                tls_layer = packet[TLS]
                tls_info = {
                    "timestamp": ts,
                    "source_ip": src,
                    "destination_ip": dst,
                    "source_port": sport,
                    "destination_port": dport,
                    "tls_version": tls_layer.version if hasattr(tls_layer, 'version') else 'N/A',
                    "cipher_suite": tls_layer.ciphersuite if hasattr(tls_layer, 'ciphersuite') else 'N/A',
                    "server_name": 'N/A',
                    "certificate_subject": 'N/A',
                    "certificate_issuer": 'N/A',
                    "certificate_validity_start": 'N/A',
                    "certificate_validity_end": 'N/A',
                }

                # Extract server name from ServerHello
                if hasattr(tls_layer, 'extensions'):
                    for ext in tls_layer.extensions:
                        if hasattr(ext, 'servername'):
                            tls_info["server_name"] = ext.servername.decode(errors='ignore')

                # Extract certificate details from Certificate message
                if hasattr(tls_layer, 'certs'):
                    for cert in tls_layer.certs:
                        try:
                            x509 = cert.x509
                            tls_info["certificate_subject"] = x509.subject.human_friendly
                            tls_info["certificate_issuer"] = x509.issuer.human_friendly
                            tls_info["certificate_validity_start"] = x509.not_valid_before.isoformat()
                            tls_info["certificate_validity_end"] = x509.not_valid_after.isoformat()
                            break # Only take the first certificate for simplicity
                        except Exception as e:
                            logger.warning(f"Error parsing X.509 certificate: {e}")

                self.tls_handshakes.append(tls_info)

        # FTP detection
        elif dport == 21 or sport == 21:
            self.total_ftp += 1
            self.protocol_stats['ftp']['packets'] += 1
            self.protocol_stats['ftp']['bytes'] += payload_len
            self.protocol_stats['ftp']['ports'].add(dport)
        
        # SMTP detection
        elif dport == 25 or sport == 25 or dport == 587 or sport == 587:
            self.total_smtp += 1
            self.protocol_stats['smtp']['packets'] += 1
            self.protocol_stats['smtp']['bytes'] += payload_len
            self.protocol_stats['smtp']['ports'].add(dport)
        
        # SSH detection
        elif dport == 22 or sport == 22:
            self.total_ssh += 1
            self.protocol_stats['ssh']['packets'] += 1
            self.protocol_stats['ssh']['bytes'] += payload_len
            self.protocol_stats['ssh']['ports'].add(dport)
        
        # Telnet detection
        elif dport == 23 or sport == 23:
            self.total_telnet += 1
            self.protocol_stats['telnet']['packets'] += 1
            self.protocol_stats['telnet']['bytes'] += payload_len
            self.protocol_stats['telnet']['ports'].add(dport)
        
        # DNS detection (UDP/53 or TCP/53)
        elif (dport == 53 or sport == 53) and (protocol == "UDP" or protocol == "TCP"):
            if DNS in packet:
                await self._handle_dns(ts, src, dst, packet[DNS])
        
        # Credential detection (HTTP, FTP, SMTP, etc.)
        if payload_len > 0:
            payload = bytes(packet[l4].payload)
            await self._handle_credentials(ts, src, dst, payload, protocol)

    async def _handle_icmp_packet(self, ts: float, src: str, dst: str, icmp_type: int, payload_len: int) -> None:
        """Handle ICMP packet processing."""
        self.total_icmp += 1
        self.protocol_stats['icmp']['packets'] += 1
        self.protocol_stats['icmp']['bytes'] += payload_len
        self.protocol_stats['icmp']['types'].add(icmp_type)

    async def _handle_arp_packet(self, ts: float, src: str, dst: str, operation: int, payload_len: int) -> None:
        """Handle ARP packet processing."""
        self.total_arp += 1
        self.protocol_stats['arp']['packets'] += 1
        self.protocol_stats['arp']['bytes'] += payload_len
        self.protocol_stats['arp']['operations'].add(operation)
        
        # Track ARP operations
        arp_operations = {1: "Request", 2: "Reply", 3: "RARP Request", 4: "RARP Reply"}
        op_name = arp_operations.get(operation, f"Operation {operation}")
        self.protocol_stats['arp']['operation_names'] = self.protocol_stats['arp'].get('operation_names', set())
        self.protocol_stats['arp']['operation_names'].add(op_name)

    async def _handle_dns(self, ts: float, src: str, dst: str, dns: DNS) -> None:
        """Handle DNS packet analysis."""
        self.total_dns += 1

        dns_info = {
            "timestamp": ts,
            "source_ip": src,
            "destination_ip": dst,
            "query_name": "",
            "query_type": "",
            "response_code": dns.rcode,
            "answers": [],
            "is_response": dns.qr == 1,
        }

        if dns.qd and isinstance(dns.qd, DNSQR):
            qname = (dns.qd.qname.decode(errors="ignore").strip('.')
                     if isinstance(dns.qd.qname, (bytes, bytearray))
                     else str(dns.qd.qname).strip('.'))
            dns_info["query_name"] = qname
            dns_info["query_type"] = dns.qd.qtype

            length = len(qname)
            alnum = re.sub(r"[^A-Za-z0-9]", "", qname)
            entropy = shannon_entropy(alnum.lower())

            if length >= self.dns_length_threshold or entropy >= self.dns_entropy_threshold:
                alert = SuspiciousDNSAlert(
                    timestamp=ts,
                    source_ip=src,
                    destination_ip=dst,
                    query=qname,
                    length=length,
                    entropy=round(entropy, 3),
                )
                alert_key = f"{src}-{dst}-{qname}-{ts}"
                if alert_key not in self._alert_dedup:
                    self._alert_dedup.add(alert_key)
                    self.suspicious_dns_alerts.append(alert)

        if dns.an:
            for answer in dns.an:
                if hasattr(answer, 'rdata'):
                    try:
                        rdata = answer.rdata.decode(errors="ignore") if isinstance(answer.rdata, (bytes, bytearray)) else str(answer.rdata)
                        dns_info["answers"].append(rdata)
                    except Exception:
                        dns_info["answers"].append(str(answer.rdata))
                elif hasattr(answer, 'rclass'): # For cases like CNAME where rdata might be another name
                    dns_info["answers"].append(str(answer.rclass))

        self.dns_queries_and_responses.append(dns_info)

    async def _handle_credentials(self, ts: float, src: str, dst: str, payload: bytes, protocol: str) -> None:
        """Handle credential leak detection."""
        if not payload:
            return
            
        text = safe_decode_bytes(payload)
        if not text:
            return

        # FTP credentials
        if re.search(r"\bUSER\s+\S+", text, flags=re.IGNORECASE) and re.search(r"\bPASS\s+\S+", text, flags=re.IGNORECASE):
            alert = CredentialLeakAlert(
                timestamp=ts,
                source_ip=src,
                destination_ip=dst,
                protocol="FTP",
                indicator="USER/PASS commands observed",
            )
            alert_key = f"{src}-{dst}-FTP-{ts}"
            if alert_key not in self._alert_dedup:
                self._alert_dedup.add(alert_key)
                self.credential_alerts.append(alert)

        # Enhanced malware detection with multiple categories
        await self._detect_malware_patterns(ts, src, dst, text, payload)

        # HTTP Basic Auth
        m = re.search(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", text, flags=re.IGNORECASE)
        if m:
            b64 = m.group(1)
            try:
                decoded = base64.b64decode(b64 + "==", validate=False).decode("utf-8", errors="ignore")
                if ":" in decoded:
                    alert = CredentialLeakAlert(
                        timestamp=ts,
                        source_ip=src,
                        destination_ip=dst,
                        protocol="HTTP",
                        indicator="Authorization: Basic present",
                    )
                    alert_key = f"{src}-{dst}-HTTP-{ts}"
                    if alert_key not in self._alert_dedup:
                        self._alert_dedup.add(alert_key)
                        self.credential_alerts.append(alert)
            except Exception:
                pass

        # HTTP forms
        if re.search(r"(?:password|passwd|pwd)=\w+", text, flags=re.IGNORECASE):
            alert = CredentialLeakAlert(
                timestamp=ts,
                source_ip=src,
                destination_ip=dst,
                protocol=protocol,
                indicator="HTTP form credential fields present",
            )
            alert_key = f"{src}-{dst}-FORM-{ts}"
            if alert_key not in self._alert_dedup:
                self._alert_dedup.add(alert_key)
                self.credential_alerts.append(alert)

    async def _detect_malware_patterns(self, ts: float, src: str, dst: str, text_payload: str, raw_payload: bytes) -> None:
        """Detect malware patterns in text and raw payloads."""
        # Example: Detect common malware C2 patterns or downloaders
        if re.search(r"User-Agent: (Mozilla/4.0 \(compatible; MSIE 6.0; Windows NT 5.1\)|WinHttp|Wget)", text_payload) or \
           re.search(r"C2_COMMAND_HERE", text_payload): # Placeholder for actual C2 commands
            alert = MalwareAlert(
                timestamp=ts,
                source_ip=src,
                destination_ip=dst,
                malware_type="C2 Communication/Downloader",
                indicator="Suspicious User-Agent or C2 pattern detected",
            )
            alert_key = f"{src}-{dst}-MALWARE-C2-{ts}"
            if alert_key not in self._alert_dedup:
                self._alert_dedup.add(alert_key)
                self.malware_alerts.append(alert)

        # Example: Detect executable file downloads (simplified)
        if b"MZ" in raw_payload[:2] and (b"Content-Type: application/octet-stream" in raw_payload or b"Content-Disposition: attachment" in raw_payload):
            alert = MalwareAlert(
                timestamp=ts,
                source_ip=src,
                destination_ip=dst,
                malware_type="Executable Download",
                indicator="Potential executable file download detected",
            )
            alert_key = f"{src}-{dst}-MALWARE-EXE-{ts}"
            if alert_key not in self._alert_dedup:
                self._alert_dedup.add(alert_key)
                self.malware_alerts.append(alert)

    async def _check_port_scan(self, ts: float, src: str, dst: str, l4, is_syn: bool) -> None:
        """Detect port scanning activities."""
        if is_syn:
            self._syn_counts[(src, dst)] += 1
            if self._syn_counts[(src, dst)] > self.portscan_threshold:
                alert = PortScanAlert(
                    timestamp=ts,
                    source_ip=src,
                    destination_ip=dst,
                    port_count=self._syn_counts[(src, dst)],
                    indicator="High number of SYN packets to different ports"
                )
                alert_key = f"{src}-{dst}-PORTSCAN-{ts}"
                if alert_key not in self._alert_dedup:
                    self._alert_dedup.add(alert_key)
                    self.portscan_alerts.append(alert)
        
        # Further port scan logic can be added here, e.g., tracking unique destination ports
        self._port_sequence[src].append((ts, dport))
        unique_ports = set([port for _, port in self._port_sequence[src]])
        if len(unique_ports) > self.portscan_threshold and (src, dst) not in self._portscan_flagged:
            alert = PortScanAlert(
                timestamp=ts,
                source_ip=src,
                destination_ip=dst,
                port_count=len(unique_ports),
                indicator="Multiple unique ports scanned from source"
            )
            alert_key = f"{src}-{dst}-PORTSCAN-UNIQUE-{ts}"
            if alert_key not in self._alert_dedup:
                self._alert_dedup.add(alert_key)
                self.portscan_alerts.append(alert)
                self._portscan_flagged.add((src, dst)) # Flag to avoid duplicate alerts for same scan

    async def _update_data_exfil(self, ts: float, host: str, bytes_sent: int, bytes_received: int) -> None:
        """Update data exfiltration metrics and detect anomalies."""
        self._current_transfer[host] += bytes_sent
        self._baseline_transfer[host].append(bytes_sent)

        if len(self._baseline_transfer[host]) > self.exfil_window_size:
            baseline_avg = sum(self._baseline_transfer[host]) / len(self._baseline_transfer[host])
            if self._current_transfer[host] > baseline_avg * self.exfil_threshold:
                alert = DataExfilAlert(
                    timestamp=ts,
                    source_ip=host,
                    destination_ip="external", # Simplified, actual destination would be more complex
                    amount_bytes=self._current_transfer[host],
                    indicator="High volume of data sent compared to baseline"
                )
                alert_key = f"{host}-EXFIL-{ts}"
                if alert_key not in self._alert_dedup:
                    self._alert_dedup.add(alert_key)
                    self.data_exfil_alerts.append(alert)
            self._current_transfer[host] = 0 # Reset for next window

    async def _check_uncommon_ports(self, ts: float, src: str, dst: str, port: int, protocol: str) -> None:
        """Detect connections to or from uncommon ports."""
        # This is a simplified check. A more robust solution would involve
        # maintaining a list of common ports and flagging anything outside.
        # For now, we'll just track counts.
        self._port_counts[port] += 1
        if self._port_counts[port] < self.uncommon_port_threshold: # If port is rarely seen
            alert = UncommonPortAlert(
                timestamp=ts,
                source_ip=src,
                destination_ip=dst,
                port=port,
                protocol=protocol,
                indicator="Connection to/from an uncommon port"
            )
            alert_key = f"{src}-{dst}-{port}-{protocol}-{ts}"
            if alert_key not in self._alert_dedup:
                self._alert_dedup.add(alert_key)
                self.uncommon_port_alerts.append(alert)

    async def _finalize_exfil_alerts(self) -> None:
        """Finalize data exfiltration alerts."""
        # Any pending exfiltration alerts can be processed here
        pass

    async def _finalize_uncommon_ports(self) -> None:
        """Finalize uncommon port alerts."""
        # Any pending uncommon port alerts can be processed here
        pass

    async def finalize(self) -> DetectionReport:
        """Finalize processing and generate report."""
        await self._finalize_exfil_alerts()
        await self._finalize_uncommon_ports()

        # Convert sets to lists for JSON serialization
        protocol_stats_serializable = {}
        for protocol, stats in self.protocol_stats.items():
            protocol_stats_serializable[protocol] = {
                'packets': stats['packets'],
                'bytes': stats['bytes'],
                'ports': list(stats.get('ports', set())),
                'types': list(stats.get('types', set())),
                'operations': list(stats.get('operations', set())),
                'type_names': list(stats.get('type_names', set())),
                'operation_names': list(stats.get('operation_names', set())),
                'methods': list(stats.get('methods', set())),
                'status_codes': list(stats.get('status_codes', set())),
                'queries': list(stats.get('queries', set())),
                'commands': list(stats.get('commands', set())),
                'versions': list(stats.get('versions', set()))
            }
        
        stats = {
            "total_packets": self.total_packets,
            "tcp_packets": self.total_tcp,
            "udp_packets": self.total_udp,
            "dns_packets": self.total_dns,
            "http_packets": self.total_http,
            "https_packets": self.total_https,
            "ftp_packets": self.total_ftp,
            "smtp_packets": self.total_smtp,
            "ssh_packets": self.total_ssh,
            "telnet_packets": self.total_telnet,
            "icmp_packets": self.total_icmp,
            "arp_packets": self.total_arp,
            "other_packets": self.total_other,
            "processed_bytes": self.processed_bytes,
        }

        return DetectionReport(
            timestamp=datetime.now().isoformat(),
            stats=stats,
            protocol_stats=protocol_stats_serializable,
            port_scan_alerts=[asdict(alert) for alert in self.portscan_alerts],
            credential_alerts=[asdict(alert) for alert in self.credential_alerts],
            suspicious_dns_alerts=[asdict(alert) for alert in self.suspicious_dns_alerts],
            data_exfil_alerts=[asdict(alert) for alert in self.data_exfil_alerts],
            uncommon_port_alerts=[asdict(alert) for alert in self.uncommon_port_alerts],
            malware_alerts=[asdict(alert) for alert in self.malware_alerts],
            flows=self.flows,
            metrics=self.metrics,
            http_requests=self.http_requests, # Include HTTP requests in the report
        )
