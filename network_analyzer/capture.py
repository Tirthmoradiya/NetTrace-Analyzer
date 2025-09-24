"""
Live packet capture and analysis module.
"""

import asyncio
from scapy.all import sniff, wrpcap
from datetime import datetime
import os
import logging
from typing import Optional, List, Dict
from pathlib import Path

logger = logging.getLogger(__name__)

class LiveCapture:
    """Captures and analyzes network traffic in real-time."""
    
    def __init__(self, interface: str, output_dir: str = "captures",
                 max_packets: Optional[int] = None,
                 rotate_size: int = 100 * 1024 * 1024):  # 100MB default
        self.interface = interface
        self.output_dir = Path(output_dir)
        self.max_packets = max_packets
        self.rotate_size = rotate_size
        self.current_file = None
        self.packet_count = 0
        self.capture_stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'protocols': {},
            'ips': set()
        }
        
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_new_filename(self) -> Path:
        """Generate new capture file name."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return self.output_dir / f"capture_{timestamp}.pcap"
    
    def packet_callback(self, packet) -> None:
        """Process captured packets."""
        try:
            # Update stats
            self.capture_stats['total_packets'] += 1
            self.capture_stats['total_bytes'] += len(packet)
            
            # Track protocols
            for proto in ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP']:
                if proto in packet:
                    self.capture_stats['protocols'][proto] = \
                        self.capture_stats['protocols'].get(proto, 0) + 1
            
            # Track IPs
            if 'IP' in packet:
                self.capture_stats['ips'].add(packet['IP'].src)
                self.capture_stats['ips'].add(packet['IP'].dst)
            
            # Write packet to file
            if not self.current_file:
                self.current_file = self._get_new_filename()
            
            wrpcap(str(self.current_file), packet, append=True)
            self.packet_count += 1
            
            # Check if we need to rotate file
            if self.current_file.stat().st_size >= self.rotate_size:
                logger.info(f"Rotating capture file at {self.packet_count} packets")
                self.current_file = self._get_new_filename()
                self.packet_count = 0
            
            # Check if we've hit max packets
            if self.max_packets and self.capture_stats['total_packets'] >= self.max_packets:
                logger.info("Reached maximum packet count, stopping capture")
                return True
                
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    async def start_capture(self) -> None:
        """Start packet capture."""
        logger.info(f"Starting capture on interface {self.interface}")
        
        try:
            # Run sniff in a separate thread to not block event loop
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: sniff(
                    iface=self.interface,
                    prn=self.packet_callback,
                    store=0
                )
            )
        except Exception as e:
            logger.error(f"Error during capture: {e}")
            raise
    
    def get_stats(self) -> Dict:
        """Get current capture statistics."""
        return {
            'total_packets': self.capture_stats['total_packets'],
            'total_bytes': self.capture_stats['total_bytes'],
            'protocols': dict(self.capture_stats['protocols']),
            'unique_ips': len(self.capture_stats['ips']),
            'current_file': str(self.current_file) if self.current_file else None
        }
