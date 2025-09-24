"""
Enhanced network traffic analysis module.
"""

import os
import time
import logging
import asyncio
from io import BytesIO
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import asdict

from scapy.all import PcapReader, IP, IPv6, TCP, UDP, DNS, Raw
from .analyzers.traffic_pattern import TrafficPatternAnalyzer, BehavioralProfiler
from .analyzers.threat_intel import ThreatIntelligence
from .analyzers.ml_detector import MLDetector
from .detector import NetworkLogAnomalyDetector

logger = logging.getLogger(__name__)

class EnhancedNetworkAnalyzer(NetworkLogAnomalyDetector):
    """Enhanced network traffic analyzer with advanced detection capabilities."""
    
    def __init__(self, pcap_path: str, config_path: Optional[str] = None,
                 ti_api_key: Optional[str] = None, model_path: Optional[str] = None):
        """Initialize the enhanced analyzer with advanced detection capabilities."""
        try:
            super().__init__(pcap_path)
            
            # Validate paths
            if config_path and not os.path.exists(config_path):
                raise ValueError(f"Config file does not exist: {config_path}")
            if model_path and not os.path.exists(model_path):
                raise ValueError(f"ML model file does not exist: {model_path}")
            
            # Initialize advanced analyzers with error handling
            try:
                self.pattern_analyzer = TrafficPatternAnalyzer()
                self.behavioral_profiler = BehavioralProfiler()
                self.threat_intel = ThreatIntelligence(ti_api_key)
                self.ml_detector = MLDetector(model_path)
            except Exception as e:
                logger.error(f"Error initializing analyzers: {str(e)}")
                raise RuntimeError("Failed to initialize analyzers") from e
            
            # Load block and white lists with validation
            try:
                self._load_lists()
            except Exception as e:
                logger.error(f"Error loading lists: {str(e)}")
                raise
        except Exception as e:
            logger.error(f"Error initializing EnhancedNetworkAnalyzer: {str(e)}")
            raise

        # Initialize memory tracking
        self.last_cleanup = 0
        self.memory_threshold = 1024 * 1024 * 1024  # 1GB
        self.last_memory_check = 0
        self.memory_check_interval = 60  # 1 minute
        
    async def process_file(self) -> None:
        """Process the configured PCAP file end-to-end.

        This minimal implementation loads the file into memory and reuses
        process_chunk for parsing and analysis.
        """
        try:
            with open(self.pcap_path, 'rb') as f:
                data = f.read()
            await self.process_chunk(BytesIO(data))
        except Exception as e:
            logger.error(f"Error in process_file: {e}")
            raise

    def _load_lists(self):
        """Load and validate block and white lists."""
        blocklist_path = Path('blocklist.txt')
        whitelist_path = Path('whitelist.txt')
        
        if not blocklist_path.exists():
            logger.warning("Blocklist file not found, creating empty file")
            blocklist_path.touch()
            
        if not whitelist_path.exists():
            logger.warning("Whitelist file not found, creating empty file")
            whitelist_path.touch()
            
        try:
            self.threat_intel.load_blocklist(str(blocklist_path))
            self.threat_intel.load_whitelist(str(whitelist_path))
        except Exception as e:
            logger.error(f"Error loading lists: {str(e)}")
            raise
        
        # Additional state
        self.advanced_alerts = []
        
    def _check_memory_usage(self):
        """Check and manage memory usage."""
        current_time = time.time()
        if current_time - self.last_memory_check < self.memory_check_interval:
            return

        self.last_memory_check = current_time
        try:
            import psutil
            process = psutil.Process()
            memory_use = process.memory_info().rss

            if memory_use > self.memory_threshold:
                logger.warning(f"Memory usage ({memory_use / 1024 / 1024:.1f}MB) exceeded threshold")
                self._cleanup_resources()
                
        except ImportError:
            logger.debug("psutil not available for memory monitoring")
        except Exception as e:
            logger.warning(f"Error checking memory usage: {e}")

    async def process_chunk(self, pcap_io: BytesIO) -> None:
        """Process PCAP chunk with enhanced analysis."""
        chunk_start = time.time()
        packets_in_chunk = 0
        packet_errors = 0
        max_errors = 10000  # Increased threshold for packet errors
        
        try:
            async with asyncio.timeout(300):  # 5-minute timeout
                reader = PcapReader(pcap_io)
                
                for pkt in reader:
                    # Check error rate every 1000 packets
                    if packets_in_chunk > 0 and packets_in_chunk % 1000 == 0:
                        error_rate = packet_errors / packets_in_chunk
                        if error_rate > 0.9:  # Allow up to 90% error rate
                            raise RuntimeError(f"Too many packet errors ({packet_errors}/{packets_in_chunk} = {error_rate:.1%}), aborting")
                        
                    try:
                        packets_in_chunk += 1
                        self.total_packets += 1
                        self.processed_bytes += len(bytes(pkt))
                        
                        # Check memory usage periodically
                        self._check_memory_usage()
                        
                        # Basic packet validation
                        if not hasattr(pkt, 'time'):
                            logger.warning(f"Packet {packets_in_chunk} missing timestamp")
                            packet_errors += 1
                            continue
                            
                        ts = float(pkt.time)
                        
                        # Extract IP layer
                        ip_layer = None
                        if IP in pkt:
                            ip_layer = pkt[IP]
                        elif IPv6 in pkt:
                            ip_layer = pkt[IPv6]
                        else:
                            continue
                        src = ip_layer.src
                        dst = ip_layer.dst

                        # Transport layer
                        l4 = None
                        if TCP in pkt:
                            l4 = pkt[TCP]
                        elif UDP in pkt:
                            l4 = pkt[UDP]

                        # Payload
                        payload_len = len(bytes(pkt)) - (getattr(ip_layer, 'ihl', 10) * 4 if hasattr(ip_layer, 'ihl') else 40)
                        payload_bytes = bytes(pkt[Raw].load) if Raw in pkt else b""

                        if l4 is not None:
                            await self._handle_tcp_udp_packet(ts, src, dst, l4, max(payload_len, 0), pkt)
                            if payload_bytes:
                                await self._handle_credentials(
                                    ts, src, dst, payload_bytes,
                                    "TCP" if isinstance(l4, TCP) else "UDP"
                                )

                        if DNS in pkt:
                            await self._handle_dns(ts, src, dst, pkt[DNS])
                            
                        # Log progress
                        if packets_in_chunk % 10000 == 0:
                            elapsed = time.time() - chunk_start
                            rate = packets_in_chunk / elapsed
                            logger.info(f"Processed {packets_in_chunk:,} packets at {rate:.0f} packets/sec")
                            
                    except Exception as e:
                        packet_errors += 1
                        logger.warning(f"Error processing packet {packets_in_chunk}: {str(e)}")
                        continue
                        
        except asyncio.TimeoutError:
            logger.error("Processing timeout exceeded (5 minutes)")
            raise
        except Exception as e:
            logger.error(f"Error processing chunk: {str(e)}")
            raise
        finally:
            elapsed = time.time() - chunk_start
            rate = packets_in_chunk / max(elapsed, 0.1)
            logger.info(
                f"Finished chunk: {packets_in_chunk:,} packets ({packet_errors} errors) "
                f"in {elapsed:.1f}s ({rate:.0f} packets/sec)"
            )
    
    async def finalize(self) -> Dict:
        """Generate enhanced analysis report."""
        base_report = await super().finalize()
        try:
            base_report_dict = asdict(base_report)
        except Exception:
            # If it's already a dict, keep as-is
            base_report_dict = base_report  # type: ignore
        
        # Add pattern analysis results
        pattern_anomalies = self.pattern_analyzer.detect_anomalies()
        behavioral_anomalies = self.behavioral_profiler.get_anomalies()
        
        # Enhanced report
        # Ensure required keys exist for downstream visualization code
        base_report_dict.setdefault('stats', {})

        enhanced_report = {
            **base_report_dict,
            'advanced_analysis': {
                'pattern_anomalies': pattern_anomalies,
                'behavioral_anomalies': behavioral_anomalies,
                'ml_detections': [a for a in self.advanced_alerts 
                                if a['type'] == 'ml_detection'],
                'threat_intel_alerts': [a for a in self.advanced_alerts 
                                      if a['type'] == 'threat_intel']
            }
        }
        
        return enhanced_report
    
    async def train_ml_detector(self, normal_pcap_path: str) -> None:
        """Train ML detector on known normal traffic."""
        detector = NetworkLogAnomalyDetector(normal_pcap_path)
        normal_flows = []
        
        async for chunk in detector.process_file_async(normal_pcap_path):
            flows = detector.extract_flows(chunk)
            normal_flows.extend(flows)
        
        self.ml_detector.train(normal_flows)
        logger.info("ML detector training completed")
        
    def analyze_pcap(self, pcap_path: str) -> Dict:
        """Analyze a single PCAP file and return a report.
        
        This is a synchronous wrapper around the async process_file method.
        """
        try:
            # Create a new event loop for this synchronous context
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Process the file
            loop.run_until_complete(self.process_file())
            report = loop.run_until_complete(self.finalize())
            
            return report
        finally:
            loop.close()
    
    def batch_analyze(self, directory: str, pattern: str = "*.pcap", max_workers: int = 4) -> List[Dict]:
        """Analyze multiple PCAP files in a directory.
        
        Args:
            directory: Directory containing PCAP files
            pattern: Glob pattern to match files (default: "*.pcap")
            max_workers: Maximum number of parallel workers
            
        Returns:
            List of analysis reports
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed
        from pathlib import Path
        
        # Find all matching files
        pcap_dir = Path(directory)
        if not pcap_dir.is_dir():
            raise ValueError(f"Directory not found: {directory}")
            
        pcap_files = list(pcap_dir.glob(pattern))
        if not pcap_files:
            logger.warning(f"No files matching '{pattern}' found in {directory}")
            return []
            
        logger.info(f"Found {len(pcap_files)} files to analyze")
        
        # Process files in parallel
        reports = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_file = {}
            for pcap_file in pcap_files:
                future = executor.submit(self.analyze_pcap, str(pcap_file))
                future_to_file[future] = pcap_file
                
            # Process results as they complete
            for future in as_completed(future_to_file):
                pcap_file = future_to_file[future]
                try:
                    report = future.result()
                    reports.append(report)
                    logger.info(f"Completed analysis of {pcap_file.name}")
                except Exception as e:
                    logger.error(f"Error analyzing {pcap_file.name}: {str(e)}")
        
        return reports
        
    def _cleanup_resources(self):
        """Clean up resources to reduce memory usage."""
        import gc
        
        # Clear caches
        self.pattern_analyzer.clear_cache()
        self.behavioral_profiler.clear_cache()
        
        # Force garbage collection
        gc.collect()
        
        self.last_cleanup = time.time()
        logger.info("Resource cleanup completed")
