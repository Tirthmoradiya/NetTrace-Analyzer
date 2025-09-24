import logging
import json
from pathlib import Path
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
import pandas as pd
from scapy.all import PcapReader

# Updated imports from network_analyzer package
from network_analyzer.detector import NetworkLogAnomalyDetector
from network_analyzer.models import DetectionReport
from network_analyzer.visualize import NetworkVisualizer
from network_analyzer.utils.helpers import now_iso, get_memory_usage

class AdvancedNetworkAnalyzer:
    """Advanced network analysis with additional features."""
    
    def __init__(self, config_file: Optional[str] = None):
        # Load configuration if provided, else use defaults
        self.config = self._load_config(config_file) if config_file else self._default_config()
        
        # Initialize network analyzer
        self.detector = NetworkLogAnomalyDetector(None)  # Will be set per file in analyze_pcap
        self.visualizer = NetworkVisualizer()
        
        # Setup logging
        self._setup_logging()
    
    def _default_config(self) -> Dict:
        return {
            'port_scan': {
                'window_seconds': 60,
                'unique_ports_threshold': 20
            },
            'dns': {
                'entropy_threshold': 3.5,
                'length_threshold': 12
            },
            'data_exfil': {
                'ratio_threshold': 3.0,
                'min_bytes': 1000000
            }
        }
    
    def _load_config(self, config_file: str) -> Dict:
        """Load configuration from JSON file."""
        with open(config_file, 'r') as f:
            return json.load(f)
    
    def _setup_logging(self):
        """Configure logging with file and console output."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('network_analysis.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def analyze_pcap(self, pcap_file: str) -> DetectionReport:
        """Analyze a single PCAP file with enhanced monitoring."""
        self.logger.info(f"Starting analysis of {pcap_file}")
        
        try:
            report = self._process_pcap(pcap_file)
            self._save_report(report, pcap_file)
            self._generate_visualizations(pcap_file)
            return report
        except Exception as e:
            self.logger.error(f"Error analyzing {pcap_file}: {str(e)}")
            raise
    
    def batch_analyze(self, pcap_dir: str, max_workers: int = 4) -> List[DetectionReport]:
        """Analyze multiple PCAP files in parallel."""
        pcap_files = list(Path(pcap_dir).rglob("*.pcap"))
        self.logger.info(f"Found {len(pcap_files)} PCAP files to analyze")
        
        reports = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_pcap = {
                executor.submit(self.analyze_pcap, str(pcap)): pcap 
                for pcap in pcap_files
            }
            
            for future in as_completed(future_to_pcap):
                pcap = future_to_pcap[future]
                try:
                    report = future.result()
                    reports.append(report)
                except Exception as e:
                    self.logger.error(f"Failed to analyze {pcap}: {str(e)}")
        
        return reports
    
    def _process_pcap(self, pcap_file: str) -> DetectionReport:
        """Process packets with enhanced monitoring."""
        packet_count = 0
        start_time = pd.Timestamp.now()
        memory_samples = []
        
        # Initialize detector with the current pcap file
        self.detector = NetworkLogAnomalyDetector(pcap_file)
        
        # Process the pcap file using the detector
        reader = PcapReader(pcap_file)
        for packet in reader:
            packet_count += 1
            current_time = float(packet.time)
            
            # Process packet with the detector
            self.detector.process_packet(packet)
            self.visualizer.add_packet(packet)
            
            # Periodic monitoring
            if packet_count % 10000 == 0:
                memory_samples.append(get_memory_usage())
                self._log_progress(packet_count, start_time)
        
        return self._create_report(pcap_file, packet_count, start_time, memory_samples)
    
    def _periodic_cleanup(self):
        """Perform periodic data cleanup."""
        # The NetworkLogAnomalyDetector handles its own cleanup
    
    def _log_progress(self, packet_count: int, start_time: pd.Timestamp):
        """Log processing progress."""
        elapsed = (pd.Timestamp.now() - start_time).total_seconds()
        rate = packet_count / elapsed
        self.logger.info(
            f"Processed {packet_count:,} packets ({rate:.0f} packets/sec)"
        )
    
    def _create_report(self, pcap_file: str, packet_count: int, 
                      start_time: pd.Timestamp, memory_samples: List[float]) -> DetectionReport:
        """Create comprehensive analysis report."""
        end_time = pd.Timestamp.now()
        processing_time = (end_time - start_time).total_seconds()
        
        # Get the base report from the detector
        base_report = self.detector.generate_report()
        
        # Add additional stats
        base_report.stats.update({
            'total_packets': packet_count,
            'processing_time': processing_time,
            'packets_per_second': packet_count / processing_time,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat()
            })
        
        # Add performance metrics
        base_report.performance_metrics = {
            'memory_usage_mb': {
                'min': min(memory_samples) if memory_samples else 0,
                'max': max(memory_samples) if memory_samples else 0,
                'avg': sum(memory_samples) / len(memory_samples) if memory_samples else 0
            },
            'processing_time_seconds': processing_time
        }
        
        return base_report
    
    def _save_report(self, report: DetectionReport, pcap_file: str):
        """Save analysis report to JSON file."""
        output_file = Path(pcap_file).with_suffix('.report.json')
        with open(output_file, 'w') as f:
            json.dump(asdict(report), f, indent=2)
        self.logger.info(f"Saved report to {output_file}")
    
    def _generate_visualizations(self, pcap_file: str):
        """Generate and save all visualizations."""
        base_path = Path(pcap_file).with_suffix('')
        
        # Save interactive HTML plots
        self.visualizer.plot_traffic_timeline().write_html(
            f"{base_path}_traffic.html"
        )
        self.visualizer.plot_port_distribution().write_html(
            f"{base_path}_ports.html"
        )
        self.visualizer.plot_protocol_distribution().write_html(
            f"{base_path}_protocols.html"
        )
        self.visualizer.plot_ip_network_graph().write_html(
            f"{base_path}_network.html"
        )
        
        self.logger.info(f"Saved visualizations for {pcap_file}")

# Example usage
if __name__ == '__main__':
    # Import the enhanced analyzer instead
    from network_analyzer.enhanced_analyzer import EnhancedNetworkAnalyzer
    
    # Create analyzer with default config
    'data_exfil': {'ratio_threshold': 2.5, 'min_bytes': 500000}
    
    analyzer = AdvancedNetworkAnalyzer(config_file=None)  # Use default config
    
    # Analyze single PCAP
    report = analyzer.analyze_pcap(
        "test_pcaps/2019-02-07-cred-stealer-via-FTP-traffic.pcap"
    )
    
    # Batch analyze directory
    reports = analyzer.batch_analyze("test_pcaps", max_workers=4)
    
    # Print summary of all analyses
    print("\nAnalysis Summary:")
    print("-" * 50)
    for report in reports:
        print(f"\nFile: {report.pcap_file}")
        print(f"Packets: {report.stats['total_packets']:,}")
        print(f"Processing Time: {report.stats['processing_time']:.2f} seconds")
        print(f"Alerts Found:")
        for alert_type, alerts in report.alerts.items():
            if alerts:
                print(f"- {alert_type}: {len(alerts)}")
