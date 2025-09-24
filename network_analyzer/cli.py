#!/usr/bin/env python3
"""
Command-line interface for the network_analyzer package.
"""

import argparse
import asyncio
import sys
from pathlib import Path

from .enhanced_analyzer import EnhancedNetworkAnalyzer
from .visualize import NetworkVisualizer


async def analyze_pcap(pcap_path, json_out, txt_out, run_dir=None):
    """Analyze a PCAP file and generate reports."""
    analyzer = EnhancedNetworkAnalyzer(pcap_path=pcap_path)
    await analyzer.process_file()
    report = await analyzer.finalize()
    
    # Use provided run_dir or create one based on the PCAP filename
    if not run_dir:
        from datetime import datetime
        base = Path(pcap_path).stem
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_dir = Path("reports") / f"{base}-{ts}"
    
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    
    # Save JSON report
    json_path = run_dir / json_out
    with open(json_path, "w") as f:
        import json
        json.dump(report, f, indent=2)
    
    # Save text report if requested
    if txt_out:
        txt_path = run_dir / txt_out
        with open(txt_path, "w") as f:
            # Write stats section
            f.write("=== Stats ===\n")
            for k, v in report.get("stats", {}).items():
                f.write(f"{k}: {v}\n")
            f.write("\n")
            
            # Write alerts section
            f.write("=== Alerts ===\n")
            for group, items in report.get("alerts", {}).items():
                f.write(f"[{group}] {len(items)} events\n")
    
    # Generate visualizations
    viz = NetworkVisualizer(output_dir=str(run_dir))
    stats = report.get("stats", {})
    protocols = stats.get("protocols", {})
    
    # Format alerts for visualization
    alerts = []
    for t, items in report.get("alerts", {}).items():
        for a in items:
            a = dict(a)
            a["type"] = t
            alerts.append(a)
    
    # Generate reports
    viz.generate_report({
        "flows": [],
        "metrics": [],
        "protocols": {k.upper(): v.get("packets", 0) for k, v in protocols.items()},
        "protocol_details": protocols,
        "alerts": alerts,
    })
    
    viz.create_intrusion_summary({
        "pcap_file": pcap_path,
        "generated_at": report.get("generated_at", ""),
        "stats": stats,
        "alerts": report.get("alerts", {}),
    })
    
    return run_dir


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="Network traffic analysis tool for anomaly and intrusion detection"
    )
    parser.add_argument(
        "pcap", 
        help="Path to .pcap/.pcapng file or URL to download"
    )
    parser.add_argument(
        "--json-out", 
        default="analysis.json", 
        help="JSON report filename (stored in run dir)"
    )
    parser.add_argument(
        "--txt-out", 
        default="analysis.txt", 
        help="Text report filename (stored in run dir)"
    )
    parser.add_argument(
        "--run-dir", 
        help="Custom output directory (default: reports/{pcap_name}-{timestamp})"
    )
    
    args = parser.parse_args()
    
    # Handle URL downloads
    pcap_path = args.pcap
    if pcap_path.startswith("http"):
        try:
            from urllib.parse import urlparse
            from urllib.request import urlopen
            import tempfile
            import shutil
            
            print(f"Downloading {pcap_path}...")
            with urlopen(pcap_path) as response, tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                shutil.copyfileobj(response, tmp_file)
                pcap_path = tmp_file.name
            print(f"Downloaded to {pcap_path}")
        except Exception as e:
            print(f"Error downloading PCAP: {e}")
            sys.exit(1)
    
    # Run analysis
    try:
        run_dir = asyncio.run(analyze_pcap(
            pcap_path, 
            args.json_out, 
            args.txt_out, 
            args.run_dir
        ))
        print(f"Analysis complete. Reports saved to {run_dir}")
    except Exception as e:
        print(f"Error analyzing PCAP: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()