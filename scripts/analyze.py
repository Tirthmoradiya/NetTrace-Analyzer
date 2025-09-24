import argparse
import json
from pathlib import Path
import asyncio
from datetime import datetime

from network_analyzer.enhanced_analyzer import EnhancedNetworkAnalyzer
from network_analyzer.visualize import NetworkVisualizer


def write_text_report(report: dict, out_path: Path) -> None:
	lines = []
	stats = report.get('stats', {})
	lines.append("=== Stats ===")
	for k, v in stats.items():
		lines.append(f"{k}: {v}")
	lines.append("")
	lines.append("=== Alerts ===")
	alerts = report.get('alerts', {})
	for group, items in alerts.items():
		lines.append(f"[{group}] {len(items)} events")
	out_path.write_text("\n".join(lines))


async def run(pcap: str, json_out: str, txt_out: str) -> None:
	analyzer = EnhancedNetworkAnalyzer(pcap_path=pcap)
	await analyzer.process_file()
	report = await analyzer.finalize()

	# Per-run directory under reports/{basename}-{timestamp}
	base = Path(pcap).stem
	ts = datetime.now().strftime("%Y%m%d_%H%M%S")
	run_dir = Path("reports") / f"{base}-{ts}"
	run_dir.mkdir(parents=True, exist_ok=True)

	# Persist JSON/TXT into run_dir
	out_json_path = run_dir / Path(json_out).name
	out_txt_path = run_dir / Path(txt_out).name if txt_out else None

	out_json_path.write_text(json.dumps(report, indent=2))
	if out_txt_path:
		write_text_report(report, out_txt_path)

	# Also generate HTML visualizations into the run_dir
	viz = NetworkVisualizer(output_dir=str(run_dir))
	stats = report.get('stats', {})
	protocols = stats.get('protocols', {})
	alerts = []
	for t, items in report.get('alerts', {}).items():
		for a in items:
			a = dict(a)
			a['type'] = t
			alerts.append(a)

	viz.generate_report({
		'flows': [],
		'metrics': [],
		'protocols': {k.upper(): v.get('packets', 0) for k, v in protocols.items()},
		'protocol_details': protocols,
		'alerts': alerts,
	})
	viz.create_intrusion_summary({
		'pcap_file': pcap,
		'generated_at': report.get('generated_at', ''),
		'stats': stats,
		'alerts': report.get('alerts', {}),
	})


def main() -> None:
	parser = argparse.ArgumentParser(description="Analyze a PCAP and write reports into a per-run directory")
	parser.add_argument("pcap", help="Path to .pcap/.pcapng file")
	parser.add_argument("--json-out", default="analysis.json", help="JSON report filename (stored in run dir)")
	parser.add_argument("--txt-out", default="analysis.txt", help="Text report filename (stored in run dir)")
	args = parser.parse_args()
	asyncio.run(run(args.pcap, args.json_out, args.txt_out))


if __name__ == "__main__":
	main()
