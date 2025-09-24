# Python-based Network Log Anomaly Detector

Analyze offline network captures (.pcap/.pcapng) to automatically flag suspicious behaviors using rule-based and anomaly-based methods.

## Features

- Rule-based detections:
  - Port scanning by unique destination ports per target within a time window
  - Cleartext credentials: FTP USER/PASS, HTTP Basic Auth, and password fields in HTTP forms
  - Suspicious DNS queries: long or high-entropy domain names (potential DGA)

- Anomaly-based detections:
  - Data exfiltration: high upload/download ratio for internal hosts to external networks
  - Uncommon ports: connections over rarely observed ports outside the top-N common ports

- Outputs JSON and human-readable text reports

## Requirements

- Python 3.9+
- libpcap dependencies for Scapy (platform-provided on macOS/Linux)

Install Python dependencies:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

### 1) Generate JSON/TXT reports (recommended)

Use the enhanced analyzer CLI to process a PCAP and write reports to the `reports/` directory.

```bash
# Activate the virtual environment first
source .venv/bin/activate

# Run the analyzer
python analyze.py test_pcaps/2019-02-07-cred-stealer-via-FTP-traffic.pcap \
  --json-out reports/analysis.json \
  --txt-out reports/analysis.txt
```

Outputs:

- `reports/analysis.json`: machine-readable report (stats, alerts, protocol breakdown)
- `reports/analysis.txt`: human-readable summary

### 2) Generate HTML visualizations (traffic flow, time series, protocols, anomalies)

```bash
source .venv/bin/activate
python example_usage.py
```

This writes outputs under a per-run folder: `reports/{pcap-basename}-{YYYYmmdd_HHMMSS}/`:

- `analysis.json`, `analysis.txt`
- `report.html` – dashboard (embeds all below)
- `intrusion_report.html` – intrusion summary with modern UI
- `traffic_flow.html` – interactive flow graph
- `time_series.html` – network metrics over time
- `protocols.html` – protocol distribution
- `protocol_details.html` – detailed protocol analysis (packets, bytes, ports, ICMP/ARP)
- `anomalies.html` – alerts scatter/timeline

Open `reports/report.html` in your browser to view the dashboard.

### 3) Original detector CLI (advanced tuning)

You can still run the lower-level detector with custom thresholds:

```bash
python detector.py sample.pcap --json-out report.json --txt-out report.txt \
  --portscan-window 60 --portscan-threshold 20 \
  --dns-length 45 --dns-entropy 3.5 \
  --exfil-ratio 3.0 --min-out-bytes 500000 \
  --uncommon-min 5 --top-common 10
```

If you omit `--json-out` or `--txt-out`, a summary prints to stdout.

## Running tests

```bash
source .venv/bin/activate
pytest -q
```

## Notes

- Sample PCAPs are included under `test_pcaps/` for quick trial runs.
- If you see parsing errors, ensure `scapy` can read your PCAP/PCAPNG and that system `libpcap` is available.

## Project Structure

See `docs/STRUCTURE.md` for a concise overview of the repo layout and where outputs are written per run.

## Where to get sample PCAPs

- Malware-Traffic-Analysis.net has realistic, labeled traces for learning and research.

## Notes on Heuristics

- Port scan: flags when a source contacts >= threshold unique destination ports on the same target within the window.
- DNS: flags domains that are very long or have high Shannon entropy (alpha-numeric only) which can indicate DGA.
- Data exfil: considers RFC1918 IPs as internal. Tracks bytes sent to/from external IPs, flags hosts with large outbound volume and high upload/download ratio.
- Uncommon ports: defines the top-N most frequent ports as common, flags others with sufficient occurrences.

## Limitations

- Heuristics can false-positive; tune thresholds based on your environment.
- PCAP parsing uses a streaming reader but still processes packets in Python, which can be slower on very large captures.

## License

MIT
