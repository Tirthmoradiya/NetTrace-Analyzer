# Project Structure

repo/

- network_analyzer/            (library code: detectors, analyzers, visualize, utils)
- scripts/
  - analyze.py                 (analyze PCAP; writes per-run outputs JSON/TXT/HTML)
  - example_usage.py           (thin wrapper delegating to root example_usage.py)
- configs/
  - default.yml                (human-editable configuration defaults)
- reports/
  - {pcap-basename}-{YYYYmmdd_HHMMSS}/
    - analysis.json
    - analysis.txt
    - report.html              (dashboard embeds charts + intrusion summary)
    - intrusion_report.html
    - traffic_flow.html
    - time_series.html
    - protocols.html
    - protocol_details.html
    - anomalies.html
  - downloads/                 (when PCAP is provided via URL)
- test_pcaps/                  (sample pcaps)
- analyze.py                   (back-compat wrapper; delegates to scripts/analyze.py)
- example_usage.py             (CLI to generate JSON/TXT + HTML)
- README.md

## Entrypoints

- scripts/analyze.py: preferred CLI; creates a timestamped folder per run.
- example_usage.py: accepts local path or URL; writes per-run outputs.
- analyze.py (root): wrapper that calls scripts/analyze.py.

## Outputs

- All artifacts for a run are placed under reports/{pcap-basename}-{YYYYmmdd_HHMMSS}/.
- If the PCAP is a URL, it is downloaded under reports/{run}/downloads/.

## Config

- Edit configs/default.yml to adjust thresholds and output settings.
