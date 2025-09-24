# Test PCAPs

Place your .pcap/.pcapng files here for local testing.

Examples of scenarios to validate:

- Port scans (e.g., Nmap)
- FTP cleartext credentials
- HTTP Basic Auth or form logins
- Suspicious/DGA-style DNS
- Data exfiltration (high upload/download ratio)
- Uncommon/non-standard ports

Run the detector against a file in this folder:

```bash
source .venv/bin/activate
python detector.py test_pcaps/your_sample.pcap --json-out report.json --txt-out report.txt
```

Note: .pcap/.pcapng files are ignored by git (see .gitignore). Keep samples local.
