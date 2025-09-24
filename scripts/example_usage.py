#!/usr/bin/env python3
"""
Symbolic link to the main example_usage.py script.
This file is maintained for backward compatibility.

Please use the main example_usage.py script directly:
    python ../example_usage.py --pcap <pcap_file> --json-out <json_file> --txt-out <txt_file>
"""

import os
import sys
from pathlib import Path

# Redirect to the main example_usage.py script
if __name__ == "__main__":
    main_script = Path(__file__).resolve().parents[1] / "example_usage.py"
    os.execv(sys.executable, [sys.executable, str(main_script)] + sys.argv[1:])


