#!/usr/bin/env python3
"""
Wrapper script for backward compatibility.
This file delegates to scripts/analyze.py.
"""

import os
import sys
from pathlib import Path

if __name__ == "__main__":
    # Get the path to scripts/analyze.py
    script_path = Path(__file__).resolve().parent / "scripts" / "analyze.py"
    
    # Execute the script with the same arguments
    os.execv(sys.executable, [sys.executable, str(script_path)] + sys.argv[1:])