#!/usr/bin/env python3
"""
Script to organize the reports directory by moving loose HTML files to an archive folder.
"""

import os
import shutil
from pathlib import Path
from datetime import datetime

def organize_reports():
    """Organize reports directory by moving loose HTML files to an archive folder."""
    reports_dir = Path(__file__).resolve().parents[1] / "reports"
    
    # Create archive directory if it doesn't exist
    archive_dir = reports_dir / "archive"
    archive_dir.mkdir(exist_ok=True)
    
    # Get current timestamp for archive folder name
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Move loose HTML files to archive directory
    html_files = [f for f in reports_dir.glob("*.html") if f.is_file()]
    
    if html_files:
        # Create timestamped archive folder
        timestamped_archive = archive_dir / f"archive_{timestamp}"
        timestamped_archive.mkdir(exist_ok=True)
        
        # Move files
        for html_file in html_files:
            shutil.move(str(html_file), str(timestamped_archive / html_file.name))
        
        print(f"Moved {len(html_files)} HTML files to {timestamped_archive}")
    else:
        print("No loose HTML files found in reports directory")

if __name__ == "__main__":
    organize_reports()