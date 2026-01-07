#!/usr/bin/env python3
"""
Enterprise Vulnerability Scanner - CLI Entry Point
Command-line interface for the scanner application.
"""

import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import main scanner CLI
from scanner import main

if __name__ == "__main__":
    main()
