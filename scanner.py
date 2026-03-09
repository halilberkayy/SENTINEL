#!/usr/bin/env python3
"""
SENTINEL - Enterprise Web Vulnerability Scanner v5.0.0
Thin wrapper that delegates to src.cli package.

Developed by: Halil Berkay Sahin
License: MIT
"""

import sys
from pathlib import Path

# Ensure src is importable
sys.path.insert(0, str(Path(__file__).parent))

from src.cli.commands import main

if __name__ == "__main__":
    main()
