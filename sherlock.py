#!/usr/bin/env python3
"""
Backward compatibility wrapper for sherlock.py.

This script maintains the original sherlock.py interface by calling main.py.
For new code, prefer using: python main.py aggregate
"""

import sys
from pathlib import Path

# Import and run the aggregator main
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sherlock._aggregator import main

if __name__ == "__main__":
    main()
