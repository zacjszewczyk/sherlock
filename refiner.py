#!/usr/bin/env python3
"""
Backward compatibility wrapper for refiner.py.

This script maintains the original refiner.py interface by calling main.py.
For new code, prefer using: python main.py refine -c config/refine.yml --mode playbooks
"""

import sys
from pathlib import Path

# Import and run the refiner main
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sherlock._refiner import main

if __name__ == "__main__":
    main()
