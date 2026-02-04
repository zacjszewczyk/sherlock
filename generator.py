#!/usr/bin/env python3
"""
Backward compatibility wrapper for generator.py.

This script maintains the original generator.py interface by calling main.py.
For new code, prefer using: python main.py generate -c config/generator.yml
"""

import sys
from pathlib import Path

# Import and run the generator main
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sherlock._generator import main

if __name__ == "__main__":
    main()
