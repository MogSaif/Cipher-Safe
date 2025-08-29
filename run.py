#!/usr/bin/env python3
"""
CipherSafe Launcher
------------------
A simple launcher script to run the CipherSafe application.
"""

import sys
import os

# Add the project root directory to the Python path
project_root = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, project_root)

# Import and run the application
from src import main

if __name__ == "__main__":
    main.main()
