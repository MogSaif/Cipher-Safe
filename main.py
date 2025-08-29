#!/usr/bin/env python3
"""
CipherSafe - Main Entry Point
---------------------------
This is the main entry point for the CipherSafe application.
"""

import os
import sys

# Add the current directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

def main():
    from src.views.main_window import MainWindow
    import tkinter as tk
    
    # Enable high DPI awareness for Windows
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except:
        pass
    
    root = tk.Tk()
    app = MainWindow(root)
    root.mainloop()

if __name__ == "__main__":
    main()
