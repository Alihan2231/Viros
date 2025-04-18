#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Viros Mitm - Advanced ARP Spoofing Detection Tool
This application monitors network interfaces for potential ARP spoofing attacks,
runs scheduled scans in the background, and can be configured to start automatically
with the system.

Version: 1.0
"""

import os
import sys
import tkinter as tk
from gui import MainApplication
from utils import setup_logging

def main():
    """
    Main application entry point.
    Initializes the GUI and starts the application.
    """
    # Setup logging
    setup_logging()
    
    # Create the root window
    root = tk.Tk()
    root.title("Viros Mitm")
    
    # Set icon for the application (will be handled by the GUI class)
    
    # Create and pack the main application
    app = MainApplication(root)
    app.pack(side="top", fill="both", expand=True)
    
    # Center the window on the screen
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    window_width = 800
    window_height = 600
    center_x = int(screen_width/2 - window_width/2)
    center_y = int(screen_height/2 - window_height/2)
    root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
    
    # Start the application
    root.mainloop()

if __name__ == "__main__":
    # Check if the app is running with the --minimized flag
    if len(sys.argv) > 1 and sys.argv[1] == "--minimized":
        # Will be handled in the MainApplication class to start minimized
        os.environ["START_MINIMIZED"] = "1"
        
    main()
