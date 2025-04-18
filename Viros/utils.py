#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Utility functions for Viros Mitm
Provides common utility functions used throughout the application.
"""

import os
import sys
import logging
import platform
import tempfile
from datetime import datetime

def setup_logging():
    """Configure logging for the application."""
    # Get the user's home directory
    home_dir = os.path.expanduser("~")
    
    # Create logs directory in appdata or home depending on platform
    if platform.system() == "Windows":
        log_dir = os.path.join(os.getenv('APPDATA'), "Viros_Mitm", "logs")
    else:
        log_dir = os.path.join(home_dir, ".viros_mitm", "logs")
    
    # Create directory if it doesn't exist
    os.makedirs(log_dir, exist_ok=True)
    
    # Define log file path with date
    log_file = os.path.join(
        log_dir, 
        f"viros_mitm_{datetime.now().strftime('%Y%m%d')}.log"
    )
    
    # Configure logging
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Log startup information
    logger = logging.getLogger(__name__)
    logger.info(f"Viros Mitm started on {platform.system()} {platform.version()}")
    logger.info(f"Python version: {platform.python_version()}")
    logger.info(f"Log file: {log_file}")

def is_admin():
    """Check if the application is running with administrator privileges."""
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False

def format_time_remaining(seconds):
    """
    Format seconds into a human-readable time string.
    
    Args:
        seconds: Number of seconds
        
    Returns:
        str: Formatted time string (e.g., "2h 30m")
    """
    if seconds < 60:
        return f"{seconds}s"
    
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    
    hours = minutes // 60
    minutes %= 60
    
    if minutes == 0:
        return f"{hours}h"
    else:
        return f"{hours}h {minutes}m"

def clean_old_logs(max_days=7):
    """
    Clean log files older than the specified number of days.
    
    Args:
        max_days: Maximum age of log files in days
    """
    # Get the user's home directory
    home_dir = os.path.expanduser("~")
    
    # Get logs directory
    if platform.system() == "Windows":
        log_dir = os.path.join(os.getenv('APPDATA'), "Viros_Mitm", "logs")
    else:
        log_dir = os.path.join(home_dir, ".viros_mitm", "logs")
    
    # Check if directory exists
    if not os.path.exists(log_dir):
        return
    
    # Get current time
    now = datetime.now()
    
    # Check each log file
    for filename in os.listdir(log_dir):
        if filename.startswith("viros_mitm_") and filename.endswith(".log"):
            # Try to parse date from filename
            try:
                date_str = filename.replace("viros_mitm_", "").replace(".log", "")
                file_date = datetime.strptime(date_str, "%Y%m%d")
                
                # Calculate age in days
                age_days = (now - file_date).days
                
                # Remove if older than max_days
                if age_days > max_days:
                    os.remove(os.path.join(log_dir, filename))
            except (ValueError, OSError):
                # Skip files with invalid date format
                pass

def get_temp_dir():
    """
    Get a temporary directory for the application.
    
    Returns:
        str: Path to temporary directory
    """
    temp_dir = os.path.join(tempfile.gettempdir(), "viros_mitm")
    os.makedirs(temp_dir, exist_ok=True)
    return temp_dir
