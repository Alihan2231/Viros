#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Scheduler module for Viros Mitm
Handles scheduling of periodic network scans.
"""

import threading
import time
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class ScheduleManager:
    """Manages scheduled scans with flexible intervals."""
    
    def __init__(self, callback=None):
        """
        Initialize the schedule manager.
        
        Args:
            callback: Function to call when scheduled time is reached
        """
        self.callback = callback
        self.active = False
        self.interval = 60  # Default: 1 minute in seconds
        self.interval_display = (1, "hour")  # For display purposes
        self.thread = None
        self.next_run_time = None
        self.stop_event = threading.Event()
    
    def start(self, interval=1, unit="hour"):
        """
        Start scheduled scanning with the specified interval.
        
        Args:
            interval: Number of time units
            unit: 'minute' or 'hour'
        """
        # Convert to seconds
        if unit == "minute":
            self.interval = interval * 60
        elif unit == "hour":
            self.interval = interval * 3600
        else:
            raise ValueError(f"Invalid time unit: {unit}")
        
        # Store display values
        self.interval_display = (interval, unit)
        
        # Calculate next run time
        self.next_run_time = datetime.now() + timedelta(seconds=self.interval)
        
        # Stop existing thread if running
        self.stop()
        
        # Start new thread
        self.active = True
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._scheduler_thread, daemon=True)
        self.thread.start()
        
        logger.info(f"Scheduling started: every {interval} {unit}(s)")
    
    def stop(self):
        """Stop scheduled scanning."""
        if self.active:
            self.active = False
            self.stop_event.set()
            
            if self.thread and self.thread.is_alive():
                # Give the thread a moment to exit gracefully
                self.thread.join(timeout=1.0)
            
            self.thread = None
            logger.info("Scheduling stopped")
    
    def update(self, interval, unit):
        """
        Update the schedule interval.
        
        Args:
            interval: Number of time units
            unit: 'minute' or 'hour'
        """
        # Only update if already active
        if self.active:
            self.start(interval, unit)
    
    def is_active(self):
        """Check if scheduling is currently active."""
        return self.active
    
    def get_interval_display(self):
        """Get the current interval for display."""
        return self.interval_display
    
    def get_next_run_time(self):
        """Get the next scheduled run time as a string."""
        if self.next_run_time:
            return self.next_run_time.strftime("%H:%M:%S")
        return "Not scheduled"
    
    def _scheduler_thread(self):
        """Thread function that handles the scheduling logic."""
        while self.active and not self.stop_event.is_set():
            # Calculate time until next run
            now = datetime.now()
            if self.next_run_time <= now:
                # Time to run the callback
                try:
                    if self.callback:
                        self.callback()
                except Exception as e:
                    logger.error(f"Error in scheduled callback: {e}")
                
                # Schedule next run
                self.next_run_time = datetime.now() + timedelta(seconds=self.interval)
                logger.debug(f"Next scan scheduled at {self.next_run_time}")
            
            # Sleep until next check (check every second for stop event)
            time.sleep(1)
