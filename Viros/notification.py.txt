#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Notification Manager for Viros Mitm
Handles system notifications with fallback options.
"""

import os
import logging
import platform
import subprocess
import threading
import tempfile
import time

logger = logging.getLogger(__name__)

class NotificationManager:
    """Manages system notifications with fallbacks."""
    
    def __init__(self, app_name):
        """
        Initialize the notification manager.
        
        Args:
            app_name: Name of the application for notifications
        """
        self.app_name = app_name
        self.platform = platform.system()
        self.notification_methods = self._detect_notification_methods()
    
    def _detect_notification_methods(self):
        """
        Detect available notification methods on the system.
        
        Returns:
            list: Available notification methods
        """
        methods = []
        
        # Check for platform-specific methods
        if self.platform == "Windows":
            # Check for Windows 10+ Toast notifications
            try:
                from win10toast import ToastNotifier
                toast = ToastNotifier()
                methods.append("win10toast")
            except ImportError:
                pass
            
            # Windows notification using balloontip (always available as fallback)
            methods.append("balloontip")
            
        elif self.platform == "Linux":
            # Check for notify-send
            try:
                subprocess.run(["notify-send", "--version"], 
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.PIPE)
                methods.append("notify-send")
            except (FileNotFoundError, subprocess.SubprocessError):
                pass
            
            # Check for zenity
            try:
                subprocess.run(["zenity", "--version"], 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE)
                methods.append("zenity")
            except (FileNotFoundError, subprocess.SubprocessError):
                pass
        
        elif self.platform == "Darwin":  # macOS
            # macOS notifications
            methods.append("osascript")
        
        logger.debug(f"Available notification methods: {methods}")
        return methods
    
    def show_notification(self, title, message):
        """
        Show a notification using the best available method.
        
        Args:
            title: Notification title
            message: Notification message
        """
        # Create and start notification thread to avoid blocking
        threading.Thread(
            target=self._show_notification_thread,
            args=(title, message, False),
            daemon=True
        ).start()
    
    def show_critical_notification(self, title, message):
        """
        Show a critical notification with higher visibility.
        
        Args:
            title: Notification title
            message: Notification message
        """
        # Create and start notification thread for critical notification
        threading.Thread(
            target=self._show_notification_thread,
            args=(title, message, True),
            daemon=True
        ).start()
    
    def _show_notification_thread(self, title, message, critical=False):
        """
        Thread function to show notification.
        
        Args:
            title: Notification title
            message: Notification message
            critical: Whether this is a critical notification
        """
        success = False
        
        # Try each method in order until one succeeds
        for method in self.notification_methods:
            if method == "win10toast" and self._notify_win10toast(title, message, critical):
                success = True
                break
            elif method == "balloontip" and self._notify_balloontip(title, message, critical):
                success = True
                break
            elif method == "notify-send" and self._notify_linux(title, message, critical):
                success = True
                break
            elif method == "zenity" and self._notify_zenity(title, message, critical):
                success = True
                break
            elif method == "osascript" and self._notify_macos(title, message, critical):
                success = True
                break
        
        # If all methods failed or no methods available, log the message
        if not success:
            logger.warning(f"Unable to show notification: {title} - {message}")
    
    def _notify_win10toast(self, title, message, critical=False):
        """Show notification using win10toast on Windows 10+."""
        try:
            from win10toast import ToastNotifier
            
            # Create toast notifier
            toast = ToastNotifier()
            
            # Show notification
            duration = 10 if critical else 5  # Longer duration for critical notifications
            toast.show_toast(
                title,
                message,
                duration=duration,
                threaded=True
            )
            
            return True
        except Exception as e:
            logger.error(f"Error showing win10toast notification: {e}")
            return False
    
    def _notify_balloontip(self, title, message, critical=False):
        """Show notification using tkinter balloon tip (fallback)."""
        try:
            # Import tkinter-related modules here to avoid dependency at startup
            import tkinter as tk
            from tkinter import messagebox
            
            # Create a temporary window
            root = tk.Tk()
            root.withdraw()  # Hide the window
            
            if critical:
                # For critical notifications, show a modal dialog
                root.after(1, lambda: messagebox.showwarning(title, message))
            else:
                # For normal notifications, show and automatically close
                root.title(title)
                root.attributes("-topmost", True)
                
                # Create a label with the message
                label = tk.Label(root, text=message, padx=20, pady=20)
                label.pack()
                
                # Show the window near the system tray
                width = 300
                height = 100
                x = root.winfo_screenwidth() - width - 20
                y = root.winfo_screenheight() - height - 60
                root.geometry(f"{width}x{height}+{x}+{y}")
                
                # Make the window visible
                root.deiconify()
                
                # Close after a delay
                duration = 8000 if critical else 4000  # milliseconds
                root.after(duration, root.destroy)
            
            # Run the tkinter main loop
            root.mainloop()
            
            return True
        except Exception as e:
            logger.error(f"Error showing balloontip notification: {e}")
            return False
    
    def _notify_linux(self, title, message, critical=False):
        """Show notification using notify-send on Linux."""
        try:
            # Set urgency based on criticality
            urgency = "critical" if critical else "normal"
            
            # Call notify-send
            subprocess.run([
                "notify-send",
                "--app-name", self.app_name,
                "--urgency", urgency,
                title,
                message
            ])
            
            return True
        except Exception as e:
            logger.error(f"Error showing Linux notification: {e}")
            return False
    
    def _notify_zenity(self, title, message, critical=False):
        """Show notification using zenity on Linux (fallback)."""
        try:
            # Set icon based on criticality
            icon = "warning" if critical else "info"
            
            # Call zenity
            subprocess.Popen([
                "zenity",
                "--notification",
                "--title", title,
                "--text", message,
                "--window-icon", icon
            ])
            
            return True
        except Exception as e:
            logger.error(f"Error showing zenity notification: {e}")
            return False
    
    def _notify_macos(self, title, message, critical=False):
        """Show notification using AppleScript on macOS."""
        try:
            # Create AppleScript command
            script = f'''
            display notification "{message}" with title "{title}" sound name "{"Basso" if critical else "Glass"}"
            '''
            
            # Execute AppleScript
            subprocess.run(["osascript", "-e", script])
            
            return True
        except Exception as e:
            logger.error(f"Error showing macOS notification: {e}")
            return False
