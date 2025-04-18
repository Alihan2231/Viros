#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Auto-start Manager for Viros Mitm
Handles system startup configuration for Windows and Linux.
"""

import os
import sys
import logging
import platform

logger = logging.getLogger(__name__)

class AutoStartManager:
    """Manages automatic startup with the system."""
    
    def __init__(self, app_name):
        """
        Initialize the auto-start manager.
        
        Args:
            app_name: Name of the application
        """
        self.app_name = app_name
        self.app_path = sys.executable
        self.script_path = os.path.abspath(sys.argv[0])
        
        # Determine the operating system
        self.platform = platform.system()
    
    def enable(self):
        """
        Enable application to start with system.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if self.platform == "Windows":
                return self._enable_windows()
            elif self.platform == "Linux":
                return self._enable_linux()
            else:
                logger.warning(f"Auto-start not supported on {self.platform}")
                return False
        except Exception as e:
            logger.error(f"Error enabling auto-start: {e}")
            return False
    
    def disable(self):
        """
        Disable application from starting with system.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if self.platform == "Windows":
                return self._disable_windows()
            elif self.platform == "Linux":
                return self._disable_linux()
            else:
                logger.warning(f"Auto-start not supported on {self.platform}")
                return False
        except Exception as e:
            logger.error(f"Error disabling auto-start: {e}")
            return False
    
    def is_enabled(self):
        """
        Check if application is set to start with system.
        
        Returns:
            bool: True if enabled, False otherwise
        """
        try:
            if self.platform == "Windows":
                return self._is_enabled_windows()
            elif self.platform == "Linux":
                return self._is_enabled_linux()
            else:
                return False
        except Exception as e:
            logger.error(f"Error checking auto-start status: {e}")
            return False
    
    def _enable_windows(self):
        """Enable auto-start on Windows using registry."""
        try:
            import winreg
            
            # Open the Run registry key
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, 
                                winreg.KEY_WRITE)
            
            # Command to run the application minimized
            cmd = f'"{self.app_path}" "{self.script_path}" --minimized'
            
            # Set the registry value
            winreg.SetValueEx(key, self.app_name, 0, winreg.REG_SZ, cmd)
            winreg.CloseKey(key)
            
            logger.info(f"Added {self.app_name} to Windows startup")
            return True
            
        except ImportError:
            logger.error("Failed to import winreg module for Windows registry access")
            return False
        except Exception as e:
            logger.error(f"Error adding to Windows startup: {e}")
            return False
    
    def _disable_windows(self):
        """Disable auto-start on Windows by removing registry entry."""
        try:
            import winreg
            
            # Open the Run registry key
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, 
                                winreg.KEY_WRITE)
            
            # Delete the registry value
            try:
                winreg.DeleteValue(key, self.app_name)
            except FileNotFoundError:
                # Key not found, already disabled
                pass
            
            winreg.CloseKey(key)
            
            logger.info(f"Removed {self.app_name} from Windows startup")
            return True
            
        except ImportError:
            logger.error("Failed to import winreg module for Windows registry access")
            return False
        except Exception as e:
            logger.error(f"Error removing from Windows startup: {e}")
            return False
    
    def _is_enabled_windows(self):
        """Check if auto-start is enabled on Windows."""
        try:
            import winreg
            
            # Open the Run registry key
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, 
                                winreg.KEY_READ)
            
            try:
                # Try to read the registry value
                winreg.QueryValueEx(key, self.app_name)
                enabled = True
            except FileNotFoundError:
                # Key not found, auto-start is disabled
                enabled = False
            
            winreg.CloseKey(key)
            return enabled
            
        except ImportError:
            logger.error("Failed to import winreg module for Windows registry access")
            return False
        except Exception as e:
            logger.error(f"Error checking Windows startup status: {e}")
            return False
    
    def _enable_linux(self):
        """Enable auto-start on Linux using desktop entry."""
        try:
            # Create ~/.config/autostart directory if it doesn't exist
            autostart_dir = os.path.expanduser("~/.config/autostart")
            os.makedirs(autostart_dir, exist_ok=True)
            
            # Create desktop entry file
            desktop_path = os.path.join(autostart_dir, f"{self.app_name.lower().replace(' ', '_')}.desktop")
            
            with open(desktop_path, "w") as f:
                f.write(
                    f"[Desktop Entry]\n"
                    f"Type=Application\n"
                    f"Name={self.app_name}\n"
                    f"Exec={self.app_path} {self.script_path} --minimized\n"
                    f"Terminal=false\n"
                    f"Hidden=false\n"
                )
            
            # Make the file executable
            os.chmod(desktop_path, 0o755)
            
            logger.info(f"Added {self.app_name} to Linux startup")
            return True
            
        except Exception as e:
            logger.error(f"Error adding to Linux startup: {e}")
            return False
    
    def _disable_linux(self):
        """Disable auto-start on Linux by removing desktop entry."""
        try:
            # Remove desktop entry file
            desktop_path = os.path.expanduser(
                f"~/.config/autostart/{self.app_name.lower().replace(' ', '_')}.desktop"
            )
            
            if os.path.exists(desktop_path):
                os.remove(desktop_path)
                logger.info(f"Removed {self.app_name} from Linux startup")
            
            return True
            
        except Exception as e:
            logger.error(f"Error removing from Linux startup: {e}")
            return False
    
    def _is_enabled_linux(self):
        """Check if auto-start is enabled on Linux."""
        try:
            # Check if desktop entry file exists
            desktop_path = os.path.expanduser(
                f"~/.config/autostart/{self.app_name.lower().replace(' ', '_')}.desktop"
            )
            
            return os.path.exists(desktop_path)
            
        except Exception as e:
            logger.error(f"Error checking Linux startup status: {e}")
            return False
