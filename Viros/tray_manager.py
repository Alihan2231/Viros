#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
System Tray Manager for Viros Mitm
Provides system tray functionality using pystray for Windows and Linux.
"""

import threading
import base64
import logging
import io
import time
from PIL import Image

logger = logging.getLogger(__name__)

class TrayManager:
    """Manages the system tray icon and menu."""
    
    def __init__(self, tooltip, icon_data, menu_items=None):
        """
        Initialize the tray manager.
        
        Args:
            tooltip: Tooltip text to display on hover
            icon_data: Base64 or bytes of the icon image
            menu_items: List of dicts with 'text' and 'command' keys
        """
        self.tooltip = tooltip
        self.icon_data = icon_data
        self.menu_items = menu_items or []
        self.pystray_icon = None
        self.click_handler = None
        
        # Initialize tray in a separate thread to avoid blocking
        threading.Thread(target=self._setup_tray, daemon=True).start()
    
    def _setup_tray(self):
        """Set up the system tray icon."""
        try:
            # Import here to avoid module import errors if not available
            # This allows the application to run even if pystray is not installed
            import pystray
            from pystray import MenuItem as item
            
            try:
                # Handle different icon data types
                if isinstance(self.icon_data, Image.Image):
                    # Directly use PIL Image
                    icon_image = self.icon_data
                elif isinstance(self.icon_data, bytes):
                    # Try to load from bytes
                    icon_image = Image.open(io.BytesIO(self.icon_data))
                elif isinstance(self.icon_data, str):
                    # Assume base64 string
                    icon_bytes = base64.b64decode(self.icon_data)
                    icon_image = Image.open(io.BytesIO(icon_bytes))
                else:
                    raise ValueError("Icon data must be PIL Image, bytes or base64 string")
            except Exception as e:
                logger.warning(f"Failed to load icon data: {e}, using fallback icon")
                # Create a simple colored icon as fallback
                icon_image = Image.new('RGB', (64, 64), color=(0, 120, 212))
            
            # Create menu items
            menu_items = []
            for menu_item in self.menu_items:
                menu_items.append(item(menu_item["text"], menu_item["command"]))
            
            # Create tray icon
            self.pystray_icon = pystray.Icon(
                "Viros_Mitm",
                icon_image,
                self.tooltip,
                menu=pystray.Menu(*menu_items)
            )
            
            # Set click handler if defined
            if self.click_handler:
                self.pystray_icon.on_click = self.click_handler
            
            # Run the icon (blocks until removed)
            self.pystray_icon.run()
            
        except ImportError as e:
            logger.error(f"Failed to import pystray: {e}")
            logger.warning("System tray functionality will be disabled")
        except Exception as e:
            logger.error(f"Error setting up system tray: {e}")
    
    def set_click_handler(self, handler):
        """
        Set the function to call when the tray icon is clicked.
        
        Args:
            handler: Function to call on click
        """
        self.click_handler = handler
        
        # Update existing icon if it's running
        if self.pystray_icon:
            self.pystray_icon.on_click = handler
    
    def update_menu(self, menu_items):
        """
        Update the tray icon menu.
        
        Args:
            menu_items: List of dicts with 'text' and 'command' keys
        """
        self.menu_items = menu_items
        
        # If icon is running, need to recreate it
        if self.pystray_icon:
            self.remove()
            threading.Thread(target=self._setup_tray, daemon=True).start()
    
    def remove(self):
        """Remove the tray icon."""
        if self.pystray_icon:
            try:
                self.pystray_icon.stop()
            except Exception as e:
                logger.error(f"Error removing tray icon: {e}")
            
            self.pystray_icon = None
