#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Icons for Viros Mitm
Contains base64-encoded SVG icons for the application.
"""

import base64

def get_app_icon_data():
    """
    Get the main application icon as bytes.
    
    Returns:
        bytes: Icon data
    """
    # Simple PNG-like data (1x1 pixel, blue) to avoid SVG parsing issues
    icon_data = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xfa\xcf\x00\x00\x02\x00\x01\xe5\'\xde\xfc\x00\x00\x00\x00IEND\xaeB`\x82'
    return icon_data

def get_help_icon_data():
    """
    Get the help icon as bytes.
    
    Returns:
        bytes: Icon data
    """
    # Simple PNG-like data (1x1 pixel, gray) to avoid SVG parsing issues
    icon_data = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\x90\x90\x90\x00\x00\x02\x00\x01H\xaf\xa4q\x00\x00\x00\x00IEND\xaeB`\x82'
    return icon_data

def get_settings_icon_data():
    """
    Get the settings icon as bytes.
    
    Returns:
        bytes: Icon data
    """
    # Simple PNG-like data (1x1 pixel, dark gray) to avoid SVG parsing issues
    icon_data = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc````\x00\x00\x00\x04\x00\x01\xf6\x178\x1f\x00\x00\x00\x00IEND\xaeB`\x82'
    return icon_data

def get_scan_icon_data():
    """
    Get the scan icon as bytes.
    
    Returns:
        bytes: Icon data
    """
    # Simple PNG-like data (1x1 pixel, green) to avoid SVG parsing issues
    icon_data = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\x00\xff\x00\x00\x00\x00\x01\x01\x01\x00#\xe7\xf8\xc2\x00\x00\x00\x00IEND\xaeB`\x82'
    return icon_data

def get_warning_icon_data():
    """
    Get the warning icon as bytes.
    
    Returns:
        bytes: Icon data
    """
    # Simple PNG-like data (1x1 pixel, orange) to avoid SVG parsing issues
    icon_data = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xfc\x8f\x0f\x00\x00\x02\x00\x01#\x13\x00\x00\x00\x00\x00IEND\xaeB`\x82'
    return icon_data

def get_critical_icon_data():
    """
    Get the critical icon as bytes.
    
    Returns:
        bytes: Icon data
    """
    # Simple PNG-like data (1x1 pixel, red) to avoid SVG parsing issues
    icon_data = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xfc\x07\x00\x00\x00\x02\x00\x01#\xf7\x1c\x0f\x00\x00\x00\x00IEND\xaeB`\x82'
    return icon_data
