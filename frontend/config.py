"""
Configuration settings for CyberShield Streamlit Frontend
"""

import os
from typing import Dict, Any

# FastAPI Backend Configuration
FASTAPI_HOST = os.getenv("FASTAPI_HOST", "localhost")
FASTAPI_PORT = os.getenv("FASTAPI_PORT", "8000")
FASTAPI_URL = f"http://{FASTAPI_HOST}:{FASTAPI_PORT}"

# Streamlit Configuration
STREAMLIT_CONFIG = {
    "page_title": "CyberShield AI",
    "page_icon": "🛡️",
    "layout": "wide",
    "initial_sidebar_state": "expanded"
}

# UI Theme Configuration
THEME_CONFIG = {
    "primary_color": "#3498db",
    "background_color": "#ffffff",
    "secondary_background_color": "#f0f2f6",
    "text_color": "#262730",
    "font": "sans serif"
}

# Chart Colors
CHART_COLORS = {
    "primary": "#3498db",
    "success": "#28a745",
    "warning": "#ffc107",
    "danger": "#dc3545",
    "info": "#17a2b8",
    "light": "#f8f9fa",
    "dark": "#343a40"
}

# Risk Level Colors
RISK_COLORS = {
    "high": "🔴",
    "medium": "🟡", 
    "low": "🟢",
    "none": "⚪",
    "unknown": "⚫"
}

# IOC Type Icons
IOC_ICONS = {
    "ip": "🌐",
    "domain": "🏗️",
    "url": "🔗",
    "email": "📧",
    "hash": "🔒",
    "mac_address": "📱",
    "phone": "📞",
    "cryptocurrency": "💰"
}

# Analysis Type Configuration
ANALYSIS_TYPES = {
    "pii": {
        "name": "PII Detection",
        "icon": "🔒",
        "description": "Detect personally identifiable information"
    },
    "ioc": {
        "name": "IOC Extraction", 
        "icon": "🚨",
        "description": "Extract indicators of compromise"
    },
    "threat": {
        "name": "Threat Analysis",
        "icon": "⚠️",
        "description": "Analyze security threats"
    },
    "vision": {
        "name": "Vision Analysis",
        "icon": "📷",
        "description": "Analyze images for security risks"
    },
    "tools": {
        "name": "Tool Analysis",
        "icon": "🔧",
        "description": "Security tool integration results"
    }
}

# File Upload Configuration
UPLOAD_CONFIG = {
    "max_file_size": 10 * 1024 * 1024,  # 10MB
    "allowed_image_types": ["png", "jpg", "jpeg", "gif", "bmp"],
    "allowed_text_types": ["txt", "csv", "json", "log"],
    "chunk_size": 1024 * 1024  # 1MB chunks
}

# API Configuration
API_CONFIG = {
    "timeout": 30,
    "max_retries": 3,
    "retry_delay": 1
}

# Cache Configuration
CACHE_CONFIG = {
    "ttl": 300,  # 5 minutes
    "max_entries": 100
}

def get_config() -> Dict[str, Any]:
    """Get complete configuration dictionary"""
    return {
        "fastapi": {
            "host": FASTAPI_HOST,
            "port": FASTAPI_PORT,
            "url": FASTAPI_URL
        },
        "streamlit": STREAMLIT_CONFIG,
        "theme": THEME_CONFIG,
        "charts": CHART_COLORS,
        "risks": RISK_COLORS,
        "iocs": IOC_ICONS,
        "analysis": ANALYSIS_TYPES,
        "upload": UPLOAD_CONFIG,
        "api": API_CONFIG,
        "cache": CACHE_CONFIG
    }