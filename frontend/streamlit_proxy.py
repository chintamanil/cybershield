#!/usr/bin/env python3
"""
Simple proxy wrapper for Streamlit to handle base path properly
"""

import streamlit as st
import os

# Configure Streamlit for proxy/ALB setup
st.set_page_config(
    page_title="CyberShield AI - Frontend",
    page_icon="🛡️", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# Import the main Streamlit app
import sys
sys.path.append('/app/frontend')

# Import and run the main application
try:
    from streamlit_app import *
except ImportError as e:
    st.error(f"Failed to import main application: {e}")
    st.info("This is a simple proxy test page for CyberShield")
    st.write("If you can see this, the Streamlit server is working!")
    
    # Show environment info for debugging
    st.subheader("Environment Information")
    st.write(f"USE_AWS_BACKEND: {os.getenv('USE_AWS_BACKEND', 'not set')}")
    st.write(f"AWS_BACKEND_URL: {os.getenv('AWS_BACKEND_URL', 'not set')}")
    st.write(f"Base URL Path: {os.getenv('STREAMLIT_SERVER_BASE_URL_PATH', 'not set')}")