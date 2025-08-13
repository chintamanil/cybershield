#!/bin/bash
# Simple health check script for Streamlit application

# Check if Streamlit is responding on port 8501
if curl -f -s --max-time 5 http://localhost:8501 > /dev/null 2>&1; then
    echo "Streamlit is healthy"
    exit 0
else
    echo "Streamlit health check failed"
    exit 1
fi