"""
Utility functions for CyberShield Streamlit Frontend
"""

import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from typing import Dict, Any, List, Optional, Union
import time
from datetime import datetime
import base64
import io

from config import FASTAPI_URL, API_CONFIG, RISK_COLORS, IOC_ICONS, CHART_COLORS

class APIClient:
    """Client for FastAPI backend communication"""
    
    def __init__(self, base_url: str = FASTAPI_URL):
        self.base_url = base_url
        self.timeout = API_CONFIG["timeout"]
        self.max_retries = API_CONFIG["max_retries"]
        self.retry_delay = API_CONFIG["retry_delay"]
    
    def _make_request(self, endpoint: str, method: str = "GET", 
                     data: Dict = None, files: Dict = None, 
                     params: Dict = None) -> Optional[Dict]:
        """Make HTTP request with error handling and retries"""
        url = f"{self.base_url}{endpoint}"
        
        for attempt in range(self.max_retries):
            try:
                if method == "GET":
                    response = requests.get(url, params=params, timeout=self.timeout)
                elif method == "POST":
                    if files:
                        response = requests.post(url, data=data, files=files, timeout=self.timeout)
                    else:
                        response = requests.post(url, json=data, timeout=self.timeout)
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")
                
                if response.status_code == 200:
                    return response.json()
                else:
                    error_msg = f"API Error {response.status_code}: {response.text}"
                    if attempt == self.max_retries - 1:
                        st.error(error_msg)
                    return None
                    
            except requests.exceptions.ConnectionError:
                error_msg = "❌ Cannot connect to FastAPI backend. Please ensure the server is running."
                if attempt == self.max_retries - 1:
                    st.error(error_msg)
                return None
            except requests.exceptions.Timeout:
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
                    continue
                st.error("⏱️ Request timed out. Please try again.")
                return None
            except Exception as e:
                if attempt == self.max_retries - 1:
                    st.error(f"Request failed: {str(e)}")
                return None
        
        return None
    
    def health_check(self) -> bool:
        """Check if backend is healthy"""
        result = self._make_request("/health")
        return result is not None and result.get("status") == "healthy"
    
    def get_status(self) -> Optional[Dict]:
        """Get system status"""
        return self._make_request("/status")
    
    def analyze_text(self, text: str, use_react_workflow: bool = True, 
                    include_vision: bool = False) -> Optional[Dict]:
        """Analyze text content"""
        return self._make_request("/analyze", "POST", {
            "text": text,
            "use_react_workflow": use_react_workflow,
            "include_vision": include_vision
        })
    
    def analyze_with_image(self, text: str, image_data: bytes, 
                          filename: str, use_react_workflow: bool = True) -> Optional[Dict]:
        """Analyze text with image"""
        files = {"image": (filename, image_data)}
        data = {
            "text": text,
            "use_react_workflow": use_react_workflow
        }
        return self._make_request("/analyze-with-image", "POST", data=data, files=files)
    
    def batch_analyze(self, inputs: List[str], use_react_workflow: bool = True) -> Optional[Dict]:
        """Analyze multiple text inputs"""
        return self._make_request("/batch-analyze", "POST", {
            "inputs": inputs,
            "use_react_workflow": use_react_workflow
        })
    
    def upload_image(self, image_data: bytes, filename: str) -> Optional[Dict]:
        """Analyze image only"""
        files = {"image": (filename, image_data)}
        return self._make_request("/upload-image", "POST", files=files)
    
    def check_ip_abuseipdb(self, ip_address: str) -> Optional[Dict]:
        """Check IP with AbuseIPDB"""
        return self._make_request("/tools/abuseipdb/check", "POST", {"ip_address": ip_address})
    
    def lookup_ip_shodan(self, ip_address: str) -> Optional[Dict]:
        """Lookup IP with Shodan"""
        return self._make_request("/tools/shodan/lookup", "POST", {"ip_address": ip_address})
    
    def lookup_virustotal(self, resource: str, resource_type: str = "ip") -> Optional[Dict]:
        """Lookup resource with VirusTotal"""
        return self._make_request("/tools/virustotal/lookup", "POST", {
            "resource": resource,
            "resource_type": resource_type
        })
    
    def extract_iocs(self, text: str) -> Optional[Dict]:
        """Extract IOCs using regex"""
        return self._make_request("/tools/regex/extract", "POST", {"text": text})
    
    def validate_pattern(self, text: str, pattern_type: str) -> Optional[Dict]:
        """Validate pattern"""
        return self._make_request("/tools/regex/validate", "POST", {
            "text": text,
            "pattern_type": pattern_type
        })

class DataVisualizer:
    """Utility class for creating data visualizations"""
    
    @staticmethod
    def create_ioc_chart(ioc_data: Dict[str, List]) -> go.Figure:
        """Create IOC distribution chart"""
        ioc_counts = {k: len(v) for k, v in ioc_data.items() if v}
        
        if not ioc_counts:
            return None
        
        fig = px.bar(
            x=list(ioc_counts.keys()),
            y=list(ioc_counts.values()),
            title="IOCs by Type",
            color=list(ioc_counts.values()),
            color_continuous_scale="Reds"
        )
        
        fig.update_layout(
            xaxis_title="IOC Type",
            yaxis_title="Count",
            showlegend=False
        )
        
        return fig
    
    @staticmethod
    def create_threat_level_chart(threat_data: Dict) -> go.Figure:
        """Create threat level distribution chart"""
        levels = ["high_risk_count", "medium_risk_count", "low_risk_count"]
        counts = [threat_data.get(level, 0) for level in levels]
        labels = ["High", "Medium", "Low"]
        colors = [CHART_COLORS["danger"], CHART_COLORS["warning"], CHART_COLORS["success"]]
        
        fig = go.Figure(data=[
            go.Pie(
                labels=labels,
                values=counts,
                marker_colors=colors,
                hole=0.3
            )
        ])
        
        fig.update_layout(
            title="Threat Level Distribution",
            showlegend=True
        )
        
        return fig
    
    @staticmethod
    def create_timeline_chart(data: List[Dict], date_field: str, value_field: str) -> go.Figure:
        """Create timeline chart"""
        df = pd.DataFrame(data)
        
        if df.empty:
            return None
        
        fig = px.line(
            df,
            x=date_field,
            y=value_field,
            title="Analysis Timeline"
        )
        
        return fig

class UIHelpers:
    """UI helper functions"""
    
    @staticmethod
    def display_metric_card(title: str, value: Union[str, int, float], 
                           delta: Optional[str] = None, 
                           help_text: Optional[str] = None):
        """Display a metric card"""
        st.metric(
            label=title,
            value=value,
            delta=delta,
            help=help_text
        )
    
    @staticmethod
    def display_status_badge(status: str, text: str = None):
        """Display status badge with appropriate color"""
        if text is None:
            text = status.title()
        
        colors = {
            "success": "🟢",
            "warning": "🟡", 
            "error": "🔴",
            "info": "🔵",
            "pending": "🟡"
        }
        
        icon = colors.get(status.lower(), "⚪")
        st.markdown(f"{icon} **{text}**")
    
    @staticmethod
    def display_risk_level(risk_level: str):
        """Display risk level with appropriate styling"""
        icon = RISK_COLORS.get(risk_level.lower(), "⚪")
        
        if risk_level.lower() == "high":
            st.error(f"{icon} High Risk")
        elif risk_level.lower() == "medium":
            st.warning(f"{icon} Medium Risk")
        elif risk_level.lower() == "low":
            st.success(f"{icon} Low Risk")
        else:
            st.info(f"{icon} {risk_level.title()} Risk")
    
    @staticmethod
    def display_ioc_list(iocs: Dict[str, List], max_items: int = 10):
        """Display IOC list with icons"""
        for ioc_type, ioc_list in iocs.items():
            if ioc_list:
                icon = IOC_ICONS.get(ioc_type, "📄")
                
                with st.expander(f"{icon} {ioc_type.replace('_', ' ').title()} ({len(ioc_list)})"):
                    displayed = 0
                    for ioc in ioc_list:
                        if displayed >= max_items:
                            st.write(f"... and {len(ioc_list) - max_items} more")
                            break
                        st.code(ioc)
                        displayed += 1
    
    @staticmethod
    def display_progress_bar(current: int, total: int, text: str = "Progress"):
        """Display progress bar"""
        if total > 0:
            progress = current / total
            st.progress(progress, text=f"{text}: {current}/{total}")
    
    @staticmethod
    def display_json_expandable(data: Dict, title: str = "Details"):
        """Display JSON data in expandable section"""
        with st.expander(title):
            st.json(data)

class FileUtils:
    """File handling utilities"""
    
    @staticmethod
    def validate_file_size(file_size: int, max_size: int = 10 * 1024 * 1024) -> bool:
        """Validate file size"""
        return file_size <= max_size
    
    @staticmethod
    def validate_file_type(filename: str, allowed_types: List[str]) -> bool:
        """Validate file type"""
        if not filename:
            return False
        
        extension = filename.split('.')[-1].lower()
        return extension in allowed_types
    
    @staticmethod
    def encode_image(image_data: bytes) -> str:
        """Encode image to base64"""
        return base64.b64encode(image_data).decode()
    
    @staticmethod
    def process_csv_file(file_content: str) -> List[str]:
        """Process CSV file and extract text from first column"""
        try:
            df = pd.read_csv(io.StringIO(file_content))
            return df.iloc[:, 0].astype(str).tolist()
        except Exception as e:
            st.error(f"Error processing CSV: {e}")
            return []
    
    @staticmethod
    def process_text_file(file_content: str) -> List[str]:
        """Process text file and split into lines"""
        return [line.strip() for line in file_content.split('\n') if line.strip()]

class CacheManager:
    """Simple caching for API results"""
    
    def __init__(self):
        if 'cache' not in st.session_state:
            st.session_state.cache = {}
    
    def get(self, key: str) -> Optional[Any]:
        """Get cached value"""
        cache_entry = st.session_state.cache.get(key)
        if cache_entry:
            timestamp, value = cache_entry
            # Check if cache is expired (5 minutes)
            if time.time() - timestamp < 300:
                return value
            else:
                # Remove expired entry
                del st.session_state.cache[key]
        return None
    
    def set(self, key: str, value: Any):
        """Set cached value"""
        st.session_state.cache[key] = (time.time(), value)
    
    def clear(self):
        """Clear all cache"""
        st.session_state.cache = {}

def format_timestamp(timestamp: Union[str, datetime]) -> str:
    """Format timestamp for display"""
    if isinstance(timestamp, str):
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        except:
            return timestamp
    else:
        dt = timestamp
    
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")

def truncate_text(text: str, max_length: int = 100) -> str:
    """Truncate text with ellipsis"""
    if len(text) <= max_length:
        return text
    return text[:max_length] + "..."

def format_file_size(size_bytes: int) -> str:
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024
        i += 1
    
    return f"{size_bytes:.1f} {size_names[i]}"