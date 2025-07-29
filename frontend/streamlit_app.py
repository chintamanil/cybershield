#!/usr/bin/env python3
"""
CyberShield Streamlit Frontend
A comprehensive UI for the CyberShield AI Security System
"""

import streamlit as st
import requests
import pandas as pd
from typing import Dict, Any, Optional
import io
from PIL import Image
import plotly.express as px

# Configure page
st.set_page_config(
    page_title="CyberShield AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Configuration
FASTAPI_URL = "http://localhost:8000"

# Custom CSS
st.markdown("""
<style>
.main-header {
    font-size: 3rem;
    color: #2c3e50;
    text-align: center;
    margin-bottom: 2rem;
}
.section-header {
    font-size: 1.5rem;
    color: #34495e;
    border-bottom: 2px solid #3498db;
    padding-bottom: 0.5rem;
    margin: 1rem 0;
}
.status-card {
    background-color: #f8f9fa;
    padding: 1rem;
    border-radius: 0.5rem;
    border-left: 4px solid #28a745;
    margin: 1rem 0;
}
.error-card {
    background-color: #f8d7da;
    padding: 1rem;
    border-radius: 0.5rem;
    border-left: 4px solid #dc3545;
    margin: 1rem 0;
}
.metric-card {
    background-color: #e3f2fd;
    padding: 1rem;
    border-radius: 0.5rem;
    text-align: center;
    margin: 0.5rem;
}
</style>
""", unsafe_allow_html=True)

def make_api_request(endpoint: str, method: str = "GET", data: Dict = None, files: Dict = None) -> Optional[Dict]:
    """Make API request to FastAPI backend"""
    try:
        url = f"{FASTAPI_URL}{endpoint}"
        
        if method == "GET":
            response = requests.get(url)
        elif method == "POST":
            if files:
                response = requests.post(url, data=data, files=files)
            else:
                response = requests.post(url, json=data)
        else:
            st.error(f"Unsupported HTTP method: {method}")
            return None
        
        if response.status_code == 200:
            return response.json()
        else:
            st.error(f"API Error {response.status_code}: {response.text}")
            return None
            
    except requests.exceptions.ConnectionError:
        st.error("❌ Cannot connect to FastAPI backend. Please ensure the server is running on http://localhost:8000")
        return None
    except Exception as e:
        st.error(f"Request failed: {str(e)}")
        return None

def display_analysis_results(results: Dict[str, Any]):
    """Display analysis results in a formatted way"""
    if not results:
        return
    
    # Main status
    status = results.get("status", "unknown")
    if status == "success":
        st.success("✅ Analysis completed successfully")
    else:
        st.error(f"❌ Analysis failed: {status}")
    
    # Processing time
    if "processing_time" in results:
        st.info(f"⏱️ Processing time: {results['processing_time']:.2f} seconds")
    
    # Results
    if "result" in results:
        result = results["result"]
        
        # Create tabs for different analysis types
        tabs = []
        tab_names = []
        
        if "pii_analysis" in result:
            tab_names.append("🔒 PII Analysis")
            tabs.append("pii")
        
        if "ioc_analysis" in result:
            tab_names.append("🚨 IOC Analysis")
            tabs.append("ioc")
        
        if "threat_analysis" in result:
            tab_names.append("⚠️ Threat Analysis")
            tabs.append("threat")
        
        if "vision_analysis" in result:
            tab_names.append("📷 Vision Analysis")
            tabs.append("vision")
        
        if "tool_analysis" in result:
            tab_names.append("🔧 Tool Analysis")
            tabs.append("tools")
        
        if "recommendations" in result:
            tab_names.append("💡 Recommendations")
            tabs.append("recommendations")
        
        if tab_names:
            tab_objects = st.tabs(tab_names)
            
            for i, tab_type in enumerate(tabs):
                with tab_objects[i]:
                    if tab_type == "pii":
                        display_pii_analysis(result["pii_analysis"])
                    elif tab_type == "ioc":
                        display_ioc_analysis(result["ioc_analysis"])
                    elif tab_type == "threat":
                        display_threat_analysis(result["threat_analysis"])
                    elif tab_type == "vision":
                        display_vision_analysis(result["vision_analysis"])
                    elif tab_type == "tools":
                        display_tool_analysis(result["tool_analysis"])
                    elif tab_type == "recommendations":
                        display_recommendations(result["recommendations"])

def display_pii_analysis(pii_data: Dict):
    """Display PII analysis results"""
    st.markdown('<div class="section-header">PII Detection Results</div>', unsafe_allow_html=True)
    
    # Handle None or empty PII data
    if not pii_data:
        st.info("No PII analysis data available")
        return
    
    if pii_data.get("pii_detected"):
        st.warning("🔒 Personally Identifiable Information (PII) detected!")
        
        if "pii_mapping" in pii_data:
            st.subheader("Detected PII:")
            pii_df = []
            for token, info in pii_data["pii_mapping"].items():
                pii_df.append({
                    "Token": token,
                    "Type": info.get("type", "Unknown"),
                    "Original": info.get("original", "Hidden"),
                    "Position": str(info.get("position", "Unknown"))
                })
            
            if pii_df:
                st.dataframe(pd.DataFrame(pii_df), use_container_width=True)
        
        if "masked_text" in pii_data:
            st.subheader("Masked Text:")
            st.code(pii_data["masked_text"], language="text")
    else:
        st.success("✅ No PII detected in the input")

def display_ioc_analysis(ioc_data: Dict):
    """Display IOC analysis results"""
    st.markdown('<div class="section-header">Indicators of Compromise (IOCs)</div>', unsafe_allow_html=True)
    
    # Handle None or empty IOC data
    if not ioc_data:
        st.info("No IOC analysis data available")
        return
    
    ioc_count = ioc_data.get("ioc_count", 0)
    total_count = ioc_data.get("total_ioc_count", ioc_count)
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric("IOCs Found", ioc_count)
    with col2:
        st.metric("Total IOCs", total_count)
    
    if "extracted_iocs" in ioc_data and ioc_data["extracted_iocs"]:
        st.subheader("Extracted IOCs:")
        iocs = ioc_data["extracted_iocs"]
        
        # Display IOCs by type
        for ioc_type, ioc_list in iocs.items():
            if ioc_list:
                with st.expander(f"{ioc_type.replace('_', ' ').title()} ({len(ioc_list)})"):
                    for ioc in ioc_list:
                        st.code(ioc)
    
    if "ocr_iocs" in ioc_data:
        st.subheader("IOCs from Image Text:")
        st.json(ioc_data["ocr_iocs"])

def display_threat_analysis(threat_data: Dict):
    """Display threat analysis results"""
    st.markdown('<div class="section-header">Threat Intelligence Analysis</div>', unsafe_allow_html=True)
    
    # Handle None or empty threat data
    if not threat_data:
        st.info("No threat analysis data available")
        return
    
    # Threat metrics
    metrics_cols = st.columns(4)
    
    with metrics_cols[0]:
        st.metric("High Risk", threat_data.get("high_risk_count", 0))
    with metrics_cols[1]:
        st.metric("Medium Risk", threat_data.get("medium_risk_count", 0))
    with metrics_cols[2]:
        st.metric("Low Risk", threat_data.get("low_risk_count", 0))
    with metrics_cols[3]:
        st.metric("Total Analyzed", threat_data.get("total_analyzed", 0))
    
    # Threat details
    if "threats" in threat_data:
        st.subheader("Threat Details:")
        for threat in threat_data["threats"]:
            risk_level = threat.get("risk_level", "unknown")
            color = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(risk_level, "⚪")
            
            with st.expander(f"{color} {threat.get('indicator', 'Unknown')} - {risk_level.title()} Risk"):
                st.json(threat)

def display_vision_analysis(vision_data: Dict):
    """Display vision analysis results"""
    st.markdown('<div class="section-header">Vision AI Analysis</div>', unsafe_allow_html=True)
    
    # Handle None or empty vision data
    if not vision_data:
        st.info("No vision analysis data available")
        return
    
    if vision_data.get("status") == "no_image_provided":
        st.info("ℹ️ No image was provided for analysis")
        return
    
    # OCR Results
    if "ocr" in vision_data:
        ocr_data = vision_data["ocr"]
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("OCR Confidence", f"{ocr_data.get('confidence', 0):.1f}%")
        with col2:
            st.metric("Words Extracted", ocr_data.get('word_count', 0))
        
        if ocr_data.get("text"):
            st.subheader("Extracted Text:")
            st.text_area("OCR Result", ocr_data["text"], height=150)
    
    # Classification Results
    if "classification" in vision_data:
        class_data = vision_data["classification"]
        
        st.subheader("Content Classification:")
        if "classifications" in class_data:
            for classification in class_data["classifications"][:5]:  # Show top 5
                confidence = classification.get("score", 0) * 100
                st.progress(confidence / 100, text=f"{classification.get('label', 'Unknown')}: {confidence:.1f}%")
        
        risk_level = class_data.get("risk_level", "none")
        risk_colors = {"high": "🔴", "medium": "🟡", "low": "🟢", "none": "⚪"}
        st.write(f"**Risk Level:** {risk_colors.get(risk_level, '⚪')} {risk_level.title()}")
    
    # Sensitive Content Analysis
    if "sensitive_analysis" in vision_data:
        sensitive_data = vision_data["sensitive_analysis"]
        overall_risk = sensitive_data.get("overall_risk", "none")
        
        st.subheader(f"Overall Security Risk: {overall_risk.title()}")
        
        if "text_analysis" in sensitive_data:
            text_analysis = sensitive_data["text_analysis"]
            if text_analysis.get("pii_detected"):
                st.warning("🔒 PII detected in image text!")
                for pii in text_analysis["pii_detected"]:
                    st.write(f"- {pii['type'].title()}: {pii['count']} instances")

def display_tool_analysis(tool_data: Dict):
    """Display tool analysis results"""
    st.markdown('<div class="section-header">Security Tool Analysis</div>', unsafe_allow_html=True)
    
    # Handle None or empty tool data
    if not tool_data:
        st.info("No tool analysis data available")
        return
    
    # IOC Extraction
    if "ioc_extraction" in tool_data:
        st.subheader("IOC Extraction Results:")
        iocs = tool_data["ioc_extraction"]
        
        # Create visualization of IOC types
        ioc_counts = {k: len(v) for k, v in iocs.items() if v}
        if ioc_counts:
            fig = px.bar(
                x=list(ioc_counts.keys()),
                y=list(ioc_counts.values()),
                title="IOCs by Type"
            )
            st.plotly_chart(fig, use_container_width=True)
    
    # Threat Intelligence
    if "threat_intelligence" in tool_data:
        st.subheader("Threat Intelligence Results:")
        threat_intel = tool_data["threat_intelligence"]
        
        for ip, results in threat_intel.items():
            with st.expander(f"IP Analysis: {ip}"):
                
                # AbuseIPDB Results
                if "abuseipdb" in results:
                    adb_data = results["abuseipdb"]
                    if "error" not in adb_data:
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Abuse Confidence", f"{adb_data.get('abuse_confidence', 0)}%")
                        with col2:
                            st.metric("Total Reports", adb_data.get('total_reports', 0))
                        with col3:
                            is_whitelisted = adb_data.get('is_whitelisted', False)
                            st.metric("Whitelisted", "✅" if is_whitelisted else "❌")
                
                # Shodan Results
                if "shodan" in results:
                    shodan_data = results["shodan"]
                    if "error" not in shodan_data and "hostnames" in shodan_data:
                        st.write("**Hostnames:**", ", ".join(shodan_data["hostnames"][:3]))
                        if "org" in shodan_data:
                            st.write("**Organization:**", shodan_data["org"])
                
                # VirusTotal Results
                if "virustotal" in results:
                    vt_data = results["virustotal"]
                    if "error" not in vt_data:
                        if "stats" in vt_data:
                            stats = vt_data["stats"]
                            col1, col2 = st.columns(2)
                            with col1:
                                st.metric("Malicious", stats.get("malicious", 0))
                            with col2:
                                st.metric("Suspicious", stats.get("suspicious", 0))

def display_recommendations(recommendations: list):
    """Display security recommendations"""
    st.markdown('<div class="section-header">Security Recommendations</div>', unsafe_allow_html=True)
    
    for i, recommendation in enumerate(recommendations, 1):
        st.markdown(f"**{i}.** {recommendation}")

def main():
    """Main Streamlit application"""
    
    # Header
    st.markdown('<div class="main-header">🛡️ CyberShield AI Security System</div>', unsafe_allow_html=True)
    st.markdown("Advanced multi-agent AI system for cybersecurity analysis")
    
    # Sidebar
    with st.sidebar:
        st.markdown("## 🔧 System Controls")
        
        # System Status
        if st.button("🔍 Check System Status", use_container_width=True):
            status = make_api_request("/status")
            if status:
                st.success("✅ System Online")
                st.json(status)
            else:
                st.error("❌ System Offline")
        
        st.markdown("---")
        
        # Analysis Options
        st.markdown("## ⚙️ Analysis Options")
        use_react_workflow = st.checkbox("Use ReAct Workflow", value=True, help="Enable intelligent multi-step reasoning")
        include_vision = st.checkbox("Include Vision Analysis", value=False, help="Process any uploaded images")
        
        st.markdown("---")
        
        # Quick Tools
        st.markdown("## 🛠️ Quick Tools")
        
        # IP Check
        st.markdown("### IP Reputation Check")
        ip_input = st.text_input("IP Address", placeholder="8.8.8.8")
        if st.button("Check IP", use_container_width=True) and ip_input:
            with st.spinner("Checking IP reputation..."):
                result = make_api_request("/tools/abuseipdb/check", "POST", {"ip_address": ip_input})
                if result:
                    st.json(result)
        
        # Domain Check
        st.markdown("### Domain Analysis")
        domain_input = st.text_input("Domain", placeholder="example.com")
        if st.button("Analyze Domain", use_container_width=True) and domain_input:
            with st.spinner("Analyzing domain..."):
                result = make_api_request("/tools/virustotal/lookup", "POST", {
                    "resource": domain_input, 
                    "resource_type": "domain"
                })
                if result:
                    st.json(result)
    
    # Main content area
    main_tab, batch_tab, image_tab, tools_tab = st.tabs([
        "🔍 Single Analysis", 
        "📊 Batch Analysis", 
        "📷 Image Analysis", 
        "🔧 Advanced Tools"
    ])
    
    with main_tab:
        st.markdown("## Text Analysis")
        st.markdown("Analyze text for security threats, PII, and indicators of compromise.")
        
        # Text input
        text_input = st.text_area(
            "Enter text to analyze:",
            placeholder="Paste logs, emails, or any text content here...",
            height=200
        )
        
        col1, col2 = st.columns([2, 1])
        with col1:
            analyze_btn = st.button("🔍 Analyze Text", type="primary", use_container_width=True)
        with col2:
            clear_btn = st.button("🗑️ Clear", use_container_width=True)
        
        if clear_btn:
            st.rerun()
        
        if analyze_btn and text_input:
            with st.spinner("Analyzing text..."):
                result = make_api_request("/analyze", "POST", {
                    "text": text_input,
                    "use_react_workflow": use_react_workflow,
                    "include_vision": include_vision
                })
                
                if result:
                    display_analysis_results(result)
    
    with batch_tab:
        st.markdown("## Batch Analysis")
        st.markdown("Analyze multiple text inputs simultaneously.")
        
        # Batch input options
        input_method = st.radio("Input Method:", ["Manual Entry", "Upload File"])
        
        inputs = []
        
        if input_method == "Manual Entry":
            st.markdown("Enter multiple texts (one per line):")
            batch_text = st.text_area(
                "Batch Input:",
                placeholder="Line 1: First text to analyze\nLine 2: Second text to analyze\n...",
                height=200
            )
            
            if batch_text:
                inputs = [line.strip() for line in batch_text.split('\n') if line.strip()]
                st.info(f"Found {len(inputs)} inputs to analyze")
        
        elif input_method == "Upload File":
            uploaded_file = st.file_uploader("Choose a text file", type=['txt', 'csv'])
            
            if uploaded_file:
                try:
                    content = uploaded_file.read().decode('utf-8')
                    if uploaded_file.type == 'text/csv':
                        # Assume first column contains text to analyze
                        df = pd.read_csv(io.StringIO(content))
                        inputs = df.iloc[:, 0].astype(str).tolist()
                    else:
                        inputs = [line.strip() for line in content.split('\n') if line.strip()]
                    
                    st.success(f"Loaded {len(inputs)} inputs from file")
                    
                    # Show preview
                    if inputs:
                        with st.expander("Preview (first 5 entries)"):
                            for i, inp in enumerate(inputs[:5], 1):
                                st.write(f"{i}. {inp[:100]}{'...' if len(inp) > 100 else ''}")
                
                except Exception as e:
                    st.error(f"Error reading file: {e}")
        
        if inputs and st.button("🔍 Analyze Batch", type="primary", use_container_width=True):
            with st.spinner(f"Analyzing {len(inputs)} inputs..."):
                result = make_api_request("/batch-analyze", "POST", {
                    "inputs": inputs,
                    "use_react_workflow": use_react_workflow
                })
                
                if result:
                    st.success(f"✅ Batch analysis completed!")
                    st.info(f"⏱️ Processing time: {result.get('processing_time', 0):.2f} seconds")
                    
                    if "results" in result:
                        # Display summary
                        results_data = result["results"]
                        st.markdown("### Batch Results Summary")
                        
                        # Create results dataframe for overview
                        summary_data = []
                        for i, res in enumerate(results_data, 1):
                            pii_detected = res.get("pii_analysis", {}).get("pii_detected", False)
                            ioc_count = res.get("ioc_analysis", {}).get("ioc_count", 0)
                            threat_level = res.get("threat_analysis", {}).get("overall_risk", "low")
                            
                            summary_data.append({
                                "Input #": i,
                                "PII Detected": "Yes" if pii_detected else "No",
                                "IOCs Found": ioc_count,
                                "Threat Level": threat_level.title(),
                                "Status": res.get("status", "unknown").title()
                            })
                        
                        summary_df = pd.DataFrame(summary_data)
                        st.dataframe(summary_df, use_container_width=True)
                        
                        # Detailed results
                        st.markdown("### Detailed Results")
                        for i, res in enumerate(results_data, 1):
                            with st.expander(f"Result {i}"):
                                display_analysis_results({"status": "success", "result": res})
    
    with image_tab:
        st.markdown("## Image Analysis")
        st.markdown("Analyze images for security risks, extract text, and detect sensitive content.")
        
        # Image upload
        uploaded_image = st.file_uploader(
            "Choose an image file",
            type=['png', 'jpg', 'jpeg', 'gif', 'bmp'],
            help="Upload an image to analyze for security risks and extract text"
        )
        
        # Text to accompany image
        image_text = st.text_area(
            "Additional text context (optional):",
            placeholder="Provide context about the image or additional text to analyze...",
            height=100
        )
        
        if uploaded_image:
            # Display image preview
            image = Image.open(uploaded_image)
            st.image(image, caption="Uploaded Image", use_column_width=True)
            
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("🔍 Analyze Image Only", use_container_width=True):
                    with st.spinner("Analyzing image..."):
                        files = {"image": uploaded_image.getvalue()}
                        result = make_api_request("/upload-image", "POST", files=files)
                        
                        if result:
                            display_analysis_results(result)
            
            with col2:
                if st.button("🔍 Analyze Image + Text", use_container_width=True):
                    with st.spinner("Analyzing image and text..."):
                        files = {"image": uploaded_image.getvalue()}
                        data = {
                            "text": image_text or "",
                            "use_react_workflow": use_react_workflow
                        }
                        result = make_api_request("/analyze-with-image", "POST", data=data, files=files)
                        
                        if result:
                            display_analysis_results(result)
    
    with tools_tab:
        st.markdown("## Advanced Security Tools")
        st.markdown("Direct access to individual security analysis tools.")
        
        tool_cols = st.columns(2)
        
        with tool_cols[0]:
            st.markdown("### 🔍 IOC Extraction")
            ioc_text = st.text_area("Text for IOC extraction:", height=150)
            
            if st.button("Extract IOCs", use_container_width=True) and ioc_text:
                with st.spinner("Extracting IOCs..."):
                    result = make_api_request("/tools/regex/extract", "POST", {"text": ioc_text})
                    if result:
                        st.json(result)
            
            st.markdown("### 🌐 Shodan Lookup")
            shodan_ip = st.text_input("IP for Shodan lookup:")
            
            if st.button("Lookup with Shodan", use_container_width=True) and shodan_ip:
                with st.spinner("Querying Shodan..."):
                    result = make_api_request("/tools/shodan/lookup", "POST", {"ip_address": shodan_ip})
                    if result:
                        st.json(result)
        
        with tool_cols[1]:
            st.markdown("### 🔒 Hash Analysis")
            hash_input = st.text_input("File hash (MD5/SHA1/SHA256):")
            
            if st.button("Analyze Hash", use_container_width=True) and hash_input:
                with st.spinner("Analyzing hash..."):
                    result = make_api_request("/tools/virustotal/lookup", "POST", {
                        "resource": hash_input,
                        "resource_type": "hash"
                    })
                    if result:
                        st.json(result)
            
            st.markdown("### ✅ Pattern Validation")
            validation_text = st.text_input("Text to validate:")
            pattern_type = st.selectbox("Pattern type:", ["ip", "domain", "hash", "url"])
            
            if st.button("Validate Pattern", use_container_width=True) and validation_text:
                with st.spinner("Validating pattern..."):
                    result = make_api_request("/tools/regex/validate", "POST", {
                        "text": validation_text,
                        "pattern_type": pattern_type
                    })
                    if result:
                        st.json(result)

if __name__ == "__main__":
    main()