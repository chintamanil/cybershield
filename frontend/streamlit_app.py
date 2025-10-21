#!/usr/bin/env python3
"""
CyberShield Streamlit Frontend - Refactored
A comprehensive UI for the CyberShield AI Security System with modular architecture
"""

import uuid

import pandas as pd
import streamlit as st
from PIL import Image

# Configure page
st.set_page_config(
    page_title='CyberShield AI',
    page_icon='🛡️',
    layout='wide',
    initial_sidebar_state='expanded',
)

# Import modular components
from components.result_display import display_analysis_results
from components.session_components import (
    display_context_enrichment,
    render_request_history,
    render_session_management,
    save_request_to_history,
    track_session_id,
)
from components.sla_dashboard import render_sla_dashboard, render_sla_stats_sidebar
from config import FASTAPI_URL, USE_AWS_BACKEND
from lib.api_client import make_api_request
from server.monitoring import SLATracker

# Custom CSS
st.markdown(
    """
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
</style>
""",
    unsafe_allow_html=True,
)


def main():
    """Main Streamlit application"""

    # Header
    st.markdown(
        '<div class="main-header">🛡️ CyberShield AI Security System</div>',
        unsafe_allow_html=True,
    )
    st.markdown('Advanced multi-agent AI system for cybersecurity analysis')

    # Backend status indicator
    backend_type = '🌩️ AWS Cloud' if USE_AWS_BACKEND else '💻 Local'
    backend_url = FASTAPI_URL
    st.info(f'**Backend**: {backend_type} | **URL**: {backend_url}')

    # Sidebar
    render_sidebar()

    # Main content tabs
    main_tab, batch_tab, image_tab, tools_tab, sla_tab = st.tabs(
        [
            '🔍 Single Analysis',
            '📊 Batch Analysis',
            '📷 Image Analysis',
            '🔧 Advanced Tools',
            '⚡ SLA Dashboard',
        ]
    )

    with main_tab:
        render_single_analysis_tab()

    with batch_tab:
        render_batch_analysis_tab()

    with image_tab:
        render_image_analysis_tab()

    with tools_tab:
        render_tools_tab()

    with sla_tab:
        render_sla_tab()


def render_sidebar():
    """Render sidebar with system controls and options"""
    with st.sidebar:
        st.markdown('## 🔧 System Controls')

        # System Status
        if st.button('🔍 Check System Status', use_container_width=True):
            status = make_api_request('/status')
            if status:
                st.success('✅ System Online')
                display_system_status(status)
            else:
                st.error('❌ System Offline')

        st.markdown('---')

        # Analysis Options
        st.markdown('## ⚙️ Analysis Options')
        st.session_state.use_react_workflow = st.checkbox(
            'Use ReAct Workflow',
            value=True,
            help='Enable intelligent multi-step reasoning with optimized API calls',
        )
        st.session_state.include_vision = st.checkbox(
            'Include Vision Analysis', value=False, help='Process any uploaded images'
        )

        # Performance options
        st.markdown('### 🚀 Performance Settings')
        st.session_state.enable_concurrent = st.checkbox(
            'Concurrent Tool Execution',
            value=True,
            help='Execute multiple tools simultaneously for faster results',
        )
        st.session_state.show_metrics = st.checkbox(
            'Show Performance Metrics',
            value=True,
            help='Display execution time and optimization details',
        )

        if st.session_state.use_react_workflow:
            st.info('🧠 ReAct workflow reduces API calls by 75% (1-2 calls vs 4-8+)')
        if st.session_state.enable_concurrent:
            st.info('⚡ Concurrent execution provides ~3x speedup for tool operations')

        st.markdown('---')

        # SLA Stats in Sidebar
        try:
            import os

            redis_host = os.getenv('REDIS_HOST', 'localhost')
            redis_port = int(os.getenv('REDIS_PORT', '6379'))
            sla_tracker = SLATracker(redis_host=redis_host, redis_port=redis_port)
            render_sla_stats_sidebar(sla_tracker)
        except Exception as e:
            st.sidebar.warning(f'SLA stats unavailable: {str(e)}')


def display_system_status(status: dict):
    """Display enhanced system status information"""
    if 'system_info' in status:
        sys_info = status['system_info']

        # Performance metrics
        if 'performance' in sys_info:
            perf = sys_info['performance']
            st.markdown('### 🚀 Performance Status')

            device = perf.get('device', 'cpu')
            if device == 'mps':
                st.info('🍎 Apple Silicon MPS Acceleration')
            elif device == 'cuda':
                st.info('🖥️ CUDA GPU Acceleration')
            else:
                st.info('💻 CPU Processing')

        # Tool availability
        if 'tools' in status:
            st.markdown('### 🔧 Tool Status')
            tools = status['tools']
            col1, col2 = st.columns(2)
            with col1:
                st.write(f'AbuseIPDB: {"✅" if tools.get("abuseipdb") else "❌"}')
                st.write(f'Shodan: {"✅" if tools.get("shodan") else "❌"}')
            with col2:
                st.write(f'VirusTotal: {"✅" if tools.get("virustotal") else "❌"}')
                st.write(
                    f'Regex Checker: {"✅" if tools.get("regex_checker") else "❌"}'
                )

        # Vector Database Status
        if 'agents' in status:
            agents = status['agents']
            supervisor = agents.get('supervisor', {})
            vectorstore_available = supervisor.get('vectorstore_available', False)

            st.markdown('### 🗃️ Vector Database')
            st.write(f'Historical Data: {"✅" if vectorstore_available else "❌"}')

            if vectorstore_available:
                st.success('📊 40K+ attack records available')
            else:
                st.warning('⚠️ Vector search unavailable')


def render_single_analysis_tab():
    """Render single text analysis tab"""
    st.markdown('## Text Analysis')
    st.markdown('Analyze text for security threats, PII, and indicators of compromise.')
    st.info(
        '💡 **Tip**: For IP investigations, the system will automatically search historical attack data when ReAct workflow is enabled.'
    )

    # Session Management
    session_id = render_session_management(
        session_key='session_id_main', default_prefix='session'
    )

    # Previous Request History
    include_previous = False
    if session_id:
        include_previous = render_request_history(session_id)

    # Text input
    text_input = st.text_area(
        'Enter text to analyze:',
        placeholder='Paste logs, emails, or any text content here...',
        height=200,
    )

    col1, col2 = st.columns([2, 1])
    with col1:
        analyze_btn = st.button(
            '🔍 Analyze Text', type='primary', use_container_width=True
        )
    with col2:
        clear_btn = st.button('🗑️ Clear', use_container_width=True)

    if clear_btn:
        st.rerun()

    if analyze_btn and text_input:
        process_text_analysis(text_input, session_id, include_previous)

    # Show last result after rerun (to keep results visible when checkbox enables)
    elif 'last_result' in st.session_state and st.session_state.last_result:
        display_analysis_results(st.session_state.last_result)


def process_text_analysis(text_input: str, session_id: str, include_previous: bool):
    """Process single text analysis request"""
    # Clear last result when starting new analysis
    if 'last_result' in st.session_state:
        st.session_state.last_result = None

    with st.spinner('Analyzing text...'):
        # If no session_id, create a new one
        if not session_id:
            session_id = f'session-{uuid.uuid4().hex[:8]}'
            st.session_state.auto_session_id = session_id

        # Check if we should include previous request
        actual_input = text_input
        if session_id and include_previous and 'request_history' in st.session_state:
            if session_id in st.session_state.request_history:
                history = st.session_state.request_history[session_id]
                if history:
                    last_request = history[-1]
                    if last_request.get('text'):
                        actual_input = f'Previous context: {last_request["text"]}\n\nCurrent query: {text_input}'
                        st.info(
                            f'📎 Including previous request in analysis ({len(last_request["text"])} chars)'
                        )

        # Build request payload
        request_data = {
            'text': actual_input,
            'use_react_workflow': st.session_state.get('use_react_workflow', True),
            'include_vision': st.session_state.get('include_vision', False),
            'enable_concurrent_tools': st.session_state.get('enable_concurrent', True),
            'show_performance_metrics': st.session_state.get('show_metrics', True),
        }

        if session_id:
            request_data['session_id'] = session_id

        result = make_api_request('/analyze', 'POST', request_data)

        if result:
            # Track session and save history BEFORE displaying results
            if session_id:
                track_session_id(session_id)

                # Extract IOCs for history
                iocs_found = extract_iocs_from_result(result)
                save_request_to_history(session_id, text_input, iocs_found)

                # Display context enrichment
                if 'result' in result and isinstance(result['result'], dict):
                    display_context_enrichment(result['result'])

            # Display results - they will persist in session state
            display_analysis_results(result)

            # Store result in session state to show after rerun
            st.session_state.last_result = result

            # Trigger ONE rerun to enable checkbox (won't rerun again because last_result is set)
            if 'first_query_done' not in st.session_state:
                st.session_state.first_query_done = True
                st.rerun()


def extract_iocs_from_result(result: dict) -> list:
    """Extract IOCs from analysis result for history display"""
    iocs_found = []
    if 'result' in result and isinstance(result['result'], dict):
        result_data = result['result']
        if 'ioc_analysis' in result_data:
            ioc_data = result_data['ioc_analysis']
            extracted_iocs = ioc_data.get('extracted_iocs', {})
            for ioc_type, ioc_list in extracted_iocs.items():
                if ioc_list:
                    iocs_found.extend([str(ioc) for ioc in ioc_list[:2]])
    return iocs_found


def render_batch_analysis_tab():
    """Render batch analysis tab"""
    st.markdown('## Batch Analysis')
    st.markdown('Analyze multiple text inputs simultaneously.')

    # Session Management
    st.markdown('### 🧠 Session Management')
    col1, col2 = st.columns([3, 1])
    with col1:
        batch_session_id = st.text_input(
            'Batch Session ID (optional):',
            placeholder='e.g., batch-investigation-001',
            help='Use the same session ID for all batch items',
            key='session_id_batch',
        )
    with col2:
        if st.button('🎲 Generate Random', key='gen_batch_session'):
            st.session_state.session_id_batch = f'batch-{uuid.uuid4().hex[:8]}'
            st.rerun()

    if batch_session_id:
        st.success(f'✅ Batch context enabled for session: `{batch_session_id}`')
    else:
        st.info('ℹ️ Session ID will enable context sharing across all batch items')

    st.markdown('---')

    # Batch input
    input_method = st.radio('Input Method:', ['Manual Entry', 'Upload File'])
    inputs = get_batch_inputs(input_method)

    if inputs and st.button(
        '🔍 Analyze Batch', type='primary', use_container_width=True
    ):
        process_batch_analysis(inputs, batch_session_id)


def get_batch_inputs(input_method: str) -> list:
    """Get batch inputs from manual entry or file upload"""
    inputs = []

    if input_method == 'Manual Entry':
        st.markdown('Enter multiple texts (one per line):')
        batch_text = st.text_area(
            'Batch Input:',
            placeholder='Line 1: First text\nLine 2: Second text\n...',
            height=200,
        )
        if batch_text:
            inputs = [line.strip() for line in batch_text.split('\n') if line.strip()]
            st.info(f'Found {len(inputs)} inputs to analyze')

    elif input_method == 'Upload File':
        uploaded_file = st.file_uploader('Choose a text file', type=['txt', 'csv'])
        if uploaded_file:
            inputs = process_uploaded_file(uploaded_file)

    return inputs


def process_uploaded_file(uploaded_file) -> list:
    """Process uploaded file and extract inputs"""
    try:
        import io

        content = uploaded_file.read().decode('utf-8')
        if uploaded_file.type == 'text/csv':
            df = pd.read_csv(io.StringIO(content))
            inputs = df.iloc[:, 0].astype(str).tolist()
        else:
            inputs = [line.strip() for line in content.split('\n') if line.strip()]

        st.success(f'Loaded {len(inputs)} inputs from file')

        if inputs:
            with st.expander('Preview (first 5 entries)'):
                for i, inp in enumerate(inputs[:5], 1):
                    st.write(f'{i}. {inp[:100]}{"..." if len(inp) > 100 else ""}')

        return inputs
    except Exception as e:
        st.error(f'Error reading file: {e}')
        return []


def process_batch_analysis(inputs: list, batch_session_id: str):
    """Process batch analysis request"""
    with st.spinner(f'Analyzing {len(inputs)} inputs...'):
        batch_request_data = {
            'inputs': inputs,
            'use_react_workflow': st.session_state.get('use_react_workflow', True),
            'enable_concurrent_tools': st.session_state.get('enable_concurrent', True),
        }

        if batch_session_id:
            batch_request_data['session_id'] = batch_session_id

        result = make_api_request('/batch-analyze', 'POST', batch_request_data)

        if result:
            st.success('✅ Batch analysis completed!')
            st.info(
                f'⏱️ Processing time: {result.get("processing_time", 0):.2f} seconds'
            )

            if 'results' in result:
                display_batch_results(result['results'])


def display_batch_results(results_data: list):
    """Display batch analysis results"""
    st.markdown('### Batch Results Summary')

    # Create summary dataframe
    summary_data = []
    for i, res in enumerate(results_data, 1):
        pii_detected = res.get('pii_analysis', {}).get('pii_detected', False)
        ioc_count = res.get('ioc_analysis', {}).get('ioc_count', 0)
        threat_level = res.get('threat_analysis', {}).get('overall_risk', 'low')

        summary_data.append(
            {
                'Input #': i,
                'PII Detected': 'Yes' if pii_detected else 'No',
                'IOCs Found': ioc_count,
                'Threat Level': threat_level.title(),
                'Status': res.get('status', 'unknown').title(),
            }
        )

    summary_df = pd.DataFrame(summary_data)
    st.dataframe(summary_df, use_container_width=True)

    # Detailed results
    st.markdown('### Detailed Results')
    for i, res in enumerate(results_data, 1):
        with st.expander(f'Result {i}'):
            display_analysis_results({'status': 'success', 'result': res})


def render_image_analysis_tab():
    """Render image analysis tab"""
    st.markdown('## Image Analysis')
    st.markdown(
        'Analyze images for security risks, extract text, and detect sensitive content.'
    )

    # Session Management
    st.markdown('### 🧠 Session Management')
    col1, col2 = st.columns([3, 1])
    with col1:
        image_session_id = st.text_input(
            'Image Session ID (optional):',
            placeholder='e.g., image-investigation-001',
            help='Track IOCs extracted from images',
            key='session_id_image',
        )
    with col2:
        if st.button('🎲 Generate Random', key='gen_image_session'):
            st.session_state.session_id_image = f'image-{uuid.uuid4().hex[:8]}'
            st.rerun()

    if image_session_id:
        st.success(f'✅ Image context enabled for session: `{image_session_id}`')
    else:
        st.info('ℹ️ Session ID will track IOCs extracted from OCR text')

    st.markdown('---')

    # Image upload
    uploaded_image = st.file_uploader(
        'Choose an image file',
        type=['png', 'jpg', 'jpeg', 'gif', 'bmp'],
        help='Upload an image to analyze',
    )

    image_text = st.text_area(
        'Additional text context (optional):',
        placeholder='Provide context about the image...',
        height=100,
    )

    if uploaded_image:
        image = Image.open(uploaded_image)
        st.image(image, caption='Uploaded Image', use_column_width=True)

        col1, col2 = st.columns(2)

        with col1:
            if st.button('🔍 Analyze Image Only', use_container_width=True):
                process_image_only(uploaded_image, image_session_id)

        with col2:
            if st.button('🔍 Analyze Image + Text', use_container_width=True):
                process_image_with_text(uploaded_image, image_text, image_session_id)


def process_image_only(uploaded_image, session_id: str):
    """Process image-only analysis"""
    with st.spinner('Analyzing image...'):
        files = {'image': uploaded_image.getvalue()}
        data = {}
        if session_id:
            data['session_id'] = session_id

        result = make_api_request('/upload-image', 'POST', data=data, files=files)
        if result:
            display_analysis_results(result)


def process_image_with_text(uploaded_image, text: str, session_id: str):
    """Process image + text analysis"""
    with st.spinner('Analyzing image and text...'):
        files = {'image': uploaded_image.getvalue()}
        data = {
            'text': text or '',
            'use_react_workflow': st.session_state.get('use_react_workflow', True),
            'enable_concurrent_tools': st.session_state.get('enable_concurrent', True),
        }

        if session_id:
            data['session_id'] = session_id

        result = make_api_request('/analyze-with-image', 'POST', data=data, files=files)
        if result:
            display_analysis_results(result)


def render_tools_tab():
    """Render advanced tools tab"""
    st.markdown('## Advanced Security Tools')
    st.markdown('Direct access to individual security analysis tools.')

    tool_cols = st.columns(2)

    with tool_cols[0]:
        render_ioc_extraction_tool()
        render_shodan_lookup_tool()

    with tool_cols[1]:
        render_hash_analysis_tool()
        render_pattern_validation_tool()


def render_ioc_extraction_tool():
    """Render IOC extraction tool"""
    st.markdown('### 🔍 IOC Extraction')
    ioc_text = st.text_area('Text for IOC extraction:', height=150, key='ioc_text')

    if (
        st.button('Extract IOCs', use_container_width=True, key='extract_iocs')
        and ioc_text
    ):
        with st.spinner('Extracting IOCs...'):
            result = make_api_request(
                '/tools/regex/extract', 'POST', {'text': ioc_text}
            )
            if result:
                st.json(result)


def render_shodan_lookup_tool():
    """Render Shodan lookup tool"""
    st.markdown('### 🌐 Shodan Lookup')
    shodan_ip = st.text_input('IP for Shodan lookup:', key='shodan_ip')

    if (
        st.button('Lookup with Shodan', use_container_width=True, key='shodan_lookup')
        and shodan_ip
    ):
        with st.spinner('Querying Shodan...'):
            result = make_api_request(
                '/tools/shodan/lookup', 'POST', {'ip_address': shodan_ip}
            )
            if result:
                st.json(result)


def render_hash_analysis_tool():
    """Render hash analysis tool"""
    st.markdown('### 🔒 Hash Analysis')
    hash_input = st.text_input('File hash (MD5/SHA1/SHA256):', key='hash_input')

    if (
        st.button('Analyze Hash', use_container_width=True, key='analyze_hash')
        and hash_input
    ):
        with st.spinner('Analyzing hash...'):
            result = make_api_request(
                '/tools/virustotal/lookup',
                'POST',
                {'resource': hash_input, 'resource_type': 'hash'},
            )
            if result:
                st.json(result)


def render_pattern_validation_tool():
    """Render pattern validation tool"""
    st.markdown('### ✅ Pattern Validation')
    validation_text = st.text_input('Text to validate:', key='validation_text')
    pattern_type = st.selectbox(
        'Pattern type:', ['ip', 'domain', 'hash', 'url'], key='pattern_type'
    )

    if (
        st.button('Validate Pattern', use_container_width=True, key='validate_pattern')
        and validation_text
    ):
        with st.spinner('Validating pattern...'):
            result = make_api_request(
                '/tools/regex/validate',
                'POST',
                {'text': validation_text, 'pattern_type': pattern_type},
            )
            if result:
                st.json(result)


def render_sla_tab():
    """Render SLA monitoring dashboard tab"""
    st.markdown('## ⚡ SLA Performance Dashboard')
    st.markdown(
        'Real-time performance metrics and SLA monitoring for all API endpoints'
    )

    try:
        import os

        redis_host = os.getenv('REDIS_HOST', 'localhost')
        redis_port = int(os.getenv('REDIS_PORT', '6379'))

        # Initialize SLA tracker
        sla_tracker = SLATracker(redis_host=redis_host, redis_port=redis_port)

        # Time window selector
        time_window = st.selectbox(
            'Time Window',
            options=[1, 6, 12, 24, 48, 168],
            format_func=lambda x: f'{x} hours' if x < 168 else '7 days',
            index=3,  # Default to 24 hours
            help='Select the time window for metrics display',
        )

        st.markdown('---')

        # Render the full SLA dashboard
        render_sla_dashboard(sla_tracker, time_window_hours=time_window)

        # Add API reference section
        with st.expander('📖 API Reference'):
            st.markdown("""
            ### Available SLA API Endpoints

            **Get Endpoint Metrics:**
            ```bash
            GET /sla/metrics/{endpoint}?time_window_hours=24
            ```

            **Get All Metrics:**
            ```bash
            GET /sla/metrics?time_window_hours=24
            ```

            **Get Alerts:**
            ```bash
            GET /sla/alerts/{endpoint}
            GET /sla/alerts
            ```

            **Get Historical Trends:**
            ```bash
            GET /sla/trends/{endpoint}?days=7
            ```

            **Get SLA Summary:**
            ```bash
            GET /sla/summary?time_window_hours=24
            ```
            """)

    except Exception as e:
        st.error(f'❌ Error loading SLA dashboard: {str(e)}')
        st.info(
            'Make sure Redis is running and the SLA tracker is properly configured.'
        )


if __name__ == '__main__':
    main()
