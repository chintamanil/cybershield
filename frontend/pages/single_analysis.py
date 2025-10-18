"""Single text analysis page."""

import streamlit as st
from components.result_display import display_analysis_results
from components.session_components import (
    display_context_enrichment,
    render_request_history,
    render_session_management,
    save_request_to_history,
    track_session_id,
)
from lib.api_client import make_api_request


def render_single_analysis_page(
    use_react_workflow: bool, enable_concurrent: bool, show_metrics: bool
):
    """Render the single text analysis page.

    Args:
        use_react_workflow: Whether to use ReAct workflow
        enable_concurrent: Whether to enable concurrent tool execution
        show_metrics: Whether to show performance metrics
    """
    st.markdown("## Text Analysis")
    st.markdown("Analyze text for security threats, PII, and indicators of compromise.")
    st.info(
        "💡 **Tip**: For IP investigations, the system will automatically search historical attack data using the vector database when ReAct workflow is enabled."
    )

    # Session Management
    session_id = render_session_management(
        session_key="session_id_main", default_prefix="session"
    )

    # Previous Request History (if session_id exists)
    include_previous = False
    if session_id:
        include_previous = render_request_history(session_id)

    # Text input
    text_input = st.text_area(
        "Enter text to analyze:",
        placeholder="Paste logs, emails, or any text content here...",
        height=200,
    )

    # Combine with previous request if needed
    actual_input = text_input
    if include_previous and session_id and text_input:
        if "request_history" in st.session_state:
            if session_id in st.session_state.request_history:
                history = st.session_state.request_history[session_id]
                if history:
                    last_request = history[-1]
                    if last_request.get("text"):
                        combined_input = (
                            f"Previous: {last_request['text']}\n\nCurrent: {text_input}"
                        )
                        st.caption(
                            f"Combined input length: {len(combined_input)} characters"
                        )

    col1, col2 = st.columns([2, 1])
    with col1:
        analyze_btn = st.button(
            "🔍 Analyze Text", type="primary", use_container_width=True
        )
    with col2:
        clear_btn = st.button("🗑️ Clear", use_container_width=True)

    if clear_btn:
        st.rerun()

    if analyze_btn and text_input:
        with st.spinner("Analyzing text..."):
            # Check if we should include previous request
            actual_input = text_input
            if session_id and "request_history" in st.session_state:
                if session_id in st.session_state.request_history:
                    history = st.session_state.request_history[session_id]
                    if (
                        st.session_state.get(
                            f"include_previous_checkbox_{session_id}", False
                        )
                        and history
                    ):
                        last_request = history[-1]
                        if last_request.get("text"):
                            actual_input = f"Previous context: {last_request['text']}\n\nCurrent query: {text_input}"
                            st.info(
                                f"📎 Including previous request in analysis ({len(last_request['text'])} chars)"
                            )

            # Build request payload
            request_data = {
                "text": actual_input,
                "use_react_workflow": use_react_workflow,
                "include_vision": False,
                "enable_concurrent_tools": enable_concurrent,
                "show_performance_metrics": show_metrics,
            }

            # Add session_id if provided
            if session_id:
                request_data["session_id"] = session_id

            result = make_api_request("/analyze", "POST", request_data)

            if result:
                # Track session ID
                if session_id:
                    track_session_id(session_id)

                    # Extract IOCs from result for history display
                    iocs_found = []
                    if "result" in result and isinstance(result["result"], dict):
                        result_data = result["result"]
                        if "ioc_analysis" in result_data:
                            ioc_data = result_data["ioc_analysis"]
                            extracted_iocs = ioc_data.get("extracted_iocs", {})
                            for ioc_type, ioc_list in extracted_iocs.items():
                                if ioc_list:
                                    iocs_found.extend(
                                        [str(ioc) for ioc in ioc_list[:2]]
                                    )  # First 2 of each type

                    # Save to history
                    save_request_to_history(session_id, text_input, iocs_found)

                    # Display context enrichment info if available
                    if "result" in result and isinstance(result["result"], dict):
                        display_context_enrichment(result["result"])

                display_analysis_results(result)
