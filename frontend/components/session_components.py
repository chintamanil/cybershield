"""Session management and context memory UI components."""


import pandas as pd
import streamlit as st


def render_session_management(
    session_key: str = "session_id_main", default_prefix: str = "session"
) -> str | None:
    """Render simplified session management UI for context continuation.

    Args:
        session_key: Streamlit session state key for storing session ID
        default_prefix: Prefix for generated session IDs

    Returns:
        Session ID (auto-generated or continued), or None for new session
    """
    # Initialize auto-generated session ID if not exists
    if "auto_session_id" not in st.session_state:
        st.session_state.auto_session_id = None

    # Initialize request history
    if "request_history" not in st.session_state:
        st.session_state.request_history = {}

    # Check if we have a previous session
    has_previous_session = st.session_state.auto_session_id is not None

    # Get previous session info
    prev_session_id = st.session_state.auto_session_id
    prev_history = (
        st.session_state.request_history.get(prev_session_id, [])
        if prev_session_id
        else []
    )

    # Always show the Context Memory section
    st.markdown("### 🧠 Context Memory")

    # Determine if checkbox should be enabled
    can_continue = has_previous_session and prev_history

    if can_continue:
        # Get last query info
        last_query = prev_history[-1]

        # Create two columns for checkbox and clear button
        col1, col2 = st.columns([3, 1])

        with col1:
            # Checkbox for continuing previous context (ENABLED)
            use_previous_context = st.checkbox(
                "📎 Continue from previous query",
                value=False,  # Default to unchecked
                help="Enable this to reference IOCs from your previous analysis (e.g., 'that IP', 'previous domain')",
                key=f"use_prev_context_{session_key}",
            )

        with col2:
            # Clear session button
            if st.button("🔄 Reset", help="Clear session history and start fresh", key=f"clear_session_{session_key}"):
                # Clear the session and all related state
                st.session_state.auto_session_id = None
                st.session_state.request_history = {}
                if 'first_query_done' in st.session_state:
                    del st.session_state.first_query_done
                if 'last_result' in st.session_state:
                    del st.session_state.last_result
                st.rerun()

        # Explanatory text
        if use_previous_context:
            st.info(
                "✅ **Context Memory Enabled** - You can now use phrases like 'that IP', 'previous domain', 'same hash' to reference items from your last query."
            )
        else:
            st.caption(
                "💡 Check the box above to reference IOCs from your previous analysis in this query."
            )

        # Show previous query details if checkbox is selected
        if use_previous_context:
            with st.expander("📋 Previous Query Context", expanded=False):
                st.markdown("**Last Query:**")
                st.text(
                    last_query.get("text", "")[:200]
                    + ("..." if len(last_query.get("text", "")) > 200 else "")
                )

                if last_query.get("iocs_found"):
                    st.markdown("**IOCs Found:**")
                    iocs_preview = last_query["iocs_found"][:5]
                    for ioc in iocs_preview:
                        st.code(ioc, language="text")
                    if len(last_query["iocs_found"]) > 5:
                        st.caption(f"...and {len(last_query['iocs_found']) - 5} more")

            st.markdown("---")
            # Return previous session ID to continue context
            return prev_session_id
        else:
            st.markdown("---")
            # Return None - will create new session only when analysis is submitted
            return None
    else:
        # First query - show disabled checkbox
        st.checkbox(
            "📎 Continue from previous query",
            value=False,
            disabled=True,  # DISABLED until first query
            help="This will be enabled after your first analysis to reference previous IOCs",
            key=f"use_prev_context_disabled_{session_key}",
        )
        st.caption(
            "💡 Submit your first query to enable context memory. You'll then be able to reference IOCs using natural language like 'that IP' or 'previous domain'."
        )
        st.markdown("---")
        # Return None - new session will be created when analysis is submitted
        return None


def render_request_history(session_id: str) -> bool:
    """Render previous request history for a session (legacy function, now handled in render_session_management).

    Args:
        session_id: Current session ID

    Returns:
        False (always, as context continuation is now automatic)
    """
    # This function is kept for backward compatibility but is no longer used
    # Context continuation is now handled automatically in render_session_management
    return False


def track_session_id(session_id: str):
    """Track a session ID to the list of previous sessions.

    Args:
        session_id: Session ID to track
    """
    if "previous_session_ids" not in st.session_state:
        st.session_state.previous_session_ids = []
    if session_id not in st.session_state.previous_session_ids:
        st.session_state.previous_session_ids.append(session_id)
        # Keep only last 10 session IDs
        if len(st.session_state.previous_session_ids) > 10:
            st.session_state.previous_session_ids = (
                st.session_state.previous_session_ids[-10:]
            )


def save_request_to_history(session_id: str, text: str, iocs_found: list):
    """Save a request to the session history.

    Args:
        session_id: Session ID to save request under
        text: Request text
        iocs_found: List of IOCs extracted from the analysis
    """
    if "request_history" not in st.session_state:
        st.session_state.request_history = {}
    if session_id not in st.session_state.request_history:
        st.session_state.request_history[session_id] = []

    st.session_state.request_history[session_id].append(
        {
            "text": text,
            "iocs_found": iocs_found,
            "timestamp": pd.Timestamp.now().isoformat(),
        }
    )


def display_context_enrichment(result_data: dict):
    """Display context enrichment information from analysis result.

    Args:
        result_data: Result data dictionary containing context_enrichment info
    """
    if "context_enrichment" in result_data:
        context_info = result_data["context_enrichment"]

        if context_info.get("enriched", False):
            st.success("🧠 Context Memory Applied!")

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Session Age", context_info.get("session_age", "N/A"))
            with col2:
                st.metric("Session Events", context_info.get("session_events", 0))
            with col3:
                context_used = context_info.get("context_used", {})
                st.metric("IOCs Resolved", len(context_used))

            # Show resolved context
            if context_used:
                with st.expander("🔍 View Resolved Context"):
                    for ioc_type, ioc_value in context_used.items():
                        st.code(f"{ioc_type}: {ioc_value}")

            # Show text enrichment
            if "original_text" in result_data.get("input_analysis", {}):
                input_analysis = result_data["input_analysis"]
                with st.expander("📝 Text Enrichment Details"):
                    st.markdown("**Original Text:**")
                    st.text(input_analysis.get("original_text", "N/A"))
                    st.markdown("**Enriched Text:**")
                    st.text(input_analysis.get("enriched_text", "N/A"))
