"""Main result display orchestrator for analysis results."""

from typing import Any

import streamlit as st

from .display_components import (
    display_ioc_analysis,
    display_pii_analysis,
    display_recommendations,
    display_threat_analysis,
    display_vision_analysis,
)
from .tool_displays import display_tool_analysis
from .vector_displays import display_vector_analysis


def display_analysis_results(results: dict[str, Any]):
    """Display analysis results in a formatted way.

    Args:
        results: Analysis results dictionary from API
    """
    if not results:
        return

    # Main status
    status = results.get("status", "unknown")
    if status == "success":
        st.success("✅ Analysis completed successfully")
    else:
        st.error(f"❌ Analysis failed: {status}")

    # Processing time and performance metrics
    if "processing_time" in results:
        st.info(f"⏱️ Processing time: {results['processing_time']:.2f} seconds")

    # ReAct workflow performance metrics
    if "result" in results and isinstance(results["result"], dict):
        result_data = results["result"]

        # Show processing summary if available
        if "processing_summary" in result_data:
            summary = result_data["processing_summary"]

            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Workflow Iterations", summary.get("iterations", 0))
            with col2:
                tools_used = summary.get("tools_used", [])
                st.metric(
                    "Tools Used", len(tools_used) if isinstance(tools_used, list) else 0
                )
            with col3:
                processing_method = result_data.get("processing_method", "unknown")
                method_display = (
                    "ReAct + Cache"
                    if "cached" in processing_method
                    else processing_method.title()
                )
                st.metric("Processing Method", method_display)
            with col4:
                cached_ops = summary.get("cached_operations", [])
                st.metric(
                    "Cached Operations",
                    len(cached_ops) if isinstance(cached_ops, list) else 0,
                )

            # Show caching performance if available
            if "performance_gain" in summary:
                st.success(f"⚡ {summary['performance_gain']}")

            # Show concurrent execution performance if available
            if "execution_time_seconds" in summary:
                st.info(f"🚀 Execution time: {summary['execution_time_seconds']}s")

        # Show device optimization status
        if "device_optimization" in result_data:
            device_info = result_data["device_optimization"]
            if device_info.get("device") == "mps":
                st.info("🍎 Apple Silicon MPS acceleration enabled")
            elif device_info.get("device") == "cuda":
                st.info("🖥️ CUDA GPU acceleration enabled")
            else:
                st.info("💻 CPU processing mode")

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

        if "vector_analysis" in result:
            tab_names.append("🗃️ Vector Search")
            tabs.append("vector")

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
                    elif tab_type == "vector":
                        display_vector_analysis(result["vector_analysis"])
                    elif tab_type == "recommendations":
                        display_recommendations(result["recommendations"])
