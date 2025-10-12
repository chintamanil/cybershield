"""Display components for security tool results."""

from typing import Dict

import streamlit as st
import pandas as pd
import plotly.express as px


def display_shodan_results(shodan_data: Dict):
    """Display Shodan lookup results."""
    if "error" in shodan_data:
        st.error(f"Shodan Error: {shodan_data['error']}")
        return

    col1, col2 = st.columns(2)
    with col1:
        if "org" in shodan_data:
            st.write(f"**Organization:** {shodan_data['org']}")
        if "country_name" in shodan_data:
            st.write(f"**Country:** {shodan_data['country_name']}")

    with col2:
        if "hostnames" in shodan_data and shodan_data["hostnames"]:
            st.write(f"**Hostnames:** {', '.join(shodan_data['hostnames'][:3])}")

    if "ports" in shodan_data:
        st.write(f"**Open Ports:** {', '.join(map(str, shodan_data['ports'][:10]))}")


def display_abuseipdb_results(abuseipdb_data: Dict):
    """Display AbuseIPDB lookup results."""
    if "error" in abuseipdb_data:
        st.error(f"AbuseIPDB Error: {abuseipdb_data['error']}")
        return

    col1, col2, col3 = st.columns(3)
    with col1:
        confidence = abuseipdb_data.get("abuse_confidence", 0)
        st.metric("Abuse Confidence", f"{confidence}%")
    with col2:
        reports = abuseipdb_data.get("total_reports", 0)
        st.metric("Total Reports", reports)
    with col3:
        whitelisted = abuseipdb_data.get("is_whitelisted", False)
        st.metric("Whitelisted", "✅ Yes" if whitelisted else "❌ No")

    if abuseipdb_data.get("usage_type"):
        st.info(f"Usage Type: {abuseipdb_data['usage_type']}")


def display_virustotal_results(vt_data: Dict):
    """Display VirusTotal lookup results."""
    if "error" in vt_data:
        st.error(f"VirusTotal Error: {vt_data['error']}")
        return

    if "last_analysis_stats" in vt_data:
        stats = vt_data["last_analysis_stats"]

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Malicious", stats.get("malicious", 0), delta_color="inverse")
        with col2:
            st.metric("Suspicious", stats.get("suspicious", 0), delta_color="inverse")
        with col3:
            st.metric("Harmless", stats.get("harmless", 0))
        with col4:
            st.metric("Undetected", stats.get("undetected", 0))

    if vt_data.get("reputation", 0) != 0:
        rep = vt_data["reputation"]
        color = "🔴" if rep < 0 else "🟢"
        st.write(f"**Reputation Score:** {color} {rep}")


def display_vector_search_tool_results(vector_result: Dict):
    """Display vector search tool results from ReAct workflow."""
    st.markdown("### 🗃️ Historical Attack Database Search")

    if "error" in vector_result:
        st.error(f"Vector Search Error: {vector_result['error']}")
        return

    search_results = vector_result.get("vector_search_results", [])
    total_searched = vector_result.get("total_ips_searched", 0)

    # Summary metrics
    col1, col2 = st.columns(2)
    with col1:
        st.metric("IPs Searched", total_searched)
    with col2:
        total_matches = sum(result.get("match_count", 0) for result in search_results)
        st.metric("Historical Matches", total_matches)

    # Results for each IP
    for result in search_results:
        ip = result.get("ip", "Unknown")
        matches = result.get("matches", [])
        match_count = result.get("match_count", 0)

        if match_count > 0:
            st.success(f"📊 **{ip}**: Found {match_count} historical records")

            # Show sample records
            if matches:
                with st.expander(f"View records for {ip}"):
                    sample_records = matches[:5]  # Show first 5 records
                    for i, record in enumerate(sample_records, 1):
                        st.write(f"**Record {i}:**")
                        st.write(
                            f"- Attack Type: {record.get('attack_type', 'Unknown')}"
                        )
                        st.write(f"- Timestamp: {record.get('timestamp', 'Unknown')}")
                        st.write(
                            f"- Severity: {record.get('severity_level', 'Unknown')}"
                        )
                        st.write(
                            f"- Action Taken: {record.get('action_taken', 'Unknown')}"
                        )
                        st.markdown("---")
        else:
            st.info(f"✅ **{ip}**: No historical attack records found")


def display_tool_analysis(tool_data: Dict):
    """Display tool analysis results with concurrent execution metrics."""
    st.markdown(
        '<div class="section-header">Security Tool Analysis</div>',
        unsafe_allow_html=True,
    )

    # Handle None or empty tool data
    if not tool_data:
        st.info("No tool analysis data available")
        return

    # Show concurrent execution metrics if available
    if "execution_metrics" in tool_data:
        metrics = tool_data["execution_metrics"]

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Tools Executed", metrics.get("tools_count", 0))
        with col2:
            st.metric("Execution Time", f"{metrics.get('execution_time', 0):.2f}s")
        with col3:
            st.metric("Success Rate", f"{metrics.get('success_rate', 0):.0%}")
        with col4:
            concurrent = metrics.get("concurrent", False)
            st.metric("Execution Mode", "Concurrent" if concurrent else "Sequential")

        if concurrent:
            st.success(
                f"🚀 {metrics.get('performance_gain', 'Optimized concurrent execution')}"
            )

    # Show detailed tool results
    if "detailed_results" in tool_data:
        st.subheader("Detailed Tool Results:")

        for tool_name, result in tool_data["detailed_results"].items():
            with st.expander(f"🔧 {tool_name.replace('_', ' ').title()}"):
                if "error" in result:
                    st.error(f"❌ Error: {result['error']}")
                else:
                    # Show execution time if available
                    if "execution_time" in result:
                        st.info(f"⏱️ Execution time: {result['execution_time']:.2f}s")

                    # Show tool-specific results
                    if tool_name == "shodan_lookup_tool" and "shodan_result" in result:
                        display_shodan_results(result["shodan_result"])
                    elif (
                        tool_name == "abuseipdb_lookup_tool"
                        and "abuseipdb_result" in result
                    ):
                        display_abuseipdb_results(result["abuseipdb_result"])
                    elif (
                        tool_name == "virustotal_lookup_tool"
                        and "virustotal_result" in result
                    ):
                        display_virustotal_results(result["virustotal_result"])
                    elif (
                        tool_name == "vector_search_tool"
                        and "vector_search_results" in result
                    ):
                        display_vector_search_tool_results(result)
                    else:
                        # Generic result display
                        st.json(result)

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
                title="IOCs by Type",
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
                            st.metric(
                                "Abuse Confidence",
                                f"{adb_data.get('abuse_confidence', 0)}%",
                            )
                        with col2:
                            st.metric("Total Reports", adb_data.get("total_reports", 0))
                        with col3:
                            is_whitelisted = adb_data.get("is_whitelisted", False)
                            st.metric("Whitelisted", "✅" if is_whitelisted else "❌")

                # Shodan Results
                if "shodan" in results:
                    shodan_data = results["shodan"]
                    if "error" not in shodan_data and "hostnames" in shodan_data:
                        st.write(
                            "**Hostnames:**", ", ".join(shodan_data["hostnames"][:3])
                        )
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
