"""Display components for vector database analysis results."""

from typing import Dict

import streamlit as st
import pandas as pd
import plotly.express as px


def display_vector_analysis(vector_data: Dict):
    """Display vector search analysis results."""
    st.markdown(
        '<div class="section-header">Vector Database Analysis</div>',
        unsafe_allow_html=True,
    )

    # Handle None or empty vector data
    if not vector_data:
        st.info("No vector search data available")
        return

    # Vector search results
    if "vector_search_results" in vector_data:
        search_results = vector_data["vector_search_results"]
        total_ips = vector_data.get("total_ips_searched", 0)

        # Summary metrics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("IPs Searched", total_ips)
        with col2:
            historical_matches = sum(
                len(result.get("matches", [])) for result in search_results
            )
            st.metric("Historical Matches", historical_matches)
        with col3:
            search_status = vector_data.get("status", "unknown")
            st.metric("Search Status", search_status.title())

        # Display results for each IP
        for result in search_results:
            ip = result.get("ip", "Unknown")
            matches = result.get("matches", [])
            match_count = result.get("match_count", 0)
            error = result.get("error")

            with st.expander(f"🔍 IP: {ip} ({match_count} historical records)"):
                if error:
                    st.error(f"❌ Search Error: {error}")
                elif match_count == 0:
                    st.info("✅ No historical attack records found for this IP")
                else:
                    st.success(f"📊 Found {match_count} historical attack records")

                    # Display historical records
                    if matches:
                        st.markdown("### Historical Attack Records:")

                        # Create dataframe for better visualization
                        records_data = []
                        for i, match in enumerate(
                            matches[:10]
                        ):  # Show first 10 matches
                            records_data.append(
                                {
                                    "Record ID": match.get("id", f"record_{i+1}"),
                                    "Timestamp": match.get("timestamp", "Unknown"),
                                    "Source IP": match.get("source_ip", "N/A"),
                                    "Dest IP": match.get("dest_ip", "N/A"),
                                    "Attack Type": match.get("attack_type", "Unknown"),
                                    "Severity": match.get("severity_level", "Unknown"),
                                    "Action Taken": match.get("action_taken", "N/A"),
                                    "Anomaly Score": match.get("anomaly_score", 0),
                                }
                            )

                        if records_data:
                            records_df = pd.DataFrame(records_data)
                            st.dataframe(records_df, use_container_width=True)

                            # Attack type distribution
                            attack_types = [
                                record["Attack Type"]
                                for record in records_data
                                if record["Attack Type"] != "Unknown"
                            ]
                            if attack_types:
                                attack_counts = pd.Series(attack_types).value_counts()
                                if len(attack_counts) > 1:
                                    fig = px.pie(
                                        values=attack_counts.values,
                                        names=attack_counts.index,
                                        title=f"Attack Types for {ip}",
                                    )
                                    st.plotly_chart(fig, use_container_width=True)

                            # Severity analysis
                            severity_levels = [
                                record["Severity"]
                                for record in records_data
                                if record["Severity"] != "Unknown"
                            ]
                            if severity_levels:
                                severity_counts = pd.Series(
                                    severity_levels
                                ).value_counts()

                                # Color-code severity
                                severity_colors = {
                                    "Critical": "🔴",
                                    "High": "🟠",
                                    "Medium": "🟡",
                                    "Low": "🟢",
                                    "Info": "🔵",
                                }

                                st.markdown("#### Severity Distribution:")
                                for severity, count in severity_counts.items():
                                    color = severity_colors.get(severity, "⚪")
                                    st.write(
                                        f"{color} **{severity}**: {count} incidents"
                                    )

                        # Show raw match data for detailed analysis
                        if st.checkbox(f"Show raw data for {ip}", key=f"raw_{ip}"):
                            st.json(matches[:3])  # Show first 3 raw records

    # Vector search performance metrics
    if "search_metrics" in vector_data:
        metrics = vector_data["search_metrics"]

        st.markdown("### 📈 Search Performance")
        metric_cols = st.columns(4)

        with metric_cols[0]:
            st.metric("Search Time", f"{metrics.get('search_time', 0):.3f}s")
        with metric_cols[1]:
            st.metric("Database Queries", metrics.get("queries_executed", 0))
        with metric_cols[2]:
            st.metric("Records Scanned", metrics.get("records_scanned", 0))
        with metric_cols[3]:
            cache_hits = metrics.get("cache_hits", 0)
            st.metric("Cache Hits", cache_hits)

    # Risk assessment based on historical data
    if "risk_assessment" in vector_data:
        risk = vector_data["risk_assessment"]

        st.markdown("### 🎯 Historical Risk Assessment")

        overall_risk = risk.get("overall_risk_level", "unknown")
        risk_colors = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "none": "✅",
        }

        risk_color = risk_colors.get(overall_risk.lower(), "⚪")
        st.markdown(f"**Overall Risk Level:** {risk_color} {overall_risk.title()}")

        if risk.get("risk_factors"):
            st.markdown("**Risk Factors:**")
            for factor in risk["risk_factors"]:
                st.write(f"• {factor}")

        if risk.get("recommendations"):
            st.markdown("**Historical Analysis Recommendations:**")
            for rec in risk["recommendations"]:
                st.write(f"• {rec}")
