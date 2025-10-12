"""Display components for analysis results."""

from typing import Dict, Any

import streamlit as st
import pandas as pd
import plotly.express as px


def display_pii_analysis(pii_data: Dict):
    """Display PII analysis results."""
    st.markdown(
        '<div class="section-header">PII Detection Results</div>',
        unsafe_allow_html=True,
    )

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
                pii_df.append(
                    {
                        "Token": token,
                        "Type": info.get("type", "Unknown"),
                        "Original": info.get("original", "Hidden"),
                        "Position": str(info.get("position", "Unknown")),
                    }
                )

            if pii_df:
                st.dataframe(pd.DataFrame(pii_df), use_container_width=True)

        if "masked_text" in pii_data:
            st.subheader("Masked Text:")
            st.code(pii_data["masked_text"], language="text")
    else:
        st.success("✅ No PII detected in the input")


def display_ioc_analysis(ioc_data: Dict):
    """Display IOC analysis results."""
    st.markdown(
        '<div class="section-header">Indicators of Compromise (IOCs)</div>',
        unsafe_allow_html=True,
    )

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
                with st.expander(
                    f"{ioc_type.replace('_', ' ').title()} ({len(ioc_list)})"
                ):
                    for ioc in ioc_list:
                        st.code(ioc)

    if "ocr_iocs" in ioc_data:
        st.subheader("IOCs from Image Text:")
        st.json(ioc_data["ocr_iocs"])


def display_threat_analysis(threat_data: Dict):
    """Display threat analysis results."""
    st.markdown(
        '<div class="section-header">Threat Intelligence Analysis</div>',
        unsafe_allow_html=True,
    )

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

            with st.expander(
                f"{color} {threat.get('indicator', 'Unknown')} - {risk_level.title()} Risk"
            ):
                st.json(threat)


def display_vision_analysis(vision_data: Dict):
    """Display vision analysis results."""
    st.markdown(
        '<div class="section-header">Vision AI Analysis</div>', unsafe_allow_html=True
    )

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
            st.metric("Words Extracted", ocr_data.get("word_count", 0))

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
                st.progress(
                    confidence / 100,
                    text=f"{classification.get('label', 'Unknown')}: {confidence:.1f}%",
                )

        risk_level = class_data.get("risk_level", "none")
        risk_colors = {"high": "🔴", "medium": "🟡", "low": "🟢", "none": "⚪"}
        st.write(
            f"**Risk Level:** {risk_colors.get(risk_level, '⚪')} {risk_level.title()}"
        )

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


def display_recommendations(recommendations: list):
    """Display security recommendations."""
    st.markdown(
        '<div class="section-header">Security Recommendations</div>',
        unsafe_allow_html=True,
    )

    for i, recommendation in enumerate(recommendations, 1):
        st.markdown(f"**{i}.** {recommendation}")
