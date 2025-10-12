"""UI display helper functions for consistent UI elements."""

from typing import Dict, List, Optional, Union

import streamlit as st

from config import RISK_COLORS, IOC_ICONS


class UIHelpers:
    """UI helper functions for displaying consistent elements."""

    @staticmethod
    def display_metric_card(
        title: str,
        value: Union[str, int, float],
        delta: Optional[str] = None,
        help_text: Optional[str] = None,
    ):
        """Display a metric card.

        Args:
            title: Metric title
            value: Metric value
            delta: Optional delta value
            help_text: Optional help text
        """
        st.metric(label=title, value=value, delta=delta, help=help_text)

    @staticmethod
    def display_status_badge(status: str, text: str = None):
        """Display status badge with appropriate color.

        Args:
            status: Status type (success, warning, error, info, pending)
            text: Optional custom text (defaults to status.title())
        """
        if text is None:
            text = status.title()

        colors = {
            "success": "🟢",
            "warning": "🟡",
            "error": "🔴",
            "info": "🔵",
            "pending": "🟡",
        }

        icon = colors.get(status.lower(), "⚪")
        st.markdown(f"{icon} **{text}**")

    @staticmethod
    def display_risk_level(risk_level: str):
        """Display risk level with appropriate styling.

        Args:
            risk_level: Risk level (high, medium, low, etc.)
        """
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
        """Display IOC list with icons.

        Args:
            iocs: Dictionary of IOC types and their lists
            max_items: Maximum items to display per type
        """
        for ioc_type, ioc_list in iocs.items():
            if ioc_list:
                icon = IOC_ICONS.get(ioc_type, "📄")

                with st.expander(
                    f"{icon} {ioc_type.replace('_', ' ').title()} ({len(ioc_list)})"
                ):
                    displayed = 0
                    for ioc in ioc_list:
                        if displayed >= max_items:
                            st.write(f"... and {len(ioc_list) - max_items} more")
                            break
                        st.code(ioc)
                        displayed += 1

    @staticmethod
    def display_progress_bar(current: int, total: int, text: str = "Progress"):
        """Display progress bar.

        Args:
            current: Current progress value
            total: Total value
            text: Progress text label
        """
        if total > 0:
            progress = current / total
            st.progress(progress, text=f"{text}: {current}/{total}")

    @staticmethod
    def display_json_expandable(data: Dict, title: str = "Details"):
        """Display JSON data in expandable section.

        Args:
            data: Dictionary to display as JSON
            title: Expander title
        """
        with st.expander(title):
            st.json(data)
