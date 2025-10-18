"""Data visualization utilities for creating charts and graphs."""


import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from config import CHART_COLORS


class DataVisualizer:
    """Utility class for creating data visualizations."""

    @staticmethod
    def create_ioc_chart(ioc_data: dict[str, list]) -> go.Figure:
        """Create IOC distribution chart.

        Args:
            ioc_data: Dictionary of IOC types and their lists

        Returns:
            Plotly figure or None if no data
        """
        ioc_counts = {k: len(v) for k, v in ioc_data.items() if v}

        if not ioc_counts:
            return None

        fig = px.bar(
            x=list(ioc_counts.keys()),
            y=list(ioc_counts.values()),
            title="IOCs by Type",
            color=list(ioc_counts.values()),
            color_continuous_scale="Reds",
        )

        fig.update_layout(xaxis_title="IOC Type", yaxis_title="Count", showlegend=False)

        return fig

    @staticmethod
    def create_threat_level_chart(threat_data: dict) -> go.Figure:
        """Create threat level distribution chart.

        Args:
            threat_data: Dictionary with threat level counts

        Returns:
            Plotly figure
        """
        levels = ["high_risk_count", "medium_risk_count", "low_risk_count"]
        counts = [threat_data.get(level, 0) for level in levels]
        labels = ["High", "Medium", "Low"]
        colors = [
            CHART_COLORS["danger"],
            CHART_COLORS["warning"],
            CHART_COLORS["success"],
        ]

        fig = go.Figure(
            data=[go.Pie(labels=labels, values=counts, marker_colors=colors, hole=0.3)]
        )

        fig.update_layout(title="Threat Level Distribution", showlegend=True)

        return fig

    @staticmethod
    def create_timeline_chart(
        data: list[dict], date_field: str, value_field: str
    ) -> go.Figure:
        """Create timeline chart.

        Args:
            data: List of data dictionaries
            date_field: Field name for date/time
            value_field: Field name for values

        Returns:
            Plotly figure or None if no data
        """
        df = pd.DataFrame(data)

        if df.empty:
            return None

        fig = px.line(df, x=date_field, y=value_field, title="Analysis Timeline")

        return fig
