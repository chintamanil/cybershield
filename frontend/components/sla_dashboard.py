"""
SLA Dashboard Component for Streamlit Frontend.

Provides comprehensive SLA monitoring visualization:
- Real-time P95/P99 latency metrics
- Uptime and availability tracking
- Error rate monitoring
- Alert status and historical trends
"""

import asyncio
from datetime import datetime
from typing import Optional

import plotly.graph_objects as go
import streamlit as st
from plotly.subplots import make_subplots

from server.monitoring.sla_tracker import SLATracker
from utils.logging_config import get_security_logger

logger = get_security_logger('sla_dashboard')


def render_sla_dashboard(
    sla_tracker: Optional[SLATracker] = None,
    time_window_hours: int = 24,
) -> None:
    """
    Render comprehensive SLA dashboard in Streamlit.

    Args:
        sla_tracker: SLATracker instance (creates if None)
        time_window_hours: Time window for metrics display
    """
    if not sla_tracker:
        sla_tracker = SLATracker()

    st.header('📊 SLA Performance Dashboard')
    st.markdown(
        f'Real-time performance metrics for the last **{time_window_hours} hours**'
    )

    try:
        # Get all endpoint metrics
        all_metrics = asyncio.run(
            sla_tracker.get_all_endpoints_metrics(time_window_hours)
        )

        if not all_metrics:
            st.warning(
                'No SLA data available yet. Metrics will appear after API usage.'
            )
            return

        # Summary metrics at the top
        _render_summary_metrics(all_metrics)

        st.divider()

        # Endpoint-specific metrics
        selected_endpoint = st.selectbox(
            'Select Endpoint',
            options=list(all_metrics.keys()),
            index=0,
        )

        if selected_endpoint:
            metrics = all_metrics[selected_endpoint]

            # Latency metrics
            _render_latency_metrics(metrics)

            # Availability and error rate
            col1, col2 = st.columns(2)

            with col1:
                _render_uptime_metric(metrics)

            with col2:
                _render_error_rate_metric(metrics)

            st.divider()

            # Alert status
            _render_alert_status(sla_tracker, selected_endpoint)

            st.divider()

            # Historical trends
            _render_historical_trends(sla_tracker, selected_endpoint)

            # Last updated
            st.caption(f'Last updated: {metrics.last_updated}')

    except Exception as e:
        logger.error('sla_dashboard_error', error=str(e))
        st.error(f'Error loading SLA dashboard: {str(e)}')


def _render_summary_metrics(all_metrics: dict) -> None:
    """Render summary metrics across all endpoints"""
    total_requests = sum(m.total_requests for m in all_metrics.values())
    total_failures = sum(m.failed_requests for m in all_metrics.values())
    avg_uptime = (
        sum(m.uptime_percentage for m in all_metrics.values()) / len(all_metrics)
        if all_metrics
        else 0.0
    )
    avg_p95 = (
        sum(m.p95_latency_ms for m in all_metrics.values()) / len(all_metrics)
        if all_metrics
        else 0.0
    )

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            'Total Requests',
            f'{total_requests:,}',
            delta=None,
        )

    with col2:
        st.metric(
            'Avg Uptime',
            f'{avg_uptime:.2f}%',
            delta=None,
            delta_color='normal' if avg_uptime >= 99.0 else 'inverse',
        )

    with col3:
        st.metric(
            'Total Failures',
            f'{total_failures:,}',
            delta=None,
        )

    with col4:
        st.metric(
            'Avg P95 Latency',
            f'{avg_p95:.0f}ms',
            delta=None,
        )


def _render_latency_metrics(metrics) -> None:
    """Render latency percentile metrics"""
    st.subheader(f'⚡ Latency Metrics - {metrics.endpoint}')

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric('Avg Latency', f'{metrics.avg_latency_ms:.2f}ms')

    with col2:
        st.metric('P50 (Median)', f'{metrics.p50_latency_ms:.2f}ms')

    with col3:
        delta_color = 'normal' if metrics.p95_latency_ms < 1000 else 'inverse'
        st.metric(
            'P95',
            f'{metrics.p95_latency_ms:.2f}ms',
            delta=None,
            delta_color=delta_color,
        )

    with col4:
        delta_color = 'normal' if metrics.p99_latency_ms < 2000 else 'inverse'
        st.metric(
            'P99',
            f'{metrics.p99_latency_ms:.2f}ms',
            delta=None,
            delta_color=delta_color,
        )

    # Latency distribution chart
    fig = go.Figure()

    percentiles = ['Avg', 'P50', 'P95', 'P99']
    values = [
        metrics.avg_latency_ms,
        metrics.p50_latency_ms,
        metrics.p95_latency_ms,
        metrics.p99_latency_ms,
    ]
    colors = ['#3498db', '#2ecc71', '#f39c12', '#e74c3c']

    fig.add_trace(
        go.Bar(
            x=percentiles,
            y=values,
            marker_color=colors,
            text=[f'{v:.2f}ms' for v in values],
            textposition='auto',
        )
    )

    fig.update_layout(
        title='Latency Distribution',
        xaxis_title='Percentile',
        yaxis_title='Latency (ms)',
        height=300,
        showlegend=False,
    )

    st.plotly_chart(fig, use_container_width=True)


def _render_uptime_metric(metrics) -> None:
    """Render uptime percentage metric"""
    st.subheader('🟢 Uptime')

    # Gauge chart for uptime
    uptime = metrics.uptime_percentage

    fig = go.Figure(
        go.Indicator(
            mode='gauge+number+delta',
            value=uptime,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': 'Uptime %'},
            delta={'reference': 99.9, 'increasing': {'color': 'green'}},
            gauge={
                'axis': {'range': [None, 100]},
                'bar': {'color': 'darkgreen' if uptime >= 99.0 else 'darkred'},
                'steps': [
                    {'range': [0, 95], 'color': 'lightgray'},
                    {'range': [95, 99], 'color': 'yellow'},
                    {'range': [99, 100], 'color': 'lightgreen'},
                ],
                'threshold': {
                    'line': {'color': 'red', 'width': 4},
                    'thickness': 0.75,
                    'value': 99.0,
                },
            },
        )
    )

    fig.update_layout(height=250)
    st.plotly_chart(fig, use_container_width=True)

    st.metric(
        'Successful Requests',
        f'{metrics.successful_requests:,}',
        delta=None,
    )


def _render_error_rate_metric(metrics) -> None:
    """Render error rate metric"""
    st.subheader('❌ Error Rate')

    # Gauge chart for error rate
    error_rate = metrics.error_rate * 100  # Convert to percentage

    fig = go.Figure(
        go.Indicator(
            mode='gauge+number',
            value=error_rate,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': 'Error Rate %'},
            gauge={
                'axis': {'range': [0, 20]},
                'bar': {'color': 'darkred' if error_rate > 5 else 'darkgreen'},
                'steps': [
                    {'range': [0, 1], 'color': 'lightgreen'},
                    {'range': [1, 5], 'color': 'yellow'},
                    {'range': [5, 20], 'color': 'lightcoral'},
                ],
                'threshold': {
                    'line': {'color': 'red', 'width': 4},
                    'thickness': 0.75,
                    'value': 5.0,
                },
            },
        )
    )

    fig.update_layout(height=250)
    st.plotly_chart(fig, use_container_width=True)

    st.metric(
        'Failed Requests',
        f'{metrics.failed_requests:,}',
        delta=None,
    )


def _render_alert_status(sla_tracker: SLATracker, endpoint: str) -> None:
    """Render alert status section"""
    st.subheader('🚨 Alert Status')

    alerts = asyncio.run(sla_tracker.check_alerts(endpoint))

    if not alerts:
        st.success('✅ All SLA thresholds met - No alerts')
    else:
        st.warning(f'⚠️  {len(alerts)} active alerts')

        for alert in alerts:
            severity_emoji = {
                'info': 'ℹ️',
                'warning': '⚠️',
                'critical': '🔴',
            }

            severity_color = {
                'info': 'blue',
                'warning': 'orange',
                'critical': 'red',
            }

            with st.expander(
                f'{severity_emoji.get(alert["severity"], "⚠️")} '
                f'{alert["metric_name"]} - {alert["severity"].upper()}',
                expanded=(alert['severity'] == 'critical'),
            ):
                col1, col2 = st.columns(2)

                with col1:
                    st.write('**Metric Value:**')
                    st.write(f'{alert["metric_value"]:.2f}')

                with col2:
                    st.write('**Threshold:**')
                    st.write(f'{alert["comparison"]} {alert["threshold_value"]:.2f}')

                st.write('**Message:**')
                st.write(alert['message'])

                st.caption(f'Triggered at: {alert["timestamp"]}')


def _render_historical_trends(sla_tracker: SLATracker, endpoint: str) -> None:
    """Render historical trend charts"""
    st.subheader('📈 Historical Trends (7 days)')

    try:
        trends = asyncio.run(sla_tracker.get_historical_trends(endpoint, days=7))

        if not trends or not trends.get('dates'):
            st.info('Not enough historical data yet. Check back after more API usage.')
            return

        # Create subplots for trends
        fig = make_subplots(
            rows=2,
            cols=1,
            subplot_titles=('P95 Latency Over Time', 'Request Volume Over Time'),
            vertical_spacing=0.15,
        )

        # P95 Latency trend
        fig.add_trace(
            go.Scatter(
                x=trends['dates'],
                y=trends['p95_latency'],
                mode='lines+markers',
                name='P95 Latency',
                line=dict(color='#e74c3c', width=2),
                marker=dict(size=8),
            ),
            row=1,
            col=1,
        )

        # Request volume trend
        fig.add_trace(
            go.Bar(
                x=trends['dates'],
                y=trends['request_count'],
                name='Requests',
                marker_color='#3498db',
            ),
            row=2,
            col=1,
        )

        fig.update_xaxes(title_text='Date', row=2, col=1)
        fig.update_yaxes(title_text='Latency (ms)', row=1, col=1)
        fig.update_yaxes(title_text='Request Count', row=2, col=1)

        fig.update_layout(height=500, showlegend=True)

        st.plotly_chart(fig, use_container_width=True)

    except Exception as e:
        logger.error('historical_trends_error', error=str(e))
        st.error(f'Error loading historical trends: {str(e)}')


def render_sla_stats_sidebar(sla_tracker: Optional[SLATracker] = None) -> None:
    """
    Render SLA summary stats in Streamlit sidebar.

    Args:
        sla_tracker: SLATracker instance
    """
    if not sla_tracker:
        sla_tracker = SLATracker()

    try:
        all_metrics = asyncio.run(sla_tracker.get_all_endpoints_metrics())

        if not all_metrics:
            return

        st.sidebar.divider()
        st.sidebar.subheader('⚡ System Performance')

        # Overall uptime
        avg_uptime = sum(m.uptime_percentage for m in all_metrics.values()) / len(
            all_metrics
        )
        uptime_color = '🟢' if avg_uptime >= 99.0 else '🟡'
        st.sidebar.metric(
            'System Uptime',
            f'{uptime_color} {avg_uptime:.2f}%',
        )

        # Average P95
        avg_p95 = sum(m.p95_latency_ms for m in all_metrics.values()) / len(all_metrics)
        p95_color = '🟢' if avg_p95 < 1000 else '🔴'
        st.sidebar.metric(
            'Avg P95 Latency',
            f'{p95_color} {avg_p95:.0f}ms',
        )

        # Total requests
        total_requests = sum(m.total_requests for m in all_metrics.values())
        st.sidebar.metric(
            'Total Requests',
            f'{total_requests:,}',
        )

    except Exception as e:
        logger.error('sla_sidebar_error', error=str(e))


# Example integration with Streamlit app
if __name__ == '__main__':
    import streamlit as st

    st.set_page_config(
        page_title='CyberShield SLA Dashboard',
        page_icon='📊',
        layout='wide',
    )

    st.title('📊 CyberShield SLA Dashboard')

    # Initialize SLA tracker
    tracker = SLATracker()

    # Render sidebar stats
    render_sla_stats_sidebar(tracker)

    # Main dashboard
    time_window = st.sidebar.slider(
        'Time Window (hours)',
        min_value=1,
        max_value=168,  # 7 days
        value=24,
        step=1,
    )

    render_sla_dashboard(tracker, time_window_hours=time_window)

    st.divider()
    st.info(
        '💡 **Tip**: SLA metrics are tracked automatically for all API endpoints. '
        'Data is retained for 30 days by default.'
    )
