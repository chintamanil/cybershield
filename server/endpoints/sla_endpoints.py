"""
SLA Monitoring API Endpoints.

Provides REST API access to SLA metrics, alerts, and trends.
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from server.monitoring.sla_tracker import SLAMetrics, SLATracker
from utils.logging_config import get_security_logger

logger = get_security_logger('sla_endpoints')

# Create router
router = APIRouter(prefix='/sla', tags=['SLA Monitoring'])


class EndpointMetricsResponse(BaseModel):
    """Response model for endpoint metrics"""

    endpoint: str
    total_requests: int
    successful_requests: int
    failed_requests: int
    error_rate: float
    avg_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    uptime_percentage: float
    last_updated: str
    timestamp: str


class AlertResponse(BaseModel):
    """Response model for SLA alerts"""

    endpoint: str
    metric_name: str
    metric_value: float
    threshold_value: float
    comparison: str
    severity: str
    timestamp: str
    message: str


class TrendsResponse(BaseModel):
    """Response model for historical trends"""

    dates: List[str]
    avg_latency: List[float]
    p95_latency: List[float]
    request_count: List[int]


# Global SLA tracker instance (set by main.py)
_sla_tracker: Optional[SLATracker] = None


def set_sla_tracker(tracker: SLATracker) -> None:
    """Set the global SLA tracker instance"""
    global _sla_tracker
    _sla_tracker = tracker
    logger.info('sla_tracker_registered')


def get_sla_tracker() -> SLATracker:
    """Get the global SLA tracker instance"""
    if _sla_tracker is None:
        raise HTTPException(
            status_code=503,
            detail='SLA tracker not initialized',
        )
    return _sla_tracker


@router.get('/metrics/{endpoint:path}', response_model=EndpointMetricsResponse)
async def get_endpoint_metrics(
    endpoint: str,
    time_window_hours: int = Query(default=24, ge=1, le=168),
) -> EndpointMetricsResponse:
    """
    Get SLA metrics for a specific endpoint.

    Args:
        endpoint: API endpoint path (e.g., 'analyze')
        time_window_hours: Time window for metrics (1-168 hours)

    Returns:
        Endpoint metrics including latency percentiles and uptime
    """
    tracker = get_sla_tracker()

    # Add leading slash if not present
    if not endpoint.startswith('/'):
        endpoint = f'/{endpoint}'

    metrics = await tracker.get_endpoint_metrics(endpoint, time_window_hours)

    if not metrics:
        raise HTTPException(
            status_code=404,
            detail=f'No SLA data found for endpoint: {endpoint}',
        )

    logger.info(
        'sla_metrics_retrieved',
        endpoint=endpoint,
        time_window_hours=time_window_hours,
    )

    return EndpointMetricsResponse(**metrics.__dict__)


@router.get('/metrics', response_model=Dict[str, EndpointMetricsResponse])
async def get_all_metrics(
    time_window_hours: int = Query(default=24, ge=1, le=168),
) -> Dict[str, EndpointMetricsResponse]:
    """
    Get SLA metrics for all tracked endpoints.

    Args:
        time_window_hours: Time window for metrics (1-168 hours)

    Returns:
        Dictionary mapping endpoint paths to their metrics
    """
    tracker = get_sla_tracker()

    all_metrics = await tracker.get_all_endpoints_metrics(time_window_hours)

    if not all_metrics:
        logger.warning('no_sla_data_available')
        return {}

    logger.info(
        'all_sla_metrics_retrieved',
        endpoint_count=len(all_metrics),
        time_window_hours=time_window_hours,
    )

    return {
        endpoint: EndpointMetricsResponse(**metrics.__dict__)
        for endpoint, metrics in all_metrics.items()
    }


@router.get('/alerts/{endpoint:path}', response_model=List[AlertResponse])
async def get_endpoint_alerts(endpoint: str) -> List[AlertResponse]:
    """
    Check SLA alerts for a specific endpoint.

    Args:
        endpoint: API endpoint path (e.g., 'analyze')

    Returns:
        List of triggered alerts
    """
    tracker = get_sla_tracker()

    # Add leading slash if not present
    if not endpoint.startswith('/'):
        endpoint = f'/{endpoint}'

    alerts = await tracker.check_alerts(endpoint)

    logger.info(
        'sla_alerts_checked',
        endpoint=endpoint,
        alert_count=len(alerts),
    )

    return [AlertResponse(**alert) for alert in alerts]


@router.get('/alerts', response_model=Dict[str, List[AlertResponse]])
async def get_all_alerts() -> Dict[str, List[AlertResponse]]:
    """
    Check SLA alerts for all tracked endpoints.

    Returns:
        Dictionary mapping endpoint paths to their alerts
    """
    tracker = get_sla_tracker()

    all_metrics = await tracker.get_all_endpoints_metrics()

    all_alerts = {}
    for endpoint in all_metrics.keys():
        alerts = await tracker.check_alerts(endpoint)
        if alerts:
            all_alerts[endpoint] = [AlertResponse(**alert) for alert in alerts]

    logger.info(
        'all_sla_alerts_checked',
        endpoints_with_alerts=len(all_alerts),
    )

    return all_alerts


@router.get('/trends/{endpoint:path}', response_model=TrendsResponse)
async def get_endpoint_trends(
    endpoint: str,
    days: int = Query(default=7, ge=1, le=30),
) -> TrendsResponse:
    """
    Get historical trend data for an endpoint.

    Args:
        endpoint: API endpoint path (e.g., 'analyze')
        days: Number of days of history (1-30)

    Returns:
        Historical trend data
    """
    tracker = get_sla_tracker()

    # Add leading slash if not present
    if not endpoint.startswith('/'):
        endpoint = f'/{endpoint}'

    trends = await tracker.get_historical_trends(endpoint, days)

    if not trends or not trends.get('dates'):
        raise HTTPException(
            status_code=404,
            detail=f'No historical data found for endpoint: {endpoint}',
        )

    logger.info(
        'sla_trends_retrieved',
        endpoint=endpoint,
        days=days,
    )

    return TrendsResponse(**trends)


@router.get('/summary')
async def get_sla_summary(
    time_window_hours: int = Query(default=24, ge=1, le=168),
) -> Dict[str, Any]:
    """
    Get overall SLA summary across all endpoints.

    Args:
        time_window_hours: Time window for metrics (1-168 hours)

    Returns:
        Aggregated SLA summary
    """
    tracker = get_sla_tracker()

    all_metrics = await tracker.get_all_endpoints_metrics(time_window_hours)

    if not all_metrics:
        return {
            'total_endpoints': 0,
            'total_requests': 0,
            'avg_uptime': 0.0,
            'avg_p95_latency': 0.0,
            'endpoints_with_alerts': 0,
        }

    total_requests = sum(m.total_requests for m in all_metrics.values())
    avg_uptime = sum(m.uptime_percentage for m in all_metrics.values()) / len(
        all_metrics
    )
    avg_p95 = sum(m.p95_latency_ms for m in all_metrics.values()) / len(all_metrics)

    # Count endpoints with alerts
    endpoints_with_alerts = 0
    for endpoint in all_metrics.keys():
        alerts = await tracker.check_alerts(endpoint)
        if alerts:
            endpoints_with_alerts += 1

    summary = {
        'total_endpoints': len(all_metrics),
        'total_requests': total_requests,
        'avg_uptime': round(avg_uptime, 2),
        'avg_p95_latency': round(avg_p95, 2),
        'endpoints_with_alerts': endpoints_with_alerts,
        'time_window_hours': time_window_hours,
    }

    logger.info('sla_summary_generated', summary=summary)

    return summary
