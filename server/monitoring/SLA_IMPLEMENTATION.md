# SLA Tracking System - Implementation Guide

**Status**: ✅ Production Ready
**Version**: 1.0
**Date**: October 20, 2025

---

## Overview

Comprehensive SLA (Service Level Agreement) tracking system for CyberShield that automatically monitors API performance, uptime, and alert thresholds across all endpoints.

### Key Features

- ✅ **Automatic Request Tracking** - FastAPI middleware integration (zero code changes)
- ✅ **P95/P99 Latency Metrics** - Accurate percentile calculations using Redis sorted sets
- ✅ **Uptime Monitoring** - Success/failure tracking with error categorization
- ✅ **Configurable Alerts** - Multi-level thresholds (info, warning, critical)
- ✅ **Historical Trends** - 7-30 day retention with daily aggregation
- ✅ **REST API** - Full API for external monitoring tool integration
- ✅ **Interactive Dashboard** - Streamlit visualization with charts and gauges

---

## Architecture

### Components

```
server/monitoring/
├── sla_tracker.py         # Core SLA tracking logic (580 lines)
└── __init__.py

server/middleware/
├── sla_middleware.py      # FastAPI middleware (145 lines)
└── __init__.py

server/endpoints/
├── sla_endpoints.py       # REST API endpoints (340 lines)
└── __init__.py

frontend/components/
└── sla_dashboard.py       # Streamlit dashboard (460 lines)
```

### Data Flow

```
API Request
    ↓
FastAPI (SLAMiddleware)
    ↓
[Measure Latency + Success/Failure]
    ↓
SLATracker.record_request()
    ↓
Redis Storage (sorted sets + counters)
    ↓
[Query Endpoints or Dashboard]
    ↓
GET /sla/metrics → SLAMetrics
GET /sla/alerts → Alerts
GET /sla/trends → Historical Data
```

---

## Installation & Setup

### 1. Backend Integration

Add to `server/main.py`:

```python
from server.middleware import setup_sla_middleware
from server.endpoints import sla_router, set_sla_tracker

app = FastAPI(...)

@app.on_event("startup")
async def startup():
    # Initialize SLA tracker and middleware
    sla_tracker = await setup_sla_middleware(
        app,
        redis_host='localhost',
        redis_port=6379
    )

    # Register SLA tracker for API endpoints
    set_sla_tracker(sla_tracker)

    # Include SLA API router
    app.include_router(sla_router)
```

### 2. Frontend Integration

Add to `frontend/app.py`:

```python
from frontend.components.sla_dashboard import (
    render_sla_dashboard,
    render_sla_stats_sidebar
)
from server.monitoring import SLATracker

# Initialize tracker
sla_tracker = SLATracker(redis_host='localhost', redis_port=6379)

# Sidebar quick stats
render_sla_stats_sidebar(sla_tracker)

# Full dashboard page
if st.sidebar.button('SLA Dashboard'):
    render_sla_dashboard(sla_tracker, time_window_hours=24)
```

---

## API Reference

### REST Endpoints

#### 1. Get Endpoint Metrics

```bash
GET /sla/metrics/{endpoint}?time_window_hours=24

# Example
curl http://localhost:8000/sla/metrics/analyze?time_window_hours=24
```

**Response**:
```json
{
  "endpoint": "/analyze",
  "total_requests": 1500,
  "successful_requests": 1425,
  "failed_requests": 75,
  "error_rate": 0.05,
  "avg_latency_ms": 245.67,
  "p50_latency_ms": 180.23,
  "p95_latency_ms": 890.45,
  "p99_latency_ms": 1234.56,
  "uptime_percentage": 95.0,
  "last_updated": "2025-10-20T15:04:22.958236",
  "timestamp": "2025-10-20T15:30:00.123456"
}
```

#### 2. Get All Metrics

```bash
GET /sla/metrics?time_window_hours=24

curl http://localhost:8000/sla/metrics
```

**Response**: Dictionary mapping endpoints to their metrics

#### 3. Get Alerts

```bash
GET /sla/alerts/{endpoint}

# Example
curl http://localhost:8000/sla/alerts/analyze
```

**Response**:
```json
[
  {
    "endpoint": "/analyze",
    "metric_name": "p95_latency_ms",
    "metric_value": 5000.0,
    "threshold_value": 1000.0,
    "comparison": "gt",
    "severity": "warning",
    "timestamp": "2025-10-20T15:04:22.962733",
    "message": "p95_latency_ms (5000.0) gt 1000.0"
  }
]
```

#### 4. Get All Alerts

```bash
GET /sla/alerts

curl http://localhost:8000/sla/alerts
```

**Response**: Dictionary mapping endpoints to their alerts

#### 5. Get Historical Trends

```bash
GET /sla/trends/{endpoint}?days=7

# Example
curl http://localhost:8000/sla/trends/analyze?days=7
```

**Response**:
```json
{
  "dates": ["2025-10-14", "2025-10-15", "2025-10-16", ...],
  "avg_latency": [250.5, 245.3, 260.8, ...],
  "p95_latency": [890.4, 875.2, 910.3, ...],
  "request_count": [1500, 1450, 1600, ...]
}
```

#### 6. Get SLA Summary

```bash
GET /sla/summary?time_window_hours=24

curl http://localhost:8000/sla/summary
```

**Response**:
```json
{
  "total_endpoints": 5,
  "total_requests": 7500,
  "avg_uptime": 99.2,
  "avg_p95_latency": 850.5,
  "endpoints_with_alerts": 2,
  "time_window_hours": 24
}
```

---

## Metrics Explained

### Latency Percentiles

| Metric | Description | Interpretation |
|--------|-------------|----------------|
| **Avg Latency** | Mean of all requests | Overall average performance |
| **P50 (Median)** | 50th percentile | Typical user experience |
| **P95** | 95th percentile | Most users experience this or better |
| **P99** | 99th percentile | Worst-case for 99% of users |

**Why P95/P99?**
- Average can be misleading (skewed by outliers)
- P95 captures "most users" experience
- P99 catches tail latencies that affect user satisfaction

### Uptime vs Availability

- **Uptime %**: `(successful_requests / total_requests) × 100`
- **Error Rate**: `(failed_requests / total_requests)`
- **99.9% uptime** = ~43 minutes downtime per month
- **99.5% uptime** = ~3.6 hours downtime per month

---

## Alert Configuration

### Default Thresholds

```python
DEFAULT_THRESHOLDS = [
    # Latency alerts
    AlertThreshold('p95_latency_ms', 1000.0, 'gt', 'warning'),    # P95 > 1s
    AlertThreshold('p95_latency_ms', 2000.0, 'gt', 'critical'),   # P95 > 2s

    # Error rate alerts
    AlertThreshold('error_rate', 0.05, 'gt', 'warning'),          # 5% errors
    AlertThreshold('error_rate', 0.10, 'gt', 'critical'),         # 10% errors

    # Uptime alerts
    AlertThreshold('uptime_percentage', 99.5, 'lt', 'warning'),   # < 99.5%
    AlertThreshold('uptime_percentage', 99.0, 'lt', 'critical'),  # < 99%
]
```

### Custom Thresholds

```python
from server.monitoring.sla_tracker import AlertThreshold

custom_thresholds = [
    AlertThreshold('p99_latency_ms', 3000.0, 'gt', 'critical'),
    AlertThreshold('avg_latency_ms', 500.0, 'gt', 'warning'),
]

alerts = await sla_tracker.check_alerts('/analyze', custom_thresholds)
```

### Comparison Operators

- `'gt'`: Greater than (>)
- `'gte'`: Greater than or equal (≥)
- `'lt'`: Less than (<)
- `'lte'`: Less than or equal (≤)

---

## Storage Schema

### Redis Keys

```javascript
// Latency sorted set (score = timestamp)
sla:analyze:latencies → sorted_set {
  "125.50:2025-10-20T15:04:22": 1729429462.123,
  "234.75:2025-10-20T15:04:23": 1729429463.456,
  ...
}

// Request counters
sla:analyze:total_requests → 1500
sla:analyze:successful_requests → 1425
sla:analyze:failed_requests → 75

// Error type tracking
sla:analyze:errors:timeout → 10
sla:analyze:errors:server_error → 5
sla:analyze:errors:rate_limit → 3

// Last seen timestamp
sla:analyze:last_seen → "2025-10-20T15:04:22.958236"
```

### Data Retention

- **Latency data**: 30 days (configurable via `retention_days`)
- **Counters**: Persistent (no expiration)
- **Automatic cleanup**: Old entries removed on new requests

---

## Dashboard Components

### 1. Summary Metrics

```python
render_sla_dashboard(sla_tracker, time_window_hours=24)
```

Displays:
- **Total Requests** across all endpoints
- **Average Uptime %** across all endpoints
- **Total Failures** count
- **Average P95 Latency** across all endpoints

### 2. Latency Distribution

Bar chart showing:
- Avg, P50, P95, P99 latencies
- Color-coded by severity (green → yellow → orange → red)

### 3. Uptime Gauge

Circular gauge with:
- Current uptime percentage
- Color zones (red < 95%, yellow 95-99%, green > 99%)
- Target threshold line at 99%

### 4. Error Rate Gauge

Circular gauge with:
- Current error rate percentage
- Color zones (green < 1%, yellow 1-5%, red > 5%)

### 5. Alert Status Panel

Expandable alerts with:
- Severity indicators (ℹ️ info, ⚠️ warning, 🔴 critical)
- Metric value vs threshold
- Trigger timestamp

### 6. Historical Trends

Line + bar chart showing:
- **P95 latency trend** (line chart)
- **Request volume** (bar chart)
- 7-day historical view

---

## Performance Considerations

### Percentile Calculation

Uses Redis sorted sets for efficient percentile queries:
- **Time complexity**: O(log N) for insertion, O(M log N) for range queries
- **Space complexity**: O(N) where N = requests in retention window
- **Typical dataset**: 100,000 requests/day = ~3M entries/month

### Optimization Tips

1. **Adjust retention period** based on storage constraints:
   ```python
   sla_tracker = SLATracker(retention_days=7)  # Reduce from 30 days
   ```

2. **Sample high-traffic endpoints**:
   ```python
   # Record only 10% of requests
   if random.random() < 0.1:
       await sla_tracker.record_request(...)
   ```

3. **Use Redis cluster** for high-scale deployments

---

## Integration Examples

### 1. Prometheus Export

```python
from prometheus_client import Gauge, Counter

# Create metrics
p95_latency = Gauge('api_p95_latency_ms', 'P95 latency', ['endpoint'])
error_rate = Gauge('api_error_rate', 'Error rate', ['endpoint'])

# Export SLA metrics
async def update_prometheus_metrics():
    all_metrics = await sla_tracker.get_all_endpoints_metrics()

    for endpoint, metrics in all_metrics.items():
        p95_latency.labels(endpoint=endpoint).set(metrics.p95_latency_ms)
        error_rate.labels(endpoint=endpoint).set(metrics.error_rate)
```

### 2. Slack Alerts

```python
import aiohttp

async def send_slack_alert(alert):
    webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

    message = {
        "text": f"🚨 SLA Alert: {alert['severity'].upper()}",
        "attachments": [{
            "color": "danger" if alert['severity'] == 'critical' else "warning",
            "fields": [
                {"title": "Endpoint", "value": alert['endpoint']},
                {"title": "Metric", "value": alert['metric_name']},
                {"title": "Value", "value": str(alert['metric_value'])},
                {"title": "Threshold", "value": str(alert['threshold_value'])},
            ]
        }]
    }

    async with aiohttp.ClientSession() as session:
        await session.post(webhook_url, json=message)

# Check and send alerts
alerts = await sla_tracker.check_alerts('/analyze')
for alert in alerts:
    if alert['severity'] in ['warning', 'critical']:
        await send_slack_alert(alert)
```

### 3. Custom Dashboard Embedding

```python
# Embed in custom dashboard
from fastapi.responses import HTMLResponse
from server.monitoring import SLATracker

@app.get("/dashboard/sla", response_class=HTMLResponse)
async def sla_dashboard_page():
    tracker = SLATracker()
    all_metrics = await tracker.get_all_endpoints_metrics()

    # Generate HTML with metrics
    html = f"""
    <html>
        <head><title>SLA Dashboard</title></head>
        <body>
            <h1>System SLA Metrics</h1>
            <div class="metrics">
                {render_metrics_html(all_metrics)}
            </div>
        </body>
    </html>
    """
    return html
```

---

## Troubleshooting

### Issue: No SLA data appearing

**Cause**: Middleware not registered or Redis connection failed

**Solution**:
1. Check middleware is added: `app.add_middleware(SLAMiddleware, ...)`
2. Verify Redis connection: `redis-cli ping`
3. Check logs for connection errors

### Issue: Incorrect percentiles

**Cause**: Insufficient data points or time window too short

**Solution**:
1. Ensure at least 100+ requests for accurate percentiles
2. Increase `time_window_hours` parameter
3. Check data retention hasn't expired entries

### Issue: High memory usage

**Cause**: Large retention window with high traffic

**Solution**:
1. Reduce `retention_days` (default 30 → 7 days)
2. Implement request sampling
3. Use Redis cluster for distribution

---

## Best Practices

### 1. Alert Fatigue Prevention

- Set thresholds based on actual baseline, not aspirational targets
- Use multi-level severity (info → warning → critical)
- Implement alert cooldowns/deduplication

### 2. Meaningful Time Windows

- **24 hours**: Daily operations monitoring
- **7 days**: Weekly trend analysis
- **30 days**: Monthly reporting and capacity planning

### 3. Endpoint Grouping

Group related endpoints for aggregate metrics:

```python
# Group all /tools/* endpoints
tools_endpoints = ['/tools/abuseipdb', '/tools/shodan', '/tools/virustotal']

total_requests = sum(
    (await sla_tracker.get_endpoint_metrics(ep)).total_requests
    for ep in tools_endpoints
)
```

---

## Production Checklist

- [ ] SLA middleware registered in `server/main.py`
- [ ] SLA endpoints included in router
- [ ] Redis connection configured and tested
- [ ] Alert thresholds customized for your SLAs
- [ ] Dashboard accessible in Streamlit frontend
- [ ] Monitoring/alerting integration (Prometheus, Slack, etc.)
- [ ] Data retention configured appropriately
- [ ] Load testing performed to validate metrics
- [ ] Documentation updated with team-specific thresholds

---

## References

- **SLA Tracker**: `server/monitoring/sla_tracker.py`
- **Middleware**: `server/middleware/sla_middleware.py`
- **API Endpoints**: `server/endpoints/sla_endpoints.py`
- **Dashboard**: `frontend/components/sla_dashboard.py`

---

**Status**: ✅ Production Ready
**Last Updated**: October 20, 2025
**Version**: 1.0
