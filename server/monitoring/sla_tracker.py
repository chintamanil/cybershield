"""
SLA Tracker with P95 Latency Monitoring and Uptime Tracking.

Provides comprehensive SLA monitoring including:
- P95/P99 latency metrics per endpoint
- Uptime and availability tracking
- Alert threshold management
- Historical trend analysis
- Error rate monitoring
"""

import asyncio
import json
import time
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import redis.asyncio as redis

from utils.logging_config import get_security_logger

logger = get_security_logger('sla_tracker')


@dataclass
class SLAMetrics:
    """SLA metrics for a specific endpoint"""

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


@dataclass
class AlertThreshold:
    """Alert threshold configuration"""

    metric_name: str
    threshold_value: float
    comparison: str  # 'gt', 'lt', 'gte', 'lte'
    severity: str  # 'info', 'warning', 'critical'
    enabled: bool = True


class SLATracker:
    """
    SLA tracking and monitoring system.

    Tracks endpoint performance metrics, uptime, and alert thresholds
    using Redis for distributed storage.
    """

    def __init__(
        self,
        redis_client: Optional[redis.Redis] = None,
        redis_host: str = 'localhost',
        redis_port: int = 6379,
        redis_db: int = 0,
        retention_days: int = 30,
    ):
        """
        Initialize SLA tracker.

        Args:
            redis_client: Existing Redis client (creates new if None)
            redis_host: Redis host
            redis_port: Redis port
            redis_db: Redis database number
            retention_days: How long to retain historical data
        """
        self.redis = redis_client
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.redis_db = redis_db
        self.retention_days = retention_days

        # Default alert thresholds
        self.default_thresholds = [
            AlertThreshold('p95_latency_ms', 1000.0, 'gt', 'warning'),
            AlertThreshold('p95_latency_ms', 2000.0, 'gt', 'critical'),
            AlertThreshold('error_rate', 0.05, 'gt', 'warning'),  # 5%
            AlertThreshold('error_rate', 0.10, 'gt', 'critical'),  # 10%
            AlertThreshold('uptime_percentage', 99.5, 'lt', 'warning'),
            AlertThreshold('uptime_percentage', 99.0, 'lt', 'critical'),
        ]

    async def connect(self) -> None:
        """Connect to Redis"""
        if not self.redis:
            self.redis = await redis.Redis(
                host=self.redis_host,
                port=self.redis_port,
                db=self.redis_db,
                decode_responses=True,
            )
        logger.info('sla_tracker_connected', host=self.redis_host, port=self.redis_port)

    async def close(self) -> None:
        """Close Redis connection"""
        if self.redis:
            await self.redis.aclose()
        logger.info('sla_tracker_closed')

    def _get_key(self, endpoint: str, metric_type: str) -> str:
        """
        Generate Redis key for SLA metric.

        Args:
            endpoint: API endpoint (e.g., '/analyze')
            metric_type: Type of metric (e.g., 'latencies', 'uptime')

        Returns:
            Redis key string
        """
        # Sanitize endpoint for Redis key
        sanitized_endpoint = endpoint.replace('/', ':').strip(':')
        return f'sla:{sanitized_endpoint}:{metric_type}'

    async def record_request(
        self,
        endpoint: str,
        latency_ms: float,
        success: bool = True,
        error_type: Optional[str] = None,
    ) -> None:
        """
        Record a single API request for SLA tracking.

        Args:
            endpoint: API endpoint path
            latency_ms: Request latency in milliseconds
            success: Whether request succeeded
            error_type: Type of error if failed
        """
        if not self.redis:
            await self.connect()

        timestamp = time.time()
        current_time_str = datetime.now().isoformat()

        # Store latency in sorted set (score = timestamp)
        latency_key = self._get_key(endpoint, 'latencies')
        await self.redis.zadd(
            latency_key, {f'{latency_ms}:{current_time_str}': timestamp}
        )

        # Expire old latencies
        cutoff_time = timestamp - (self.retention_days * 86400)
        await self.redis.zremrangebyscore(latency_key, 0, cutoff_time)

        # Increment request counters
        total_key = self._get_key(endpoint, 'total_requests')
        await self.redis.incr(total_key)

        if success:
            success_key = self._get_key(endpoint, 'successful_requests')
            await self.redis.incr(success_key)
        else:
            failed_key = self._get_key(endpoint, 'failed_requests')
            await self.redis.incr(failed_key)

            # Track error types
            if error_type:
                error_key = self._get_key(endpoint, f'errors:{error_type}')
                await self.redis.incr(error_key)

        # Update last seen timestamp
        last_seen_key = self._get_key(endpoint, 'last_seen')
        await self.redis.set(last_seen_key, current_time_str)

        logger.debug(
            'request_recorded',
            endpoint=endpoint,
            latency_ms=latency_ms,
            success=success,
            error_type=error_type,
        )

    async def get_endpoint_metrics(
        self, endpoint: str, time_window_hours: int = 24
    ) -> Optional[SLAMetrics]:
        """
        Get SLA metrics for a specific endpoint.

        Args:
            endpoint: API endpoint path
            time_window_hours: Time window for metrics (default 24 hours)

        Returns:
            SLAMetrics object or None if no data
        """
        if not self.redis:
            await self.connect()

        # Get latencies within time window
        latency_key = self._get_key(endpoint, 'latencies')
        cutoff_time = time.time() - (time_window_hours * 3600)

        # Get all latencies in time window
        latency_data = await self.redis.zrangebyscore(
            latency_key, cutoff_time, '+inf', withscores=True
        )

        if not latency_data:
            logger.warning('no_sla_data', endpoint=endpoint)
            return None

        # Extract latency values
        latencies = [float(entry[0].split(':')[0]) for entry in latency_data]
        latencies.sort()

        # Calculate percentiles
        def percentile(data: List[float], p: float) -> float:
            if not data:
                return 0.0
            k = (len(data) - 1) * p
            f = int(k)
            c = k - f
            if f + 1 < len(data):
                return data[f] + c * (data[f + 1] - data[f])
            return data[f]

        p50 = percentile(latencies, 0.50)
        p95 = percentile(latencies, 0.95)
        p99 = percentile(latencies, 0.99)
        avg = sum(latencies) / len(latencies) if latencies else 0.0

        # Get request counts
        total_key = self._get_key(endpoint, 'total_requests')
        success_key = self._get_key(endpoint, 'successful_requests')
        failed_key = self._get_key(endpoint, 'failed_requests')

        total_requests = int(await self.redis.get(total_key) or 0)
        successful_requests = int(await self.redis.get(success_key) or 0)
        failed_requests = int(await self.redis.get(failed_key) or 0)

        # Calculate error rate and uptime
        error_rate = failed_requests / total_requests if total_requests > 0 else 0.0
        uptime_percentage = (
            (successful_requests / total_requests * 100) if total_requests > 0 else 0.0
        )

        # Get last update time
        last_seen_key = self._get_key(endpoint, 'last_seen')
        last_updated = await self.redis.get(last_seen_key) or datetime.now().isoformat()

        metrics = SLAMetrics(
            endpoint=endpoint,
            total_requests=total_requests,
            successful_requests=successful_requests,
            failed_requests=failed_requests,
            error_rate=error_rate,
            avg_latency_ms=round(avg, 2),
            p50_latency_ms=round(p50, 2),
            p95_latency_ms=round(p95, 2),
            p99_latency_ms=round(p99, 2),
            uptime_percentage=round(uptime_percentage, 2),
            last_updated=last_updated,
            timestamp=datetime.now().isoformat(),
        )

        logger.debug('endpoint_metrics_retrieved', endpoint=endpoint, metrics=metrics)

        return metrics

    async def get_all_endpoints_metrics(
        self, time_window_hours: int = 24
    ) -> Dict[str, SLAMetrics]:
        """
        Get SLA metrics for all tracked endpoints.

        Args:
            time_window_hours: Time window for metrics (default 24 hours)

        Returns:
            Dictionary mapping endpoint to SLAMetrics
        """
        if not self.redis:
            await self.connect()

        # Find all tracked endpoints
        pattern = 'sla:*:total_requests'
        endpoints_metrics = {}

        async for key in self.redis.scan_iter(match=pattern):
            # Extract endpoint from key
            endpoint_part = key.replace('sla:', '').replace(':total_requests', '')
            endpoint = '/' + endpoint_part.replace(':', '/')

            metrics = await self.get_endpoint_metrics(endpoint, time_window_hours)
            if metrics:
                endpoints_metrics[endpoint] = metrics

        logger.info(
            'all_endpoints_metrics_retrieved', endpoint_count=len(endpoints_metrics)
        )

        return endpoints_metrics

    async def check_alerts(
        self,
        endpoint: str,
        thresholds: Optional[List[AlertThreshold]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Check if endpoint metrics trigger any alerts.

        Args:
            endpoint: API endpoint to check
            thresholds: Custom alert thresholds (uses defaults if None)

        Returns:
            List of triggered alerts
        """
        if thresholds is None:
            thresholds = self.default_thresholds

        metrics = await self.get_endpoint_metrics(endpoint)
        if not metrics:
            return []

        triggered_alerts = []

        for threshold in thresholds:
            if not threshold.enabled:
                continue

            metric_value = getattr(metrics, threshold.metric_name, None)
            if metric_value is None:
                continue

            # Compare metric value against threshold
            is_triggered = False
            if (
                threshold.comparison == 'gt'
                and metric_value > threshold.threshold_value
            ):
                is_triggered = True
            elif (
                threshold.comparison == 'gte'
                and metric_value >= threshold.threshold_value
            ):
                is_triggered = True
            elif (
                threshold.comparison == 'lt'
                and metric_value < threshold.threshold_value
            ):
                is_triggered = True
            elif (
                threshold.comparison == 'lte'
                and metric_value <= threshold.threshold_value
            ):
                is_triggered = True

            if is_triggered:
                alert = {
                    'endpoint': endpoint,
                    'metric_name': threshold.metric_name,
                    'metric_value': metric_value,
                    'threshold_value': threshold.threshold_value,
                    'comparison': threshold.comparison,
                    'severity': threshold.severity,
                    'timestamp': datetime.now().isoformat(),
                    'message': f'{threshold.metric_name} ({metric_value}) {threshold.comparison} {threshold.threshold_value}',
                }
                triggered_alerts.append(alert)

                logger.warning(
                    'sla_alert_triggered',
                    endpoint=endpoint,
                    metric=threshold.metric_name,
                    value=metric_value,
                    threshold=threshold.threshold_value,
                    severity=threshold.severity,
                )

        return triggered_alerts

    async def get_historical_trends(
        self, endpoint: str, days: int = 7
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get historical trend data for an endpoint.

        Args:
            endpoint: API endpoint
            days: Number of days of history

        Returns:
            Dictionary with daily aggregated metrics
        """
        if not self.redis:
            await self.connect()

        trends = defaultdict(list)
        latency_key = self._get_key(endpoint, 'latencies')

        for day_offset in range(days):
            day_start = datetime.now() - timedelta(days=day_offset + 1)
            day_end = datetime.now() - timedelta(days=day_offset)

            start_timestamp = day_start.timestamp()
            end_timestamp = day_end.timestamp()

            # Get latencies for this day
            day_latencies = await self.redis.zrangebyscore(
                latency_key, start_timestamp, end_timestamp
            )

            if day_latencies:
                latencies = [float(entry.split(':')[0]) for entry in day_latencies]
                latencies.sort()

                trends['dates'].append(day_start.strftime('%Y-%m-%d'))
                trends['avg_latency'].append(round(sum(latencies) / len(latencies), 2))
                trends['p95_latency'].append(
                    round(
                        latencies[int(len(latencies) * 0.95)] if latencies else 0.0,
                        2,
                    )
                )
                trends['request_count'].append(len(latencies))

        logger.debug('historical_trends_retrieved', endpoint=endpoint, days=days)

        return dict(trends)

    async def reset_endpoint_metrics(self, endpoint: str) -> None:
        """
        Reset all metrics for an endpoint (admin function).

        Args:
            endpoint: API endpoint to reset
        """
        if not self.redis:
            await self.connect()

        # Find all keys for this endpoint
        pattern = self._get_key(endpoint, '*')
        keys = []
        async for key in self.redis.scan_iter(match=pattern):
            keys.append(key)

        if keys:
            await self.redis.delete(*keys)

        logger.warning(
            'endpoint_metrics_reset', endpoint=endpoint, keys_deleted=len(keys)
        )


# Example usage and testing
if __name__ == '__main__':

    async def test_sla_tracker():
        """Test SLA tracker functionality"""
        tracker = SLATracker()
        await tracker.connect()

        print('Testing SLA Tracker\n' + '=' * 50)

        # Simulate API requests
        print('\n1. Simulating API requests for /analyze endpoint')
        endpoint = '/analyze'

        # Simulate 100 requests with varying latencies
        for i in range(100):
            if i < 90:
                # 90% successful requests
                latency = 100 + (i * 10)  # Increasing latency
                await tracker.record_request(endpoint, latency, success=True)
            else:
                # 10% failed requests
                latency = 5000  # High latency for failures
                await tracker.record_request(
                    endpoint, latency, success=False, error_type='timeout'
                )

            if i % 20 == 0:
                await asyncio.sleep(0.01)  # Small delay

        print(f'   Recorded 100 requests (90 success, 10 failures)')

        # Get endpoint metrics
        print('\n2. Retrieving endpoint metrics')
        metrics = await tracker.get_endpoint_metrics(endpoint)

        if metrics:
            print(f'\n   Endpoint: {metrics.endpoint}')
            print(f'   Total Requests: {metrics.total_requests}')
            print(f'   Success Rate: {metrics.uptime_percentage:.2f}%')
            print(f'   Error Rate: {metrics.error_rate * 100:.2f}%')
            print(f'   Avg Latency: {metrics.avg_latency_ms:.2f}ms')
            print(f'   P50 Latency: {metrics.p50_latency_ms:.2f}ms')
            print(f'   P95 Latency: {metrics.p95_latency_ms:.2f}ms')
            print(f'   P99 Latency: {metrics.p99_latency_ms:.2f}ms')

        # Check alerts
        print('\n3. Checking alert thresholds')
        alerts = await tracker.check_alerts(endpoint)

        if alerts:
            print(f'   ⚠️  {len(alerts)} alerts triggered:')
            for alert in alerts:
                print(
                    f'      [{alert["severity"].upper()}] {alert["metric_name"]}: '
                    f'{alert["metric_value"]:.2f} {alert["comparison"]} {alert["threshold_value"]:.2f}'
                )
        else:
            print('   ✅ No alerts triggered')

        # Get all endpoints
        print('\n4. All tracked endpoints')
        all_metrics = await tracker.get_all_endpoints_metrics()
        for ep, ep_metrics in all_metrics.items():
            print(
                f'   {ep}: {ep_metrics.total_requests} requests, '
                f'{ep_metrics.p95_latency_ms:.2f}ms P95'
            )

        # Cleanup
        await tracker.reset_endpoint_metrics(endpoint)
        await tracker.close()

        print('\n' + '=' * 50)
        print('✅ SLA tracker test complete\n')

    asyncio.run(test_sla_tracker())
