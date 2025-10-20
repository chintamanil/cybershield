"""
FastAPI middleware for automatic SLA tracking.

Automatically records latency, success/failure, and error types
for all API requests.
"""

import time
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from server.monitoring.sla_tracker import SLATracker
from utils.logging_config import get_security_logger

logger = get_security_logger('sla_middleware')


class SLAMiddleware(BaseHTTPMiddleware):
    """
    Middleware to automatically track SLA metrics for all API requests.

    Records:
    - Request latency (in milliseconds)
    - Success/failure status
    - Error types for failed requests
    """

    def __init__(self, app: ASGIApp, sla_tracker: SLATracker):
        """
        Initialize SLA middleware.

        Args:
            app: ASGI application
            sla_tracker: SLATracker instance for recording metrics
        """
        super().__init__(app)
        self.sla_tracker = sla_tracker

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request and record SLA metrics.

        Args:
            request: Incoming HTTP request
            call_next: Next middleware/endpoint in chain

        Returns:
            HTTP response
        """
        # Skip SLA tracking for health check and static files
        if request.url.path in ['/health', '/favicon.ico', '/docs', '/openapi.json']:
            return await call_next(request)

        # Record start time
        start_time = time.time()
        endpoint = request.url.path
        error_type = None
        success = True

        try:
            # Process request
            response = await call_next(request)

            # Determine success based on status code
            if response.status_code >= 400:
                success = False
                if response.status_code >= 500:
                    error_type = 'server_error'
                elif response.status_code == 429:
                    error_type = 'rate_limit'
                elif response.status_code == 404:
                    error_type = 'not_found'
                elif response.status_code == 401 or response.status_code == 403:
                    error_type = 'auth_error'
                else:
                    error_type = 'client_error'

        except Exception as e:
            # Request failed with exception
            success = False
            error_type = type(e).__name__

            # Re-raise exception after recording
            latency_ms = (time.time() - start_time) * 1000
            await self.sla_tracker.record_request(
                endpoint=endpoint,
                latency_ms=latency_ms,
                success=success,
                error_type=error_type,
            )

            logger.error(
                'request_failed_with_exception',
                endpoint=endpoint,
                error=str(e),
                error_type=error_type,
                latency_ms=latency_ms,
            )

            raise

        # Calculate latency
        latency_ms = (time.time() - start_time) * 1000

        # Record SLA metrics
        await self.sla_tracker.record_request(
            endpoint=endpoint,
            latency_ms=latency_ms,
            success=success,
            error_type=error_type,
        )

        # Add latency header to response
        response.headers['X-Response-Time'] = f'{latency_ms:.2f}ms'

        # Log slow requests
        if latency_ms > 1000:
            logger.warning(
                'slow_request',
                endpoint=endpoint,
                latency_ms=latency_ms,
                status_code=response.status_code,
            )

        return response


async def setup_sla_middleware(
    app, redis_host: str = 'localhost', redis_port: int = 6379
):
    """
    Setup SLA tracking middleware for FastAPI app.

    Args:
        app: FastAPI application instance
        redis_host: Redis host for SLA storage
        redis_port: Redis port

    Returns:
        SLATracker instance for additional monitoring
    """
    sla_tracker = SLATracker(redis_host=redis_host, redis_port=redis_port)
    await sla_tracker.connect()

    app.add_middleware(SLAMiddleware, sla_tracker=sla_tracker)

    logger.info(
        'sla_middleware_configured',
        redis_host=redis_host,
        redis_port=redis_port,
    )

    return sla_tracker
