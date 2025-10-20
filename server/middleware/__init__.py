"""
FastAPI middleware components.
"""

from server.middleware.sla_middleware import SLAMiddleware, setup_sla_middleware

__all__ = ['SLAMiddleware', 'setup_sla_middleware']
