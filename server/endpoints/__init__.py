"""
API endpoints for CyberShield server.
"""

from server.endpoints.sla_endpoints import router as sla_router
from server.endpoints.sla_endpoints import set_sla_tracker

__all__ = ['sla_router', 'set_sla_tracker']
