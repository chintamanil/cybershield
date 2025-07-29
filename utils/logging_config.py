"""
Structured logging configuration for CyberShield platform.

This module provides centralized logging configuration using structlog
for consistent, structured logging across all components.
"""

import os
import sys
import logging
from typing import Any, Dict, Optional
import structlog
from datetime import datetime


def configure_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    json_format: bool = False,
    include_stdlib: bool = True,
) -> None:
    """
    Configure structured logging for the CyberShield platform.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for log output
        json_format: Whether to output logs in JSON format
        include_stdlib: Whether to configure stdlib logging
    """
    # Set log level
    level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Configure structlog processors
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    
    # Add context processors for security events
    processors.extend([
        add_security_context,
        add_request_id,
    ])
    
    if json_format:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(
            structlog.dev.ConsoleRenderer(colors=sys.stdout.isatty())
        )
    
    # Configure structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        context_class=dict,
        cache_logger_on_first_use=True,
    )
    
    # Configure stdlib logging if requested
    if include_stdlib:
        # Always add console handler for terminal output
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(
            structlog.stdlib.ProcessorFormatter(
                processor=structlog.dev.ConsoleRenderer(colors=True)
                if not json_format
                else structlog.processors.JSONRenderer(),
            )
        )
        
        root_logger = logging.getLogger()
        root_logger.addHandler(console_handler)
        
        # Add file handler if log_file is specified
        if log_file:
            # Create directory if it doesn't exist
            import pathlib
            log_path = pathlib.Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(
                structlog.stdlib.ProcessorFormatter(
                    processor=structlog.dev.ConsoleRenderer(colors=False)
                    if not json_format
                    else structlog.processors.JSONRenderer(),
                )
            )
            root_logger.addHandler(file_handler)
        
        root_logger.setLevel(level)


def add_security_context(logger: Any, method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add security-specific context to log events.
    
    Args:
        logger: The logger instance
        method_name: The logging method name
        event_dict: The event dictionary
        
    Returns:
        Enhanced event dictionary with security context
    """
    # Add security classification for certain log levels
    if method_name in ["warning", "error", "critical"]:
        event_dict["security_relevant"] = True
    
    # Add component context if available
    if hasattr(logger, "_context") and "component" in logger._context:
        event_dict["component"] = logger._context["component"]
    
    return event_dict


def add_request_id(logger: Any, method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add request ID to log events for tracing.
    
    Args:
        logger: The logger instance
        method_name: The logging method name
        event_dict: The event dictionary
        
    Returns:
        Enhanced event dictionary with request ID
    """
    # Try to get request ID from context
    if hasattr(logger, "_context") and "request_id" in logger._context:
        event_dict["request_id"] = logger._context["request_id"]
    
    return event_dict


def get_logger(name: str, **context: Any) -> structlog.BoundLogger:
    """
    Get a structured logger with optional context.
    
    Args:
        name: Logger name (typically __name__)
        **context: Additional context to bind to the logger
        
    Returns:
        Configured structured logger
    """
    logger = structlog.get_logger(name)
    if context:
        logger = logger.bind(**context)
    return logger


def get_security_logger(component: str, **context: Any) -> structlog.BoundLogger:
    """
    Get a security-focused logger with component context.
    
    Args:
        component: Component name (e.g., 'threat_agent', 'pii_agent')
        **context: Additional context to bind to the logger
        
    Returns:
        Configured structured logger with security context
    """
    security_context = {
        "component": component,
        "category": "security",
        **context
    }
    return get_logger(f"cybershield.{component}", **security_context)


def log_security_event(
    logger: structlog.BoundLogger,
    event_type: str,
    severity: str = "info",
    **details: Any
) -> None:
    """
    Log a security event with standardized format.
    
    Args:
        logger: The structured logger to use
        event_type: Type of security event (e.g., 'threat_detected', 'pii_found')
        severity: Event severity (debug, info, warning, error, critical)
        **details: Additional event details
    """
    log_method = getattr(logger, severity.lower(), logger.info)
    log_method(
        "Security event",
        event_type=event_type,
        timestamp=datetime.utcnow().isoformat(),
        **details
    )


def log_api_request(
    logger: structlog.BoundLogger,
    method: str,
    path: str,
    status_code: int,
    duration_ms: float,
    **details: Any
) -> None:
    """
    Log an API request with standardized format.
    
    Args:
        logger: The structured logger to use
        method: HTTP method
        path: Request path
        status_code: HTTP status code
        duration_ms: Request duration in milliseconds
        **details: Additional request details
    """
    severity = "error" if status_code >= 400 else "info"
    log_method = getattr(logger, severity)
    
    log_method(
        "API request",
        method=method,
        path=path,
        status_code=status_code,
        duration_ms=duration_ms,
        **details
    )


def log_agent_action(
    logger: structlog.BoundLogger,
    agent_name: str,
    action: str,
    success: bool = True,
    **details: Any
) -> None:
    """
    Log an agent action with standardized format.
    
    Args:
        logger: The structured logger to use
        agent_name: Name of the agent performing the action
        action: Description of the action
        success: Whether the action was successful
        **details: Additional action details
    """
    severity = "info" if success else "warning"
    log_method = getattr(logger, severity)
    
    log_method(
        "Agent action",
        agent_name=agent_name,
        action=action,
        success=success,
        **details
    )


# Environment-based configuration
def setup_from_env() -> None:
    """
    Setup logging configuration from environment variables.
    """
    log_level = os.getenv("LOG_LEVEL", "INFO")
    log_file = os.getenv("LOG_FILE")
    json_format = os.getenv("LOG_FORMAT", "").lower() == "json"
    
    configure_logging(
        log_level=log_level,
        log_file=log_file,
        json_format=json_format
    )