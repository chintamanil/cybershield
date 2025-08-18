# AWS CloudWatch logging integration
import boto3
import json
import time
from typing import Dict, Any
from utils.environment_config import config
from utils.logging_config import get_security_logger

logger = get_security_logger("aws_logging")


class CloudWatchHandler:
    """CloudWatch Logs integration for AWS deployment"""

    def __init__(self):
        if config.detector.is_aws():
            self.logs_client = boto3.client("logs")
            self.log_group = "/aws/cybershield/application"
            self.log_stream = "security-analysis"
            self._ensure_log_group_exists()

    def _ensure_log_group_exists(self):
        """Create log group if it doesn't exist"""
        try:
            self.logs_client.create_log_group(logGroupName=self.log_group)
            logger.info(f"Created CloudWatch log group: {self.log_group}")
        except self.logs_client.exceptions.ResourceAlreadyExistsException:
            logger.debug(f"Log group already exists: {self.log_group}")
        except Exception as e:
            logger.error(f"Failed to create log group: {e}")

    def log_security_event(self, event_type: str, data: Dict[str, Any]):
        """Log security events to CloudWatch"""
        if not config.detector.is_aws():
            return

        try:
            log_entry = {
                "timestamp": int(time.time() * 1000),
                "message": json.dumps(
                    {
                        "event_type": event_type,
                        "data": data,
                        "environment": "aws",
                        "service": "cybershield",
                    }
                ),
            }

            self.logs_client.put_log_events(
                logGroupName=self.log_group,
                logStreamName=self.log_stream,
                logEvents=[log_entry],
            )

        except Exception as e:
            logger.error(f"Failed to log to CloudWatch: {e}")


# Global CloudWatch handler
cloudwatch_handler = CloudWatchHandler() if config.detector.is_aws() else None
