"""
Pytest configuration and fixtures for CDK tests.
"""

import os

import pytest


@pytest.fixture(autouse=True)
def set_test_environment() -> None:
    """Set environment variables for testing."""
    os.environ["AWS_ACCOUNT_ID"] = "123456789012"
    os.environ["AWS_REGION"] = "us-east-1"
    os.environ["ENVIRONMENT"] = "dev"
