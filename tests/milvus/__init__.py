"""
Milvus tests package for CyberShield

This package contains comprehensive tests for all Milvus-related functionality:
- Milvus data viewers (interactive and programmatic)
- Milvus client initialization and connection
- Milvus data ingestion and preprocessing
- Integration tests for complete workflows

Test modules:
- test_milvus_viewer.py: Tests for data viewing functionality
- test_milvus_client.py: Tests for Milvus client operations
- test_milvus_ingestion.py: Tests for data ingestion pipeline
- test_runner.py: Comprehensive test runner for all Milvus tests

Usage:
    # Run all Milvus tests
    python tests/milvus/test_runner.py
    
    # Run specific test category
    python tests/milvus/test_runner.py viewer
    python tests/milvus/test_runner.py client
    python tests/milvus/test_runner.py ingestion
    
    # Run individual test files
    python -m unittest tests.milvus.test_milvus_viewer
    python -m unittest tests.milvus.test_milvus_client
    python -m unittest tests.milvus.test_milvus_ingestion
"""

__version__ = "1.0.0"
__author__ = "CyberShield Team"

# Import main test classes for easier access
from .test_milvus_viewer import TestMilvusDataViewer, TestInteractiveMilvusViewer
from .test_milvus_client import TestMilvusClient, TestMilvusDataTypes
from .test_milvus_ingestion import TestMilvusIngestion, TestMilvusIngestionIntegration

__all__ = [
    'TestMilvusDataViewer',
    'TestInteractiveMilvusViewer', 
    'TestMilvusClient',
    'TestMilvusDataTypes',
    'TestMilvusIngestion',
    'TestMilvusIngestionIntegration'
]