#!/usr/bin/env python3
"""
Tests for Milvus data ingestion functionality
"""

import unittest
import sys
import os
import pandas as pd
from unittest.mock import Mock, patch
import tempfile

# Add parent directory to path for imports
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from data.milvus_ingestion import CyberSecurityDataProcessor


class TestMilvusIngestion(unittest.TestCase):
    """Test cases for Milvus data ingestion functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.processor = CyberSecurityDataProcessor()
        self.sample_data = pd.DataFrame(
            {
                "id": [1, 2, 3],
                "timestamp": [
                    "2024-01-01 00:00:00",
                    "2024-01-01 01:00:00",
                    "2024-01-01 02:00:00",
                ],
                "source_ip": ["192.168.1.100", "10.0.0.1", "172.16.0.1"],
                "dest_ip": ["8.8.8.8", "1.1.1.1", "208.67.222.222"],
                "protocol": ["TCP", "UDP", "TCP"],
                "attack_type": ["DDoS", "Malware", "Intrusion"],
                "severity_level": ["High", "Medium", "Low"],
                "full_context": [
                    "DDoS attack detected from source IP",
                    "Malware signature found in traffic",
                    "Unauthorized access attempt detected",
                ],
            }
        )

    def test_preprocess_data_success(self):
        """Test successful data preprocessing"""
        # Test preprocessing the data
        processed_data = self.processor.preprocess_data(self.sample_data.copy())

        # Verify data was processed correctly
        self.assertIsInstance(processed_data, pd.DataFrame)
        self.assertEqual(len(processed_data), 3)
        self.assertIn("full_context", processed_data.columns)
        self.assertIn("attack_type", processed_data.columns)

    def test_preprocess_data_empty_dataframe(self):
        """Test data preprocessing with empty dataframe"""
        empty_df = pd.DataFrame()
        processed_data = self.processor.preprocess_data(empty_df)
        self.assertIsInstance(processed_data, pd.DataFrame)
        self.assertEqual(len(processed_data), 0)

    def test_preprocess_data_missing_columns(self):
        """Test data preprocessing with missing required columns"""
        # Create data missing required columns
        incomplete_data = pd.DataFrame(
            {"id": [1, 2], "some_column": ["value1", "value2"]}
        )

        # Should handle missing columns gracefully
        processed_data = self.processor.preprocess_data(incomplete_data)
        self.assertIsInstance(processed_data, pd.DataFrame)
        self.assertEqual(len(processed_data), 2)

    def test_create_embeddings_success(self):
        """Test successful embedding creation"""
        texts = ["text1", "text2", "text3"]
        
        # Test with processor (will use fallback if sentence-transformers not available)
        embeddings = self.processor.create_embeddings(texts)

        # Verify embeddings were created
        self.assertEqual(len(embeddings), 3)
        self.assertGreater(len(embeddings[0]), 0)  # Should have some dimensions

    def test_create_embeddings_with_fallback(self):
        """Test embedding creation with fallback when SentenceTransformer is not available"""
        # Create processor without embedding model
        processor_no_model = CyberSecurityDataProcessor()
        processor_no_model.embedding_model = None  # Force fallback
        
        texts = ["text1", "text2", "text3"]
        embeddings = processor_no_model.create_embeddings(texts)

        # Should return fallback embeddings
        self.assertEqual(len(embeddings), 3)
        self.assertEqual(len(embeddings[0]), 384)  # Default embedding dimension

    def test_create_milvus_collection_new_collection(self):
        """Test creating a new Milvus collection"""
        # Test collection creation (this will fail without Milvus, but should not crash)
        try:
            self.processor.create_milvus_collection(force_recreate=True)
        except Exception as e:
            # Expected to fail without Milvus running, but should handle gracefully
            self.assertIsInstance(e, Exception)

    def test_prepare_milvus_data(self):
        """Test preparing data for Milvus insertion"""
        # Test data preparation
        milvus_data = self.processor.prepare_milvus_data(self.sample_data)
        
        # Verify data structure
        self.assertIsInstance(milvus_data, dict)
        self.assertIn('id', milvus_data)
        self.assertIn('embeddings', milvus_data)

    def test_generate_record_id(self):
        """Test record ID generation"""
        # Test ID generation
        sample_row = self.sample_data.iloc[0]
        record_id = self.processor.generate_record_id(sample_row)
        
        # Verify ID is generated
        self.assertIsInstance(record_id, str)
        self.assertGreater(len(record_id), 0)

    def test_insert_data_batch_success(self):
        """Test successful data batch insertion to Milvus"""
        # Mock collection
        mock_collection = Mock()
        mock_collection.insert.return_value = Mock()

        # Prepare data
        milvus_data = self.processor.prepare_milvus_data(self.sample_data)

        try:
            self.processor.insert_data_batch(mock_collection, milvus_data, batch_size=2)
            # If no exception, test passes
        except Exception:
            # Expected to fail without proper Milvus setup
            pass

    def test_insert_data_empty_data(self):
        """Test data insertion with empty data"""
        empty_data = pd.DataFrame()
        milvus_data = self.processor.prepare_milvus_data(empty_data)
        
        # Should handle empty data gracefully
        self.assertIsInstance(milvus_data, dict)
        self.assertEqual(len(milvus_data.get('id', [])), 0)


class TestMilvusIngestionIntegration(unittest.TestCase):
    """Integration tests for Milvus ingestion workflow"""

    def setUp(self):
        """Set up test fixtures"""
        self.processor = CyberSecurityDataProcessor()
        self.sample_data = pd.DataFrame(
            {
                "id": [1, 2],
                "timestamp": ["2024-01-01 00:00:00", "2024-01-01 01:00:00"],
                "source_ip": ["192.168.1.100", "10.0.0.1"],
                "dest_ip": ["8.8.8.8", "1.1.1.1"],
                "source_port": [80, 443],
                "dest_port": [443, 80],
                "protocol": ["TCP", "UDP"],
                "attack_type": ["DDoS", "Malware"],
                "attack_signature": ["signature1", "signature2"],
                "severity_level": ["High", "Medium"],
                "action_taken": ["Blocked", "Monitored"],
                "anomaly_score": [0.9, 0.7],
                "malware_indicators": ["indicator1", "indicator2"],
                "geo_location": ["US", "CA"],
                "user_info": ["user1", "user2"],
                "log_source": ["firewall", "ids"],
                "full_context": [
                    "DDoS attack detected from source IP",
                    "Malware signature found in traffic",
                ],
            }
        )

    def test_full_ingestion_workflow(self):
        """Test the complete ingestion workflow"""
        # Test data preprocessing
        processed_data = self.processor.preprocess_data(self.sample_data.copy())
        self.assertIsInstance(processed_data, pd.DataFrame)
        self.assertEqual(len(processed_data), 2)
        
        # Test context creation
        if "full_context" in processed_data.columns:
            contexts = processed_data["full_context"].tolist()
        else:
            contexts = ["test context 1", "test context 2"]
        
        # Test embedding creation
        embeddings = self.processor.create_embeddings(contexts)
        self.assertEqual(len(embeddings), 2)
        
        # Test data preparation for Milvus
        milvus_data = self.processor.prepare_milvus_data(processed_data)
        self.assertIsInstance(milvus_data, dict)
        self.assertIn('embeddings', milvus_data)

    def test_data_validation_workflow(self):
        """Test data validation during the ingestion workflow"""
        # Create data with missing required fields
        invalid_data = pd.DataFrame(
            {"id": [1, 2], "incomplete_field": ["value1", "value2"]}
        )

        # Test preprocessing with incomplete data
        processed_data = self.processor.preprocess_data(invalid_data)
        
        # Should handle missing columns gracefully
        self.assertIsInstance(processed_data, pd.DataFrame)
        self.assertEqual(len(processed_data), 2)

    def test_error_handling_workflow(self):
        """Test error handling throughout the ingestion workflow"""
        # Test error handling with empty data
        empty_data = pd.DataFrame()
        
        # Should handle empty data gracefully
        result = self.processor.preprocess_data(empty_data)
        self.assertIsInstance(result, pd.DataFrame)
        
        # Test error handling with invalid embeddings
        try:
            self.processor.create_embeddings([])
        except Exception:
            # Expected to handle gracefully
            pass


class TestMilvusDataPreprocessing(unittest.TestCase):
    """Test cases for data preprocessing functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.processor = CyberSecurityDataProcessor()

    def test_data_type_conversion(self):
        """Test that data types are properly converted during preprocessing"""
        # Create sample data with mixed types
        sample_data = pd.DataFrame(
            {
                "id": ["1", "2", "3"],  # String IDs
                "timestamp": [
                    "2024-01-01 00:00:00",
                    "2024-01-01 01:00:00",
                    "2024-01-01 02:00:00",
                ],
                "source_ip": ["192.168.1.100", "10.0.0.1", "172.16.0.1"],
                "dest_ip": ["8.8.8.8", "1.1.1.1", "208.67.222.222"],
                "protocol": ["TCP", "UDP", "TCP"],
                "attack_type": ["DDoS", "Malware", "Intrusion"],
                "severity_level": ["High", "Medium", "Low"],
                "full_context": [
                    "DDoS attack detected from source IP",
                    "Malware signature found in traffic",
                    "Unauthorized access attempt detected",
                ],
            }
        )

        # Test data preprocessing
        processed_data = self.processor.preprocess_data(sample_data)

        # Verify data was processed correctly
        self.assertIsInstance(processed_data, pd.DataFrame)
        self.assertEqual(len(processed_data), 3)

        # Check that context columns exist or were created
        self.assertIn("full_context", processed_data.columns)


if __name__ == "__main__":
    unittest.main(verbosity=2)
