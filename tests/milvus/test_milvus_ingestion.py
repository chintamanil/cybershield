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
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from data.milvus_ingestion import (
    load_and_preprocess_data, create_embeddings, 
    setup_milvus_collection, insert_data_to_milvus
)


class TestMilvusIngestion(unittest.TestCase):
    """Test cases for Milvus data ingestion functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.sample_data = pd.DataFrame({
            'id': [1, 2, 3],
            'timestamp': ['2024-01-01 00:00:00', '2024-01-01 01:00:00', '2024-01-01 02:00:00'],
            'source_ip': ['192.168.1.100', '10.0.0.1', '172.16.0.1'],
            'dest_ip': ['8.8.8.8', '1.1.1.1', '208.67.222.222'],
            'protocol': ['TCP', 'UDP', 'TCP'],
            'attack_type': ['DDoS', 'Malware', 'Intrusion'],
            'severity_level': ['High', 'Medium', 'Low'],
            'full_context': [
                'DDoS attack detected from source IP',
                'Malware signature found in traffic',
                'Unauthorized access attempt detected'
            ]
        })
    
    def test_load_and_preprocess_data_success(self):
        """Test successful data loading and preprocessing"""
        # Create a temporary CSV file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp_file:
            self.sample_data.to_csv(tmp_file.name, index=False)
            tmp_filename = tmp_file.name
        
        try:
            # Test loading the data
            loaded_data = load_and_preprocess_data(tmp_filename)
            
            # Verify data was loaded correctly
            self.assertIsInstance(loaded_data, pd.DataFrame)
            self.assertEqual(len(loaded_data), 3)
            self.assertIn('full_context', loaded_data.columns)
            self.assertIn('attack_type', loaded_data.columns)
            
        finally:
            # Clean up
            os.unlink(tmp_filename)
    
    def test_load_and_preprocess_data_file_not_found(self):
        """Test data loading with non-existent file"""
        with self.assertRaises(FileNotFoundError):
            load_and_preprocess_data("non_existent_file.csv")
    
    def test_load_and_preprocess_data_missing_columns(self):
        """Test data loading with missing required columns"""
        # Create data missing required columns
        incomplete_data = pd.DataFrame({
            'id': [1, 2],
            'some_column': ['value1', 'value2']
        })
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp_file:
            incomplete_data.to_csv(tmp_file.name, index=False)
            tmp_filename = tmp_file.name
        
        try:
            with self.assertRaises(KeyError):
                load_and_preprocess_data(tmp_filename)
        finally:
            os.unlink(tmp_filename)
    
    @patch('sentence_transformers.SentenceTransformer')
    def test_create_embeddings_success(self, mock_sentence_transformer):
        """Test successful embedding creation"""
        # Mock the sentence transformer
        mock_model = Mock()
        mock_model.encode.return_value = [[0.1, 0.2, 0.3], [0.4, 0.5, 0.6], [0.7, 0.8, 0.9]]
        mock_sentence_transformer.return_value = mock_model
        
        texts = ["text1", "text2", "text3"]
        embeddings = create_embeddings(texts)
        
        # Verify embeddings were created
        self.assertEqual(len(embeddings), 3)
        self.assertEqual(len(embeddings[0]), 3)  # Each embedding has 3 dimensions
        mock_model.encode.assert_called_once_with(texts, show_progress_bar=True)
    
    @patch('sentence_transformers.SentenceTransformer')
    def test_create_embeddings_import_error(self, mock_sentence_transformer):
        """Test embedding creation when SentenceTransformer is not available"""
        mock_sentence_transformer.side_effect = ImportError("SentenceTransformer not available")
        
        texts = ["text1", "text2", "text3"]
        embeddings = create_embeddings(texts)
        
        # Should return fallback embeddings
        self.assertEqual(len(embeddings), 3)
        self.assertEqual(len(embeddings[0]), 384)  # Default embedding dimension
        
        # All embeddings should be the same fallback vector
        for embedding in embeddings:
            self.assertEqual(embedding, [0.1] * 384)
    
    @patch('data.milvus_ingestion.connections')
    @patch('data.milvus_ingestion.utility')
    @patch('data.milvus_ingestion.Collection')
    def test_setup_milvus_collection_new_collection(self, mock_collection_class, mock_utility, mock_connections):
        """Test setting up a new Milvus collection"""
        # Mock that collection doesn't exist
        mock_utility.has_collection.return_value = False
        
        # Mock collection creation
        mock_collection = Mock()
        mock_collection_class.return_value = mock_collection
        
        collection = setup_milvus_collection("test_collection")
        
        # Verify connection was established
        mock_connections.connect.assert_called_once()
        
        # Verify collection existence was checked
        mock_utility.has_collection.assert_called_once_with("test_collection")
        
        # Verify collection was created and loaded
        self.assertEqual(collection, mock_collection)
        mock_collection.load.assert_called_once()
    
    @patch('data.milvus_ingestion.connections')
    @patch('data.milvus_ingestion.utility')
    @patch('data.milvus_ingestion.Collection')
    def test_setup_milvus_collection_existing_collection(self, mock_collection_class, mock_utility, mock_connections):
        """Test setting up an existing Milvus collection"""
        # Mock that collection exists
        mock_utility.has_collection.return_value = True
        
        # Mock collection loading
        mock_collection = Mock()
        mock_collection_class.return_value = mock_collection
        
        collection = setup_milvus_collection("test_collection")
        
        # Verify collection was loaded but not created
        self.assertEqual(collection, mock_collection)
        mock_collection.load.assert_called_once()
    
    @patch('data.milvus_ingestion.connections')
    def test_setup_milvus_collection_connection_error(self, mock_connections):
        """Test collection setup with connection error"""
        mock_connections.connect.side_effect = Exception("Connection failed")
        
        with self.assertRaises(Exception) as context:
            setup_milvus_collection("test_collection")
        
        self.assertIn("Connection failed", str(context.exception))
    
    def test_insert_data_to_milvus_success(self):
        """Test successful data insertion to Milvus"""
        # Mock collection
        mock_collection = Mock()
        mock_collection.insert.return_value = Mock()
        
        # Sample data and embeddings
        data = self.sample_data
        embeddings = [[0.1, 0.2, 0.3]] * len(data)
        
        with patch('builtins.print'):  # Suppress print output
            insert_data_to_milvus(mock_collection, data, embeddings, batch_size=2)
        
        # Verify insert was called
        self.assertGreater(mock_collection.insert.call_count, 0)
        
        # Verify flush was called
        mock_collection.flush.assert_called_once()
    
    def test_insert_data_to_milvus_empty_data(self):
        """Test data insertion with empty data"""
        mock_collection = Mock()
        empty_data = pd.DataFrame()
        empty_embeddings = []
        
        with patch('builtins.print'):
            insert_data_to_milvus(mock_collection, empty_data, empty_embeddings)
        
        # Should not call insert with empty data
        mock_collection.insert.assert_not_called()
    
    def test_insert_data_to_milvus_mismatched_lengths(self):
        """Test data insertion with mismatched data and embeddings lengths"""
        mock_collection = Mock()
        data = self.sample_data
        mismatched_embeddings = [[0.1, 0.2, 0.3]]  # Only one embedding for 3 data rows
        
        with self.assertRaises(IndexError):
            insert_data_to_milvus(mock_collection, data, mismatched_embeddings)
    
    def test_insert_data_to_milvus_insertion_error(self):
        """Test data insertion with Milvus insertion error"""
        mock_collection = Mock()
        mock_collection.insert.side_effect = Exception("Insertion failed")
        
        data = self.sample_data
        embeddings = [[0.1, 0.2, 0.3]] * len(data)
        
        with self.assertRaises(Exception) as context:
            insert_data_to_milvus(mock_collection, data, embeddings)
        
        self.assertIn("Insertion failed", str(context.exception))


class TestMilvusIngestionIntegration(unittest.TestCase):
    """Integration tests for Milvus ingestion workflow"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.sample_data = pd.DataFrame({
            'id': [1, 2],
            'timestamp': ['2024-01-01 00:00:00', '2024-01-01 01:00:00'],
            'source_ip': ['192.168.1.100', '10.0.0.1'],
            'dest_ip': ['8.8.8.8', '1.1.1.1'],
            'source_port': [80, 443],
            'dest_port': [443, 80],
            'protocol': ['TCP', 'UDP'],
            'attack_type': ['DDoS', 'Malware'],
            'attack_signature': ['signature1', 'signature2'],
            'severity_level': ['High', 'Medium'],
            'action_taken': ['Blocked', 'Monitored'],
            'anomaly_score': [0.9, 0.7],
            'malware_indicators': ['indicator1', 'indicator2'],
            'geo_location': ['US', 'CA'],
            'user_info': ['user1', 'user2'],
            'log_source': ['firewall', 'ids'],
            'full_context': [
                'DDoS attack detected from source IP',
                'Malware signature found in traffic'
            ]
        })
    
    @patch('data.milvus_ingestion.connections')
    @patch('data.milvus_ingestion.utility')
    @patch('data.milvus_ingestion.Collection')
    @patch('sentence_transformers.SentenceTransformer')
    def test_full_ingestion_workflow(self, mock_sentence_transformer, mock_collection_class, 
                                   mock_utility, mock_connections):
        """Test the complete ingestion workflow"""
        # Create temporary CSV file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp_file:
            self.sample_data.to_csv(tmp_file.name, index=False)
            tmp_filename = tmp_file.name
        
        try:
            # Mock sentence transformer
            mock_model = Mock()
            mock_model.encode.return_value = [[0.1, 0.2, 0.3], [0.4, 0.5, 0.6]]
            mock_sentence_transformer.return_value = mock_model
            
            # Mock Milvus components
            mock_utility.has_collection.return_value = False
            mock_collection = Mock()
            mock_collection_class.return_value = mock_collection
            
            # Run the full workflow
            data = load_and_preprocess_data(tmp_filename)
            embeddings = create_embeddings(data['full_context'].tolist())
            collection = setup_milvus_collection("test_collection")
            
            with patch('builtins.print'):
                insert_data_to_milvus(collection, data, embeddings)
            
            # Verify workflow completed successfully
            self.assertEqual(len(data), 2)
            self.assertEqual(len(embeddings), 2)
            mock_collection.insert.assert_called()
            mock_collection.flush.assert_called_once()
            
        finally:
            os.unlink(tmp_filename)
    
    def test_data_validation_workflow(self):
        """Test data validation during the ingestion workflow"""
        # Create data with missing required fields
        invalid_data = pd.DataFrame({
            'id': [1, 2],
            'incomplete_field': ['value1', 'value2']
        })
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp_file:
            invalid_data.to_csv(tmp_file.name, index=False)
            tmp_filename = tmp_file.name
        
        try:
            # Should raise error for missing required columns
            with self.assertRaises(KeyError):
                load_and_preprocess_data(tmp_filename)
                
        finally:
            os.unlink(tmp_filename)
    
    @patch('data.milvus_ingestion.connections')
    @patch('data.milvus_ingestion.utility')
    def test_error_handling_workflow(self, mock_utility, mock_connections):
        """Test error handling throughout the ingestion workflow"""
        # Test connection error
        mock_connections.connect.side_effect = Exception("Connection failed")
        
        with self.assertRaises(Exception):
            setup_milvus_collection("test_collection")
        
        # Reset mock
        mock_connections.connect.side_effect = None
        
        # Test collection creation error
        mock_utility.has_collection.side_effect = Exception("Utility error")
        
        with self.assertRaises(Exception):
            setup_milvus_collection("test_collection")


class TestMilvusDataPreprocessing(unittest.TestCase):
    """Test cases for data preprocessing functionality"""
    
    def test_data_type_conversion(self):
        """Test that data types are properly converted during preprocessing"""
        # Create sample data with mixed types
        sample_data = pd.DataFrame({
            'id': ['1', '2', '3'],  # String IDs
            'timestamp': ['2024-01-01 00:00:00', '2024-01-01 01:00:00', '2024-01-01 02:00:00'],
            'source_ip': ['192.168.1.100', '10.0.0.1', '172.16.0.1'],
            'dest_ip': ['8.8.8.8', '1.1.1.1', '208.67.222.222'],
            'protocol': ['TCP', 'UDP', 'TCP'],
            'attack_type': ['DDoS', 'Malware', 'Intrusion'],
            'severity_level': ['High', 'Medium', 'Low'],
            'full_context': [
                'DDoS attack detected from source IP',
                'Malware signature found in traffic',
                'Unauthorized access attempt detected'
            ]
        })
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp_file:
            sample_data.to_csv(tmp_file.name, index=False)
            tmp_filename = tmp_file.name
        
        try:
            loaded_data = load_and_preprocess_data(tmp_filename)
            
            # Verify data was loaded and types are appropriate
            self.assertIsInstance(loaded_data, pd.DataFrame)
            self.assertEqual(len(loaded_data), 3)
            
            # Check that required columns exist
            required_columns = ['full_context', 'attack_type', 'source_ip', 'dest_ip']
            for col in required_columns:
                self.assertIn(col, loaded_data.columns)
                
        finally:
            os.unlink(tmp_filename)


if __name__ == "__main__":
    unittest.main(verbosity=2)