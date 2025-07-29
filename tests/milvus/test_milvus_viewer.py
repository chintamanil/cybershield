#!/usr/bin/env python3
"""
Tests for Milvus data viewers
"""

import unittest
import sys
import os
from unittest.mock import Mock, patch

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from data.milivus_view.view_milvus_data import MilvusDataViewer
from data.milivus_view.interactive_milvus_viewer import InteractiveMilvusViewer


class TestMilvusDataViewer(unittest.TestCase):
    """Test cases for MilvusDataViewer class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.viewer = MilvusDataViewer("test_collection")
    
    @patch('data.milivus_view.view_milvus_data.connections')
    def test_connect_success(self, mock_connections):
        """Test successful connection to Milvus"""
        mock_connections.connect.return_value = None
        
        result = self.viewer.connect()
        
        self.assertTrue(result)
        mock_connections.connect.assert_called_once_with("default", host="localhost", port="19530")
    
    @patch('data.milivus_view.view_milvus_data.connections')
    def test_connect_failure(self, mock_connections):
        """Test failed connection to Milvus"""
        mock_connections.connect.side_effect = Exception("Connection failed")
        
        result = self.viewer.connect()
        
        self.assertFalse(result)
    
    @patch('data.milivus_view.view_milvus_data.PYMILVUS_AVAILABLE', False)
    def test_connect_no_pymilvus(self):
        """Test connection when pymilvus is not available"""
        result = self.viewer.connect()
        
        self.assertFalse(result)
    
    @patch('data.milivus_view.view_milvus_data.utility')
    @patch('data.milivus_view.view_milvus_data.Collection')
    def test_load_collection_success(self, mock_collection_class, mock_utility):
        """Test successful collection loading"""
        mock_utility.has_collection.return_value = True
        mock_collection = Mock()
        mock_collection_class.return_value = mock_collection
        
        result = self.viewer.load_collection()
        
        self.assertTrue(result)
        self.assertEqual(self.viewer.collection, mock_collection)
        mock_collection.load.assert_called_once()
    
    @patch('data.milivus_view.view_milvus_data.utility')
    def test_load_collection_not_found(self, mock_utility):
        """Test collection loading when collection doesn't exist"""
        mock_utility.has_collection.return_value = False
        
        result = self.viewer.load_collection()
        
        self.assertFalse(result)
        self.assertIsNone(self.viewer.collection)
    
    def test_get_collection_stats_no_collection(self):
        """Test getting stats when no collection is loaded"""
        with patch('builtins.print') as mock_print:
            self.viewer.get_collection_stats()
            mock_print.assert_called_with("❌ Collection not loaded")
    
    def test_get_collection_stats_success(self):
        """Test getting collection statistics"""
        mock_collection = Mock()
        mock_collection.get_statistics.return_value = {"row_count": 1000}
        
        # Mock schema
        mock_field = Mock()
        mock_field.name = "test_field"
        mock_field.dtype = "VARCHAR"
        mock_field.is_primary = False
        
        mock_schema = Mock()
        mock_schema.fields = [mock_field]
        mock_collection.schema = mock_schema
        
        self.viewer.collection = mock_collection
        
        with patch('builtins.print') as mock_print:
            self.viewer.get_collection_stats()
            # Verify print was called with statistics
            mock_print.assert_any_call("\n📊 Collection Statistics:")
    
    def test_query_sample_data_no_collection(self):
        """Test querying data when no collection is loaded"""
        with patch('builtins.print') as mock_print:
            self.viewer.query_sample_data()
            mock_print.assert_called_with("❌ Collection not loaded")
    
    def test_query_sample_data_success(self):
        """Test successful sample data querying"""
        mock_collection = Mock()
        sample_data = [
            {
                "id": 1,
                "timestamp": "2024-01-01T00:00:00Z",
                "source_ip": "192.168.1.100",
                "dest_ip": "10.0.0.1",
                "source_port": 80,
                "dest_port": 443,
                "protocol": "TCP",
                "attack_type": "DDoS",
                "attack_signature": "Test signature",
                "severity_level": "High",
                "action_taken": "Blocked",
                "anomaly_score": 0.9,
                "malware_indicators": "None",
                "geo_location": "US",
                "user_info": "anonymous",
                "log_source": "firewall",
                "full_context": "Test attack context"
            }
        ]
        
        mock_collection.query.return_value = sample_data
        self.viewer.collection = mock_collection
        
        with patch('builtins.print'):
            self.viewer.query_sample_data(limit=1)
            
        mock_collection.query.assert_called_once()
    
    def test_query_sample_data_no_results(self):
        """Test sample data querying with no results"""
        mock_collection = Mock()
        mock_collection.query.return_value = []
        self.viewer.collection = mock_collection
        
        with patch('builtins.print') as mock_print:
            self.viewer.query_sample_data()
            mock_print.assert_any_call("❌ No results found")
    
    def test_search_similar_no_collection(self):
        """Test similarity search when no collection is loaded"""
        with patch('builtins.print') as mock_print:
            self.viewer.search_similar("test query")
            mock_print.assert_called_with("❌ Collection not loaded")
    
    def test_search_similar_success(self):
        """Test successful similarity search"""
        mock_collection = Mock()
        search_results = [
            {
                "id": 1,
                "timestamp": "2024-01-01T00:00:00Z",
                "attack_type": "DDoS",
                "severity_level": "High",
                "source_ip": "192.168.1.100",
                "dest_ip": "10.0.0.1",
                "full_context": "DDoS attack detected from source"
            }
        ]
        
        mock_collection.query.return_value = search_results
        self.viewer.collection = mock_collection
        
        with patch('builtins.print'):
            self.viewer.search_similar("DDoS attack")
            
        mock_collection.query.assert_called_once()
    
    def test_export_to_csv_no_collection(self):
        """Test CSV export when no collection is loaded"""
        with patch('builtins.print') as mock_print:
            self.viewer.export_to_csv()
            mock_print.assert_called_with("❌ Collection not loaded")
    
    @patch('pandas.DataFrame.to_csv')
    def test_export_to_csv_success(self, mock_to_csv):
        """Test successful CSV export"""
        mock_collection = Mock()
        export_data = [
            {
                "id": 1,
                "timestamp": "2024-01-01T00:00:00Z",
                "source_ip": "192.168.1.100",
                "dest_ip": "10.0.0.1",
                "source_port": 80,
                "dest_port": 443,
                "protocol": "TCP",
                "attack_type": "DDoS",
                "attack_signature": "Test signature",
                "severity_level": "High",
                "action_taken": "Blocked",
                "anomaly_score": 0.9,
                "malware_indicators": "None",
                "geo_location": "US",
                "user_info": "anonymous",
                "log_source": "firewall",
                "full_context": "Test attack context"
            }
        ]
        
        mock_collection.query.return_value = export_data
        self.viewer.collection = mock_collection
        
        with patch('builtins.print'):
            self.viewer.export_to_csv("test_export.csv", limit=1)
            
        mock_to_csv.assert_called_once_with("test_export.csv", index=False)
    
    def test_export_to_csv_no_data(self):
        """Test CSV export with no data"""
        mock_collection = Mock()
        mock_collection.query.return_value = []
        self.viewer.collection = mock_collection
        
        with patch('builtins.print') as mock_print:
            self.viewer.export_to_csv()
            mock_print.assert_any_call("❌ No data to export")


class TestInteractiveMilvusViewer(unittest.TestCase):
    """Test cases for InteractiveMilvusViewer class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.viewer = InteractiveMilvusViewer("test_collection")
    
    @patch('data.milivus_view.interactive_milvus_viewer.connections')
    def test_connect_success(self, mock_connections):
        """Test successful connection to Milvus"""
        mock_connections.connect.return_value = None
        
        result = self.viewer.connect()
        
        self.assertTrue(result)
        mock_connections.connect.assert_called_once_with("default", host="localhost", port="19530")
    
    @patch('data.milivus_view.interactive_milvus_viewer.connections')
    def test_connect_failure(self, mock_connections):
        """Test failed connection to Milvus"""
        mock_connections.connect.side_effect = Exception("Connection failed")
        
        result = self.viewer.connect()
        
        self.assertFalse(result)
    
    @patch('data.milivus_view.interactive_milvus_viewer.utility')
    @patch('data.milivus_view.interactive_milvus_viewer.Collection')
    def test_load_collection_success(self, mock_collection_class, mock_utility):
        """Test successful collection loading"""
        mock_utility.has_collection.return_value = True
        mock_collection = Mock()
        mock_collection_class.return_value = mock_collection
        
        result = self.viewer.load_collection()
        
        self.assertTrue(result)
        self.assertEqual(self.viewer.collection, mock_collection)
        mock_collection.load.assert_called_once()
    
    def test_get_total_count_success(self):
        """Test getting total record count"""
        mock_collection = Mock()
        mock_collection.query.side_effect = [
            [{"id": 1}],  # First call for limit=1
            [{"id": 1}, {"id": 2}, {"id": 3}]  # Second call for all IDs
        ]
        self.viewer.collection = mock_collection
        
        count = self.viewer.get_total_count()
        
        self.assertEqual(count, 3)
        self.assertEqual(mock_collection.query.call_count, 2)
    
    def test_get_total_count_error(self):
        """Test getting total count with error"""
        mock_collection = Mock()
        mock_collection.query.side_effect = Exception("Query failed")
        self.viewer.collection = mock_collection
        
        count = self.viewer.get_total_count()
        
        self.assertEqual(count, 0)
    
    def test_query_by_attack_type_success(self):
        """Test querying by attack type"""
        mock_collection = Mock()
        attack_data = [
            {
                "id": 1,
                "timestamp": "2024-01-01T00:00:00Z",
                "source_ip": "192.168.1.100",
                "dest_ip": "10.0.0.1",
                "protocol": "TCP",
                "attack_type": "DDoS",
                "severity_level": "High",
                "full_context": "DDoS attack detected"
            }
        ]
        
        mock_collection.query.return_value = attack_data
        self.viewer.collection = mock_collection
        
        results = self.viewer.query_by_attack_type("DDoS", limit=10)
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["attack_type"], "DDoS")
        mock_collection.query.assert_called_once()
    
    def test_query_by_severity_success(self):
        """Test querying by severity level"""
        mock_collection = Mock()
        severity_data = [
            {
                "id": 1,
                "timestamp": "2024-01-01T00:00:00Z",
                "source_ip": "192.168.1.100",
                "dest_ip": "10.0.0.1",
                "protocol": "TCP",
                "attack_type": "DDoS",
                "severity_level": "High",
                "full_context": "High severity attack"
            }
        ]
        
        mock_collection.query.return_value = severity_data
        self.viewer.collection = mock_collection
        
        results = self.viewer.query_by_severity("High", limit=10)
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["severity_level"], "High")
    
    def test_query_by_protocol_success(self):
        """Test querying by protocol"""
        mock_collection = Mock()
        protocol_data = [
            {
                "id": 1,
                "timestamp": "2024-01-01T00:00:00Z",
                "source_ip": "192.168.1.100",
                "dest_ip": "10.0.0.1",
                "protocol": "TCP",
                "attack_type": "DDoS",
                "severity_level": "High",
                "full_context": "TCP protocol attack"
            }
        ]
        
        mock_collection.query.return_value = protocol_data
        self.viewer.collection = mock_collection
        
        results = self.viewer.query_by_protocol("TCP", limit=10)
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["protocol"], "TCP")
    
    def test_query_by_ip_success(self):
        """Test querying by IP address"""
        mock_collection = Mock()
        ip_data = [
            {
                "id": 1,
                "timestamp": "2024-01-01T00:00:00Z",
                "source_ip": "192.168.1.100",
                "dest_ip": "10.0.0.1",
                "protocol": "TCP",
                "attack_type": "DDoS",
                "severity_level": "High",
                "full_context": "Attack from IP address"
            }
        ]
        
        mock_collection.query.return_value = ip_data
        self.viewer.collection = mock_collection
        
        results = self.viewer.query_by_ip("192.168.1.100", limit=10)
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["source_ip"], "192.168.1.100")
    
    def test_get_attack_type_stats_success(self):
        """Test getting attack type statistics"""
        mock_collection = Mock()
        stats_data = [
            {"attack_type": "DDoS"},
            {"attack_type": "DDoS"},
            {"attack_type": "Malware"},
            {"attack_type": "Intrusion"}
        ]
        
        mock_collection.query.return_value = stats_data
        self.viewer.collection = mock_collection
        
        with patch('pandas.DataFrame') as mock_df:
            mock_df.return_value.value_counts.return_value.to_dict.return_value = {
                "DDoS": 2,
                "Malware": 1,
                "Intrusion": 1
            }
            
            stats = self.viewer.get_attack_type_stats()
            
            self.assertEqual(stats["DDoS"], 2)
            self.assertEqual(stats["Malware"], 1)
    
    def test_get_severity_stats_success(self):
        """Test getting severity level statistics"""
        mock_collection = Mock()
        severity_data = [
            {"severity_level": "High"},
            {"severity_level": "High"},
            {"severity_level": "Medium"},
            {"severity_level": "Low"}
        ]
        
        mock_collection.query.return_value = severity_data
        self.viewer.collection = mock_collection
        
        with patch('pandas.DataFrame') as mock_df:
            mock_df.return_value.value_counts.return_value.to_dict.return_value = {
                "High": 2,
                "Medium": 1,
                "Low": 1
            }
            
            stats = self.viewer.get_severity_stats()
            
            self.assertEqual(stats["High"], 2)
            self.assertEqual(stats["Medium"], 1)
    
    def test_display_results_no_results(self):
        """Test displaying results when no data found"""
        with patch('builtins.print') as mock_print:
            self.viewer.display_results([], "Test Query")
            mock_print.assert_called_with("❌ No results found for Test Query")
    
    def test_display_results_with_data(self):
        """Test displaying results with data"""
        results = [
            {
                "id": 1,
                "timestamp": "2024-01-01T00:00:00Z",
                "source_ip": "192.168.1.100",
                "dest_ip": "10.0.0.1",
                "protocol": "TCP",
                "attack_type": "DDoS",
                "severity_level": "High",
                "full_context": "DDoS attack detected from source IP"
            }
        ]
        
        with patch('builtins.print') as mock_print:
            self.viewer.display_results(results, "Test Query")
            mock_print.assert_any_call("\n📋 Test Query (1 records):")
    
    def test_query_error_handling(self):
        """Test error handling in query methods"""
        mock_collection = Mock()
        mock_collection.query.side_effect = Exception("Query error")
        self.viewer.collection = mock_collection
        
        # Test all query methods handle errors gracefully
        self.assertEqual(self.viewer.query_by_attack_type("DDoS"), [])
        self.assertEqual(self.viewer.query_by_severity("High"), [])
        self.assertEqual(self.viewer.query_by_protocol("TCP"), [])
        self.assertEqual(self.viewer.query_by_ip("192.168.1.100"), [])
        self.assertEqual(self.viewer.get_attack_type_stats(), {})
        self.assertEqual(self.viewer.get_severity_stats(), {})


class TestMilvusIntegration(unittest.TestCase):
    """Integration tests for Milvus components"""
    
    @patch('data.milivus_view.view_milvus_data.connections')
    @patch('data.milivus_view.view_milvus_data.utility')
    @patch('data.milivus_view.view_milvus_data.Collection')
    def test_full_workflow_data_viewer(self, mock_collection_class, mock_utility, mock_connections):
        """Test full workflow for MilvusDataViewer"""
        # Mock successful connection
        mock_connections.connect.return_value = None
        
        # Mock collection exists and loads successfully
        mock_utility.has_collection.return_value = True
        mock_collection = Mock()
        mock_collection_class.return_value = mock_collection
        
        # Mock data for queries
        mock_collection.get_statistics.return_value = {"row_count": 1000}
        mock_collection.query.return_value = [
            {
                "id": 1,
                "timestamp": "2024-01-01T00:00:00Z",
                "source_ip": "192.168.1.100",
                "dest_ip": "10.0.0.1",
                "source_port": 80,
                "dest_port": 443,
                "protocol": "TCP",
                "attack_type": "DDoS",
                "attack_signature": "Test signature",
                "severity_level": "High",
                "action_taken": "Blocked",
                "anomaly_score": 0.9,
                "malware_indicators": "None",
                "geo_location": "US",
                "user_info": "anonymous",
                "log_source": "firewall",
                "full_context": "Test attack context"
            }
        ]
        
        # Mock schema
        mock_field = Mock()
        mock_field.name = "test_field"
        mock_field.dtype = "VARCHAR"
        mock_field.is_primary = False
        mock_schema = Mock()
        mock_schema.fields = [mock_field]
        mock_collection.schema = mock_schema
        
        viewer = MilvusDataViewer()
        
        # Test full workflow
        self.assertTrue(viewer.connect())
        self.assertTrue(viewer.load_collection())
        
        with patch('builtins.print'):
            viewer.get_collection_stats()
            viewer.query_sample_data(limit=1)
            viewer.search_similar("test", limit=1)
        
        with patch('pandas.DataFrame.to_csv'):
            viewer.export_to_csv("test.csv", limit=1)
    
    @patch('data.milivus_view.interactive_milvus_viewer.connections')
    @patch('data.milivus_view.interactive_milvus_viewer.utility')
    @patch('data.milivus_view.interactive_milvus_viewer.Collection')
    def test_full_workflow_interactive_viewer(self, mock_collection_class, mock_utility, mock_connections):
        """Test full workflow for InteractiveMilvusViewer"""
        # Mock successful connection
        mock_connections.connect.return_value = None
        
        # Mock collection exists and loads successfully
        mock_utility.has_collection.return_value = True
        mock_collection = Mock()
        mock_collection_class.return_value = mock_collection
        
        # Mock data for queries
        mock_collection.query.side_effect = [
            [{"id": 1}],  # For get_total_count first call
            [{"id": 1}, {"id": 2}],  # For get_total_count second call
            [{"attack_type": "DDoS"}],  # For attack type stats
            [{"severity_level": "High"}]  # For severity stats
        ]
        
        viewer = InteractiveMilvusViewer()
        
        # Test full workflow
        self.assertTrue(viewer.connect())
        self.assertTrue(viewer.load_collection())
        self.assertEqual(viewer.get_total_count(), 2)
        
        with patch('pandas.DataFrame') as mock_df:
            mock_df.return_value.value_counts.return_value.to_dict.return_value = {"DDoS": 1}
            stats = viewer.get_attack_type_stats()
            self.assertEqual(stats["DDoS"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)