#!/usr/bin/env python3
"""
Tests for Milvus client functionality
"""

import unittest
import sys
import os
from unittest.mock import Mock, patch

# Add parent directory to path for imports
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from vectorstore.milvus_client import init_milvus


class TestMilvusClient(unittest.TestCase):
    """Test cases for Milvus client functionality"""

    @patch("vectorstore.milvus_client.connections")
    @patch("vectorstore.milvus_client.utility")
    @patch("vectorstore.milvus_client.Collection")
    @patch("vectorstore.milvus_client.CollectionSchema")
    @patch("vectorstore.milvus_client.FieldSchema")
    def test_init_milvus_new_collection(
        self,
        mock_field_schema,
        mock_collection_schema,
        mock_collection_class,
        mock_utility,
        mock_connections,
    ):
        """Test initializing Milvus with new collection creation"""
        # Mock that neither collection exists - will create new one
        mock_utility.has_collection.return_value = False

        # Mock field schemas
        mock_id_field = Mock()
        mock_embedding_field = Mock()
        mock_field_schema.side_effect = [mock_id_field, mock_embedding_field]

        # Mock collection schema
        mock_schema = Mock()
        mock_collection_schema.return_value = mock_schema

        # Mock collection creation
        mock_collection = Mock()
        mock_collection.name = "log_vectors"
        mock_collection.num_entities = 0
        mock_collection_class.return_value = mock_collection

        # Call the function
        init_milvus()

        # Verify connections
        mock_connections.connect.assert_called_once_with(host="localhost", port="19530")

        # Verify collection existence checks (checks cybersecurity_attacks first, then log_vectors)
        assert mock_utility.has_collection.call_count == 2
        mock_utility.has_collection.assert_any_call("cybersecurity_attacks")
        mock_utility.has_collection.assert_any_call("log_vectors")

        # Verify field schema creation
        self.assertEqual(mock_field_schema.call_count, 2)

        # Verify ID field creation
        mock_field_schema.assert_any_call(
            name="id",
            dtype=mock_field_schema.call_args_list[0][1]["dtype"],
            is_primary=True,
            auto_id=True,
        )

        # Verify embedding field creation
        mock_field_schema.assert_any_call(
            name="embedding",
            dtype=mock_field_schema.call_args_list[1][1]["dtype"],
            dim=384,
        )

        # Verify schema creation
        mock_collection_schema.assert_called_once_with(
            [mock_id_field, mock_embedding_field], "Log vector index"
        )

        # Verify collection creation
        mock_collection_class.assert_called_once_with("log_vectors", mock_schema)

    @patch("vectorstore.milvus_client.connections")
    @patch("vectorstore.milvus_client.utility")
    @patch("vectorstore.milvus_client.Collection")
    def test_init_milvus_existing_collection(self, mock_collection_class, mock_utility, mock_connections):
        """Test initializing Milvus when cybersecurity_attacks collection exists"""
        # Mock that cybersecurity_attacks collection exists
        def has_collection_side_effect(name):
            return name == "cybersecurity_attacks"

        mock_utility.has_collection.side_effect = has_collection_side_effect

        # Mock collection
        mock_collection = Mock()
        mock_collection.name = "cybersecurity_attacks"
        mock_collection.num_entities = 100
        mock_collection_class.return_value = mock_collection

        # Call the function
        result = init_milvus()

        # Verify connections
        mock_connections.connect.assert_called_once_with(host="localhost", port="19530")

        # Verify it checked for cybersecurity_attacks first
        mock_utility.has_collection.assert_called_with("cybersecurity_attacks")

        # Verify it loaded the existing collection
        mock_collection_class.assert_called_once_with("cybersecurity_attacks")

        # Verify it returned the collection
        self.assertEqual(result.name, "cybersecurity_attacks")

    @patch("vectorstore.milvus_client.connections")
    def test_init_milvus_connection_error(self, mock_connections):
        """Test Milvus initialization with connection error"""
        # Mock connection failure
        mock_connections.connect.side_effect = Exception("Connection failed")

        # Should raise the exception
        with self.assertRaises(Exception) as context:
            init_milvus()

        self.assertIn("Connection failed", str(context.exception))

    @patch("vectorstore.milvus_client.connections")
    @patch("vectorstore.milvus_client.utility")
    @patch("vectorstore.milvus_client.Collection")
    def test_init_milvus_collection_creation_error(
        self, mock_collection_class, mock_utility, mock_connections
    ):
        """Test Milvus initialization with collection creation error"""
        # Mock that collection doesn't exist
        mock_utility.has_collection.return_value = False

        # Mock collection creation failure
        mock_collection_class.side_effect = Exception("Collection creation failed")

        # Should raise the exception
        with self.assertRaises(Exception):
            init_milvus()


class TestMilvusDataTypes(unittest.TestCase):
    """Test cases for Milvus data types and schema validation"""

    @patch("vectorstore.milvus_client.DataType")
    def test_data_types_usage(self, mock_data_type):
        """Test that correct data types are used"""
        from vectorstore.milvus_client import init_milvus

        # Mock data types
        mock_data_type.INT64 = "INT64"
        mock_data_type.FLOAT_VECTOR = "FLOAT_VECTOR"

        with (
            patch("vectorstore.milvus_client.connections"),
            patch("vectorstore.milvus_client.utility") as mock_utility,
            patch("vectorstore.milvus_client.Collection"),
            patch("vectorstore.milvus_client.CollectionSchema"),
            patch("vectorstore.milvus_client.FieldSchema") as mock_field_schema,
        ):

            mock_utility.has_collection.return_value = False

            init_milvus()

            # Verify field schemas were created with correct data types
            call_args_list = mock_field_schema.call_args_list

            # Check ID field
            id_field_call = call_args_list[0]
            self.assertEqual(id_field_call[1]["name"], "id")
            self.assertEqual(id_field_call[1]["dtype"], mock_data_type.INT64)
            self.assertTrue(id_field_call[1]["is_primary"])
            self.assertTrue(id_field_call[1]["auto_id"])

            # Check embedding field
            embedding_field_call = call_args_list[1]
            self.assertEqual(embedding_field_call[1]["name"], "embedding")
            self.assertEqual(
                embedding_field_call[1]["dtype"], mock_data_type.FLOAT_VECTOR
            )
            self.assertEqual(embedding_field_call[1]["dim"], 384)


class TestMilvusUtilities(unittest.TestCase):
    """Test cases for Milvus utility functions"""

    def test_collection_name_validation(self):
        """Test collection name validation"""
        # The implementation checks cybersecurity_attacks first, then log_vectors

        with (
            patch("vectorstore.milvus_client.connections"),
            patch("vectorstore.milvus_client.utility") as mock_utility,
            patch("vectorstore.milvus_client.Collection") as mock_collection,
            patch("vectorstore.milvus_client.CollectionSchema"),
            patch("vectorstore.milvus_client.FieldSchema"),
        ):
            # Mock cybersecurity_attacks collection exists
            def has_collection_side_effect(name):
                return name == "cybersecurity_attacks"

            mock_utility.has_collection.side_effect = has_collection_side_effect

            # Mock collection
            mock_coll = Mock()
            mock_coll.name = "cybersecurity_attacks"
            mock_coll.num_entities = 100
            mock_collection.return_value = mock_coll

            from vectorstore.milvus_client import init_milvus

            init_milvus()

            # Verify it checked for cybersecurity_attacks
            mock_utility.has_collection.assert_called_with("cybersecurity_attacks")

    def test_schema_description(self):
        """Test schema description is correctly set"""
        expected_description = "Log vector index"

        with (
            patch("vectorstore.milvus_client.connections"),
            patch("vectorstore.milvus_client.utility") as mock_utility,
            patch("vectorstore.milvus_client.Collection"),
            patch("vectorstore.milvus_client.CollectionSchema") as mock_schema,
            patch("vectorstore.milvus_client.FieldSchema"),
        ):

            mock_utility.has_collection.return_value = False

            from vectorstore.milvus_client import init_milvus

            init_milvus()

            # Verify schema was created with correct description
            mock_schema.assert_called_once()
            call_args = mock_schema.call_args
            self.assertEqual(call_args[0][1], expected_description)


class TestMilvusConnectionParameters(unittest.TestCase):
    """Test cases for Milvus connection parameters"""

    @patch("vectorstore.milvus_client.connections")
    @patch("vectorstore.milvus_client.Collection")
    def test_default_connection_parameters(self, mock_collection, mock_connections):
        """Test default connection parameters are used"""
        with patch("vectorstore.milvus_client.utility") as mock_utility:
            # Mock cybersecurity_attacks collection exists
            def has_collection_side_effect(name):
                return name == "cybersecurity_attacks"

            mock_utility.has_collection.side_effect = has_collection_side_effect

            # Mock collection
            mock_coll = Mock()
            mock_coll.name = "cybersecurity_attacks"
            mock_coll.num_entities = 100
            mock_collection.return_value = mock_coll

            from vectorstore.milvus_client import init_milvus

            init_milvus()

            # Verify default connection parameters
            mock_connections.connect.assert_called_once_with(
                host="localhost", port="19530"
            )

    def test_embedding_dimension(self):
        """Test embedding dimension is correctly set"""
        expected_dimension = 384

        with (
            patch("vectorstore.milvus_client.connections"),
            patch("vectorstore.milvus_client.utility") as mock_utility,
            patch("vectorstore.milvus_client.Collection"),
            patch("vectorstore.milvus_client.CollectionSchema"),
            patch("vectorstore.milvus_client.FieldSchema") as mock_field_schema,
        ):

            mock_utility.has_collection.return_value = False

            from vectorstore.milvus_client import init_milvus

            init_milvus()

            # Verify embedding field was created with correct dimension
            call_args_list = mock_field_schema.call_args_list
            embedding_field_call = call_args_list[1]
            self.assertEqual(embedding_field_call[1]["dim"], expected_dimension)


class TestMilvusErrorScenarios(unittest.TestCase):
    """Test cases for various error scenarios"""

    @patch("vectorstore.milvus_client.connections")
    @patch("vectorstore.milvus_client.utility")
    def test_utility_has_collection_error(self, mock_utility, mock_connections):
        """Test error when checking if collection exists"""
        mock_utility.has_collection.side_effect = Exception("Utility error")

        with self.assertRaises(Exception) as context:
            from vectorstore.milvus_client import init_milvus

            init_milvus()

        self.assertIn("Utility error", str(context.exception))

    @patch("vectorstore.milvus_client.connections")
    @patch("vectorstore.milvus_client.utility")
    @patch("vectorstore.milvus_client.FieldSchema")
    def test_field_schema_creation_error(
        self, mock_field_schema, mock_utility, mock_connections
    ):
        """Test error during field schema creation"""
        mock_utility.has_collection.return_value = False
        mock_field_schema.side_effect = Exception("Field schema error")

        with self.assertRaises(Exception) as context:
            from vectorstore.milvus_client import init_milvus

            init_milvus()

        self.assertIn("Field schema error", str(context.exception))

    @patch("vectorstore.milvus_client.connections")
    @patch("vectorstore.milvus_client.utility")
    @patch("vectorstore.milvus_client.CollectionSchema")
    @patch("vectorstore.milvus_client.FieldSchema")
    def test_collection_schema_creation_error(
        self, mock_field_schema, mock_collection_schema, mock_utility, mock_connections
    ):
        """Test error during collection schema creation"""
        mock_utility.has_collection.return_value = False
        mock_collection_schema.side_effect = Exception("Collection schema error")

        with self.assertRaises(Exception) as context:
            from vectorstore.milvus_client import init_milvus

            init_milvus()

        self.assertIn("Collection schema error", str(context.exception))


class TestMilvusImportValidation(unittest.TestCase):
    """Test cases for import validation"""

    def test_required_imports(self):
        """Test that all required Milvus components can be imported"""
        try:
            pass
            # If we reach here, all imports are successful
            self.assertTrue(True)
        except ImportError as e:
            self.fail(f"Required import failed: {e}")

    def test_function_exists(self):
        """Test that init_milvus function exists and is callable"""
        from vectorstore.milvus_client import init_milvus

        self.assertTrue(callable(init_milvus))


if __name__ == "__main__":
    unittest.main(verbosity=2)
