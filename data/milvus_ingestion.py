#!/usr/bin/env python3
"""
Milvus Data Ingestion Pipeline for CyberShield
Converts cybersecurity attack data to vector embeddings and stores in Milvus
"""

import pandas as pd
import numpy as np
from typing import List, Dict, Any
import json
import hashlib
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configure structured logging and device optimization
from utils.logging_config import get_security_logger
from utils.device_config import create_performance_config

logger = get_security_logger("milvus_ingestion")

# Try to import optional dependencies
try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False
    SentenceTransformer = None
    logger.warning("sentence-transformers not available. Install with: pip install sentence-transformers")
    logger.info("Note: PyTorch may not be available for Python 3.13. Using fallback embeddings.")

try:
    from pymilvus import connections, Collection, FieldSchema, CollectionSchema, DataType, utility
    PYMILVUS_AVAILABLE = True
except ImportError:
    PYMILVUS_AVAILABLE = False

class CyberSecurityDataProcessor:
    """Process and vectorize cybersecurity attack data for Milvus storage"""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        """
        Initialize the data processor

        Args:
            model_name: SentenceTransformer model for creating embeddings
        """
        self.model_name = model_name
        self.embedding_model = None
        self.dimension = 384  # Default for all-MiniLM-L6-v2
        self.collection_name = "cybersecurity_attacks"

        # Get optimal device configuration for Mac M4
        self.perf_config = create_performance_config()
        
        # Initialize embedding model if available
        if SENTENCE_TRANSFORMERS_AVAILABLE:
            try:
                import torch
                device = self.perf_config["sentence_transformers_device"]
                
                logger.info("Initializing embedding model with optimization", 
                           model=model_name,
                           device=device,
                           batch_size=self.perf_config["batch_size"],
                           precision=self.perf_config["precision"])
                
                # Initialize with optimal settings for Mac M4
                self.embedding_model = SentenceTransformer(model_name, device=device)
                
                # Enable half precision for better performance on Apple Silicon
                if device == "mps" and hasattr(self.embedding_model, '_modules'):
                    try:
                        self.embedding_model.half()
                        logger.info("Enabled half precision for Apple Silicon MPS")
                    except:
                        logger.info("Using full precision (half precision not supported)")
                
                self.dimension = self.embedding_model.get_sentence_embedding_dimension()
                logger.info("Embedding model initialized successfully", 
                           model=model_name, 
                           dimension=self.dimension, 
                           device=device,
                           optimized_for="Mac_M4")
            except Exception as e:
                logger.warning(f"Failed to initialize embedding model: {e}")
                logger.info("Will use fallback text processing without embeddings")
        else:
            logger.warning("sentence-transformers not available, will use fallback embeddings")
            logger.info("To install: pip install sentence-transformers")

    def preprocess_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Clean and preprocess the cybersecurity data

        Args:
            df: Raw pandas DataFrame

        Returns:
            Cleaned DataFrame
        """
        logger.info("Starting data preprocessing", data_source="cybersecurity_attacks.csv")

        # Create a copy to avoid modifying original
        processed_df = df.copy()

        # Clean column names
        processed_df.columns = [col.strip().replace(' ', '_').lower() for col in processed_df.columns]

        # Handle missing values
        processed_df = processed_df.fillna('')

        # Parse timestamp
        if 'timestamp' in processed_df.columns:
            processed_df['timestamp'] = pd.to_datetime(processed_df['timestamp'], errors='coerce')

        # Clean IP addresses
        ip_columns = ['source_ip_address', 'destination_ip_address']
        for col in ip_columns:
            if col in processed_df.columns:
                processed_df[col] = processed_df[col].astype(str).str.strip()

        # Clean numeric columns
        numeric_columns = ['source_port', 'destination_port', 'packet_length', 'anomaly_scores']
        for col in numeric_columns:
            if col in processed_df.columns:
                processed_df[col] = pd.to_numeric(processed_df[col], errors='coerce').fillna(0)

        # Create composite text fields for embeddings
        processed_df['attack_description'] = self._create_attack_description(processed_df)
        processed_df['network_context'] = self._create_network_context(processed_df)
        processed_df['full_context'] = self._create_full_context(processed_df)

        logger.info("Data preprocessing completed", 
                   records_processed=len(processed_df),
                   original_count=len(df))
        return processed_df

    def _create_attack_description(self, df: pd.DataFrame) -> pd.Series:
        """Create a comprehensive attack description for embedding"""
        descriptions = []

        for _, row in df.iterrows():
            parts = []

            # Attack information
            if 'attack_type' in row and row['attack_type']:
                parts.append(f"Attack Type: {row['attack_type']}")

            if 'attack_signature' in row and row['attack_signature']:
                parts.append(f"Signature: {row['attack_signature']}")

            if 'severity_level' in row and row['severity_level']:
                parts.append(f"Severity: {row['severity_level']}")

            # Payload and malware info
            if 'payload_data' in row and row['payload_data']:
                payload = str(row['payload_data'])[:200]  # Limit length
                parts.append(f"Payload: {payload}")

            if 'malware_indicators' in row and row['malware_indicators']:
                parts.append(f"Malware: {row['malware_indicators']}")

            # Alerts
            if 'alerts/warnings' in row and row['alerts/warnings']:
                parts.append(f"Alert: {row['alerts/warnings']}")

            descriptions.append(" | ".join(parts))

        return pd.Series(descriptions)

    def _create_network_context(self, df: pd.DataFrame) -> pd.Series:
        """Create network context description for embedding"""
        contexts = []

        for _, row in df.iterrows():
            parts = []

            # Network information
            if 'source_ip_address' in row and row['source_ip_address']:
                parts.append(f"Source: {row['source_ip_address']}")

            if 'destination_ip_address' in row and row['destination_ip_address']:
                parts.append(f"Destination: {row['destination_ip_address']}")

            if 'protocol' in row and row['protocol']:
                parts.append(f"Protocol: {row['protocol']}")

            if 'traffic_type' in row and row['traffic_type']:
                parts.append(f"Traffic: {row['traffic_type']}")

            if 'network_segment' in row and row['network_segment']:
                parts.append(f"Segment: {row['network_segment']}")

            if 'geo-location_data' in row and row['geo-location_data']:
                parts.append(f"Location: {row['geo-location_data']}")

            contexts.append(" | ".join(parts))

        return pd.Series(contexts)

    def _create_full_context(self, df: pd.DataFrame) -> pd.Series:
        """Create full context combining attack and network information"""
        full_contexts = []

        for i, row in df.iterrows():
            attack_desc = row.get('attack_description', '')
            network_ctx = row.get('network_context', '')

            # Additional context
            additional_parts = []

            if 'action_taken' in row and row['action_taken']:
                additional_parts.append(f"Action: {row['action_taken']}")

            if 'user_information' in row and row['user_information']:
                additional_parts.append(f"User: {row['user_information']}")

            if 'log_source' in row and row['log_source']:
                additional_parts.append(f"Source: {row['log_source']}")

            additional_ctx = " | ".join(additional_parts)

            full_context = " || ".join(filter(None, [attack_desc, network_ctx, additional_ctx]))
            full_contexts.append(full_context)

        return pd.Series(full_contexts)

    def create_embeddings(self, texts: List[str], batch_size: int = None) -> np.ndarray:
        """
        Create embeddings for text data with optimal batch size for Mac M4

        Args:
            texts: List of text strings to embed
            batch_size: Batch size for processing (auto-optimized if None)

        Returns:
            numpy array of embeddings
        """
        if not self.embedding_model:
            logger.warning("No embedding model available, using zero vectors")
            return np.zeros((len(texts), self.dimension))

        # Use optimized batch size for Mac M4 if not specified
        if batch_size is None:
            batch_size = self.perf_config["batch_size"]

        logger.info("Creating embeddings with optimization", 
                   text_count=len(texts),
                   batch_size=batch_size,
                   device=self.perf_config["torch_device"],
                   precision=self.perf_config["precision"])

        # Process in batches to avoid memory issues
        all_embeddings = []

        for i in range(0, len(texts), batch_size):
            batch_texts = texts[i:i + batch_size]
            
            # Use optimized encoding settings for Mac M4
            batch_embeddings = self.embedding_model.encode(
                batch_texts, 
                show_progress_bar=False,
                convert_to_numpy=True,
                normalize_embeddings=True,  # Better for similarity search
                batch_size=min(batch_size, len(batch_texts))  # Ensure we don't exceed batch
            )
            all_embeddings.append(batch_embeddings)
            
            if (i + batch_size) % (batch_size * 10) == 0:  # Log every 10 batches
                logger.info(f"Processed {i + batch_size}/{len(texts)} texts")

        embeddings = np.vstack(all_embeddings)
        logger.info("Embedding creation completed", 
                   shape=embeddings.shape,
                   dtype=embeddings.dtype,
                   device=self.perf_config["torch_device"])
        return embeddings

    def create_milvus_collection(self, force_recreate: bool = False):
        """
        Create Milvus collection for cybersecurity data

        Args:
            force_recreate: Whether to drop and recreate existing collection
        """
        if not PYMILVUS_AVAILABLE:
            logger.error("pymilvus not available. Install with: pip install pymilvus")
            return None

        try:
            # Connect to Milvus
            connections.connect("default", host="localhost", port="19530")
            logger.info("Connected to Milvus")

            # Check if collection exists
            if utility.has_collection(self.collection_name):
                if force_recreate:
                    utility.drop_collection(self.collection_name)
                    logger.info(f"Dropped existing collection: {self.collection_name}")
                else:
                    logger.info(f"Collection {self.collection_name} already exists")
                    return Collection(self.collection_name)

            # Define schema
            fields = [
                FieldSchema(name="id", dtype=DataType.VARCHAR, max_length=64, is_primary=True),
                FieldSchema(name="timestamp", dtype=DataType.VARCHAR, max_length=32),
                FieldSchema(name="source_ip", dtype=DataType.VARCHAR, max_length=45),
                FieldSchema(name="dest_ip", dtype=DataType.VARCHAR, max_length=45),
                FieldSchema(name="source_port", dtype=DataType.INT64),
                FieldSchema(name="dest_port", dtype=DataType.INT64),
                FieldSchema(name="protocol", dtype=DataType.VARCHAR, max_length=16),
                FieldSchema(name="attack_type", dtype=DataType.VARCHAR, max_length=64),
                FieldSchema(name="attack_signature", dtype=DataType.VARCHAR, max_length=128),
                FieldSchema(name="severity_level", dtype=DataType.VARCHAR, max_length=16),
                FieldSchema(name="action_taken", dtype=DataType.VARCHAR, max_length=32),
                FieldSchema(name="anomaly_score", dtype=DataType.FLOAT),
                FieldSchema(name="malware_indicators", dtype=DataType.VARCHAR, max_length=128),
                FieldSchema(name="geo_location", dtype=DataType.VARCHAR, max_length=128),
                FieldSchema(name="user_info", dtype=DataType.VARCHAR, max_length=128),
                FieldSchema(name="log_source", dtype=DataType.VARCHAR, max_length=32),
                FieldSchema(name="full_context", dtype=DataType.VARCHAR, max_length=2048),
                FieldSchema(name="embedding", dtype=DataType.FLOAT_VECTOR, dim=self.dimension)
            ]

            schema = CollectionSchema(fields, f"CyberShield cybersecurity attacks collection")
            collection = Collection(self.collection_name, schema)

            # Create index for vector field
            index_params = {
                "metric_type": "IP",  # Inner Product
                "index_type": "IVF_FLAT",
                "params": {"nlist": 1024}
            }
            collection.create_index("embedding", index_params)

            logger.info(f"Created collection: {self.collection_name}")
            return collection

        except Exception as e:
            logger.error(f"Failed to create Milvus collection: {e}")
            raise

    def generate_record_id(self, row: pd.Series) -> str:
        """Generate unique ID for each record"""
        # Create ID from key fields
        key_parts = [
            str(row.get('timestamp', '')),
            str(row.get('source_ip_address', '')),
            str(row.get('destination_ip_address', '')),
            str(row.get('attack_type', ''))
        ]
        key_string = "_".join(key_parts)
        return hashlib.md5(key_string.encode()).hexdigest()[:16]

    def prepare_milvus_data(self, df: pd.DataFrame) -> Dict[str, List]:
        """
        Prepare data for Milvus insertion

        Args:
            df: Preprocessed DataFrame

        Returns:
            Dictionary with field names as keys and lists of values
        """
        logger.info("Preparing data for Milvus insertion...")

        # Create embeddings
        embeddings = self.create_embeddings(df['full_context'].tolist())

        # Helper function to safely convert to list with proper handling
        def safe_convert(series, dtype=str, default=''):
            try:
                if dtype == int:
                    return [int(x) if pd.notna(x) and x != '' else 0 for x in series]
                elif dtype == float:
                    return [float(x) if pd.notna(x) and x != '' else 0.0 for x in series]
                else:
                    return [str(x) if pd.notna(x) and x != '' else default for x in series]
            except Exception as e:
                logger.warning(f"Error converting series to {dtype}: {e}")
                return [default] * len(series)

        # Prepare data dictionary with proper type handling
        data = {
            "id": [self.generate_record_id(row) for _, row in df.iterrows()],
            "timestamp": safe_convert(df['timestamp'], str, ''),
            "source_ip": safe_convert(df['source_ip_address'], str, ''),
            "dest_ip": safe_convert(df['destination_ip_address'], str, ''),
            "source_port": safe_convert(df['source_port'], int, 0),
            "dest_port": safe_convert(df['destination_port'], int, 0),
            "protocol": safe_convert(df['protocol'], str, ''),
            "attack_type": safe_convert(df['attack_type'], str, ''),
            "attack_signature": safe_convert(df['attack_signature'], str, ''),
            "severity_level": safe_convert(df['severity_level'], str, ''),
            "action_taken": safe_convert(df['action_taken'], str, ''),
            "anomaly_score": safe_convert(df['anomaly_scores'], float, 0.0),
            "malware_indicators": safe_convert(df['malware_indicators'], str, ''),
            "geo_location": safe_convert(df.get('geo-location_data', pd.Series([''] * len(df))), str, ''),
            "user_info": safe_convert(df['user_information'], str, ''),
            "log_source": safe_convert(df['log_source'], str, ''),
            "full_context": safe_convert(df['full_context'], str, ''),
            "embedding": embeddings.tolist()
        }

        # Validate data lengths
        lengths = {k: len(v) for k, v in data.items()}
        if len(set(lengths.values())) > 1:
            logger.error(f"Data length mismatch: {lengths}")
            raise ValueError("All data fields must have the same length")

        logger.info(f"Prepared {len(data['id'])} records for insertion")
        logger.info(f"Data field lengths: {lengths}")
        return data

    def insert_data_batch(self, collection: Any, data: Dict[str, List],
                         batch_size: int = 1000) -> int:
        """
        Insert data into Milvus collection in batches

        Args:
            collection: Milvus collection
            data: Prepared data dictionary
            batch_size: Batch size for insertion

        Returns:
            Total number of inserted records
        """
        total_records = len(data['id'])
        inserted_count = 0

        logger.info(f"Inserting {total_records} records in batches of {batch_size}")

        for i in range(0, total_records, batch_size):
            end_idx = min(i + batch_size, total_records)

            # Create batch data - extract slices from each field
            batch_data = {}
            for field, values in data.items():
                batch_data[field] = values[i:end_idx]

            try:
                # Insert batch - use the newer Milvus API format
                # Convert the batch data to the format expected by Milvus
                insert_data = []
                for j in range(len(batch_data['id'])):
                    record = {}
                    for field, values in batch_data.items():
                        if j < len(values):
                            record[field] = values[j]
                    insert_data.append(record)

                collection.insert(insert_data)
                inserted_count += len(insert_data)

                if i % (batch_size * 10) == 0:  # Log every 10 batches
                    logger.info(f"Inserted {inserted_count}/{total_records} records")

            except Exception as e:
                logger.error(f"Failed to insert batch {i}-{end_idx}: {e}")
                logger.error(f"Batch data keys: {list(batch_data.keys())}")
                if batch_data and len(batch_data) > 0:
                    sample_record = {}
                    for key, values in batch_data.items():
                        if values and len(values) > 0:
                            sample_record[key] = values[0]
                    logger.error(f"Sample record: {sample_record}")
                continue

        # Flush to ensure data is written
        collection.flush()
        logger.info(f"Successfully inserted {inserted_count} records")
        return inserted_count

def main():
    """Main function to run the data ingestion pipeline"""
    logger.info("Starting CyberShield data ingestion pipeline")

    # Initialize processor
    processor = CyberSecurityDataProcessor()

    # Load data
    csv_path = "data/cybersecurity_attacks.csv"
    if not os.path.exists(csv_path):
        logger.error(f"Data file not found: {csv_path}")
        return

    logger.info(f"Loading data from {csv_path}")
    df = pd.read_csv(csv_path)
    logger.info(f"Loaded {len(df)} records with {len(df.columns)} columns")

    # Preprocess data
    processed_df = processor.preprocess_data(df)

    # Prepare data for Milvus
    milvus_data = processor.prepare_milvus_data(processed_df)

    # Try to create Milvus collection and insert data
    collection = processor.create_milvus_collection(force_recreate=False)
    if collection is not None:
        # Insert data
        inserted_count = processor.insert_data_batch(collection, milvus_data)
        logger.info(f"Data ingestion complete! Inserted {inserted_count} records")
    else:
        logger.info("Milvus not available - saving processed data to JSON file")
        # Save processed data to JSON for later ingestion
        output_file = "data/processed_cybersecurity_data.json"
        sample_data = {k: v[:10] for k, v in milvus_data.items()}  # Save first 10 records as sample
        with open(output_file, 'w') as f:
            json.dump(sample_data, f, indent=2, default=str)
        logger.info(f"Sample processed data saved to {output_file}")
        logger.info(f"Total records processed: {len(milvus_data['id'])}")
        inserted_count = 0

    logger.info(f"Data ingestion complete! Inserted {inserted_count} records")
    logger.info(f"Collection '{processor.collection_name}' is ready for similarity search")

if __name__ == "__main__":
    main()