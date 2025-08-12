#!/usr/bin/env python3
# Migration tool for moving data from Milvus to OpenSearch

import asyncio
import json
import sys
from typing import List, Dict, Any
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from vectorstore.milvus_vector_store import MilvusVectorStore
from vectorstore.opensearch_vector_store import OpenSearchVectorStore
from utils.logging_config import get_security_logger, setup_from_env
from utils.service_factory import LLMFactory

# Setup logging
setup_from_env()
logger = get_security_logger("data_migration")


class VectorDataMigrator:
    """Tool for migrating vector data between different stores"""
    
    def __init__(self):
        self.milvus_store = None
        self.opensearch_store = None
        self.embeddings_model = None
    
    async def initialize_stores(self, milvus_config: Dict[str, Any], opensearch_config: Dict[str, Any]):
        """Initialize both vector stores"""
        logger.info("Initializing vector stores for migration")
        
        # Initialize Milvus (source)
        self.milvus_store = MilvusVectorStore(
            collection_name=milvus_config.get("collection_name", "cybersecurity_attacks"),
            host=milvus_config.get("host", "localhost"),
            port=milvus_config.get("port", "19530")
        )
        
        milvus_connected = await self.milvus_store.connect()
        if not milvus_connected:
            raise Exception("Failed to connect to Milvus")
        
        # Initialize OpenSearch (destination)
        self.opensearch_store = OpenSearchVectorStore(
            collection_name=opensearch_config.get("collection_name", "cybersecurity-attacks"),
            host=opensearch_config.get("host", "localhost"),
            port=opensearch_config.get("port", 9200)
        )
        
        opensearch_connected = await self.opensearch_store.connect()
        if not opensearch_connected:
            raise Exception("Failed to connect to OpenSearch")
        
        # Initialize embeddings model for vector generation
        try:
            self.embeddings_model = LLMFactory.create_embeddings()
            logger.info("Embeddings model initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize embeddings model: {e}")
            self.embeddings_model = None
    
    async def export_milvus_data(self, output_file: str = "milvus_export.json", limit: int = None) -> int:
        """Export all data from Milvus to JSON file"""
        logger.info(f"Exporting Milvus data to {output_file}")
        
        try:
            # Query all documents from Milvus
            # Note: This is a simplified approach - for large datasets, use pagination
            results = self.milvus_store.collection.query(
                expr="",  # Empty expression to get all documents
                output_fields=[
                    "id", "timestamp", "source_ip", "dest_ip", "source_port", 
                    "dest_port", "protocol", "attack_type", "attack_signature",
                    "severity_level", "action_taken", "anomaly_score",
                    "malware_indicators", "geo_location", "log_source"
                ],
                limit=limit or 16384  # Milvus default limit
            )
            
            # Save to JSON file
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            logger.info(f"Exported {len(results)} documents to {output_file}")
            return len(results)
            
        except Exception as e:
            logger.error(f"Milvus export failed: {e}")
            raise
    
    async def import_to_opensearch(self, input_file: str = "milvus_export.json", batch_size: int = 100) -> Dict[str, Any]:
        """Import data from JSON file to OpenSearch with embeddings"""
        logger.info(f"Importing data from {input_file} to OpenSearch")
        
        try:
            # Load data from JSON file
            with open(input_file, 'r') as f:
                documents = json.load(f)
            
            logger.info(f"Loaded {len(documents)} documents from {input_file}")
            
            # Process documents in batches
            total_imported = 0
            total_failed = 0
            
            for i in range(0, len(documents), batch_size):
                batch = documents[i:i+batch_size]
                logger.info(f"Processing batch {i//batch_size + 1}: {i} to {i+len(batch)}")
                
                # Enhance documents with embeddings and text content
                enhanced_batch = []
                for doc in batch:
                    enhanced_doc = await self._enhance_document(doc)
                    enhanced_batch.append(enhanced_doc)
                
                # Bulk index to OpenSearch
                result = await self.opensearch_store.bulk_index(enhanced_batch)
                
                if result['success']:
                    total_imported += result['successful']
                    total_failed += result['failed']
                    logger.info(f"Batch imported: {result['successful']} successful, {result['failed']} failed")
                else:
                    logger.error(f"Batch import failed: {result.get('error', 'Unknown error')}")
                    total_failed += len(batch)
            
            return {
                "total_documents": len(documents),
                "successful": total_imported,
                "failed": total_failed,
                "success_rate": (total_imported / len(documents)) * 100 if documents else 0
            }
            
        except Exception as e:
            logger.error(f"OpenSearch import failed: {e}")
            raise
    
    async def _enhance_document(self, doc: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance document with text content and embeddings"""
        try:
            # Create searchable text content from structured fields
            text_parts = []
            
            if doc.get('attack_signature'):
                text_parts.append(f"Attack: {doc['attack_signature']}")
            if doc.get('malware_indicators'):
                text_parts.append(f"Malware: {doc['malware_indicators']}")
            if doc.get('attack_type'):
                text_parts.append(f"Type: {doc['attack_type']}")
            if doc.get('source_ip'):
                text_parts.append(f"Source: {doc['source_ip']}")
            if doc.get('dest_ip'):
                text_parts.append(f"Destination: {doc['dest_ip']}")
            
            text_content = " | ".join(text_parts)
            doc['text_content'] = text_content
            
            # Generate embeddings if model is available
            if self.embeddings_model and text_content:
                try:
                    embedding = await asyncio.to_thread(
                        self.embeddings_model.embed_query, 
                        text_content
                    )
                    doc['embedding'] = embedding
                except Exception as e:
                    logger.warning(f"Failed to generate embedding for document: {e}")
                    # Use zero vector as fallback
                    doc['embedding'] = [0.0] * 384
            else:
                # Use zero vector if no embeddings model
                doc['embedding'] = [0.0] * 384
            
            return doc
            
        except Exception as e:
            logger.error(f"Document enhancement failed: {e}")
            return doc
    
    async def migrate_direct(self, batch_size: int = 100, limit: int = None) -> Dict[str, Any]:
        """Direct migration from Milvus to OpenSearch without intermediate file"""
        logger.info("Starting direct migration from Milvus to OpenSearch")
        
        try:
            # Get all documents from Milvus
            results = self.milvus_store.collection.query(
                expr="",
                output_fields=[
                    "id", "timestamp", "source_ip", "dest_ip", "source_port", 
                    "dest_port", "protocol", "attack_type", "attack_signature",
                    "severity_level", "action_taken", "anomaly_score",
                    "malware_indicators", "geo_location", "log_source"
                ],
                limit=limit or 16384
            )
            
            logger.info(f"Retrieved {len(results)} documents from Milvus")
            
            # Process in batches
            total_imported = 0
            total_failed = 0
            
            for i in range(0, len(results), batch_size):
                batch = results[i:i+batch_size]
                logger.info(f"Migrating batch {i//batch_size + 1}: {i} to {i+len(batch)}")
                
                # Enhance documents
                enhanced_batch = []
                for doc in batch:
                    enhanced_doc = await self._enhance_document(doc)
                    enhanced_batch.append(enhanced_doc)
                
                # Import to OpenSearch
                result = await self.opensearch_store.bulk_index(enhanced_batch)
                
                if result['success']:
                    total_imported += result['successful']
                    total_failed += result['failed']
                else:
                    total_failed += len(batch)
            
            return {
                "total_documents": len(results),
                "successful": total_imported,
                "failed": total_failed,
                "success_rate": (total_imported / len(results)) * 100 if results else 0
            }
            
        except Exception as e:
            logger.error(f"Direct migration failed: {e}")
            raise
    
    async def validate_migration(self, sample_size: int = 10) -> Dict[str, Any]:
        """Validate migration by comparing data between stores"""
        logger.info("Validating migration results")
        
        try:
            # Get sample IPs from both stores
            milvus_health = await self.milvus_store.health_check()
            opensearch_health = await self.opensearch_store.health_check()
            
            validation_results = {
                "milvus_health": milvus_health,
                "opensearch_health": opensearch_health,
                "sample_comparisons": []
            }
            
            # Test a few IP searches
            test_ips = ["192.168.1.1", "10.0.0.1", "203.0.113.1"]
            
            for ip in test_ips:
                milvus_results = await self.milvus_store.search_by_ip(ip, limit=5)
                opensearch_results = await self.opensearch_store.search_by_ip(ip, limit=5)
                
                validation_results["sample_comparisons"].append({
                    "ip": ip,
                    "milvus_count": len(milvus_results),
                    "opensearch_count": len(opensearch_results),
                    "data_consistency": len(milvus_results) == len(opensearch_results)
                })
            
            return validation_results
            
        except Exception as e:
            logger.error(f"Migration validation failed: {e}")
            return {"error": str(e)}
    
    async def cleanup(self):
        """Clean up connections"""
        try:
            if self.milvus_store:
                await self.milvus_store.disconnect()
            if self.opensearch_store:
                await self.opensearch_store.disconnect()
            logger.info("Migration cleanup completed")
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")


async def main():
    """Main migration function"""
    if len(sys.argv) < 2:
        print("Usage: python migrate_vector_data.py [export|import|migrate|validate]")
        print("Commands:")
        print("  export   - Export Milvus data to JSON file")
        print("  import   - Import JSON data to OpenSearch")
        print("  migrate  - Direct migration from Milvus to OpenSearch")
        print("  validate - Validate migration results")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    # Configuration
    milvus_config = {
        "host": "localhost",
        "port": "19530",
        "collection_name": "cybersecurity_attacks"
    }
    
    opensearch_config = {
        "host": "search-cybershield-xxxxx.us-east-1.es.amazonaws.com",  # Update with your endpoint
        "port": 443,
        "collection_name": "cybersecurity-attacks"
    }
    
    migrator = VectorDataMigrator()
    
    try:
        await migrator.initialize_stores(milvus_config, opensearch_config)
        
        if command == "export":
            count = await migrator.export_milvus_data("milvus_export.json")
            print(f"✅ Exported {count} documents from Milvus")
            
        elif command == "import":
            result = await migrator.import_to_opensearch("milvus_export.json")
            print(f"✅ Import completed: {result['successful']}/{result['total_documents']} successful")
            
        elif command == "migrate":
            result = await migrator.migrate_direct(batch_size=100)
            print(f"✅ Migration completed: {result['successful']}/{result['total_documents']} successful")
            print(f"Success rate: {result['success_rate']:.2f}%")
            
        elif command == "validate":
            result = await migrator.validate_migration()
            print(f"✅ Validation completed")
            print(f"Milvus status: {result['milvus_health']['status']}")
            print(f"OpenSearch status: {result['opensearch_health']['status']}")
            for comp in result['sample_comparisons']:
                print(f"IP {comp['ip']}: Milvus({comp['milvus_count']}) vs OpenSearch({comp['opensearch_count']}) - Consistent: {comp['data_consistency']}")
        
        else:
            print(f"❌ Unknown command: {command}")
    
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        print(f"❌ Migration failed: {e}")
    
    finally:
        await migrator.cleanup()


if __name__ == "__main__":
    asyncio.run(main())