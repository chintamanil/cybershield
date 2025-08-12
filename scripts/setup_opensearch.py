#!/usr/bin/env python3
# Setup script for OpenSearch deployment

import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from vectorstore.opensearch_vector_store import OpenSearchVectorStore
from utils.logging_config import get_security_logger, setup_from_env

# Setup logging
setup_from_env()
logger = get_security_logger("opensearch_setup")


async def setup_local_opensearch():
    """Setup local OpenSearch for development"""
    logger.info("Setting up local OpenSearch")
    
    opensearch = OpenSearchVectorStore(
        collection_name="cybersecurity-attacks",
        host="localhost",
        port=9200
    )
    
    try:
        connected = await opensearch.connect()
        if connected:
            logger.info("✅ Local OpenSearch setup completed")
            
            # Test basic functionality
            health = await opensearch.health_check()
            logger.info(f"Health check: {health}")
            
        else:
            logger.error("❌ Failed to connect to local OpenSearch")
            
    except Exception as e:
        logger.error(f"❌ Local OpenSearch setup failed: {e}")
        print("Make sure OpenSearch is running locally:")
        print("  docker run -p 9200:9200 -e 'discovery.type=single-node' opensearchproject/opensearch:2.11.0")
    
    finally:
        await opensearch.disconnect()


async def setup_aws_opensearch(endpoint: str):
    """Setup AWS OpenSearch"""
    logger.info(f"Setting up AWS OpenSearch at {endpoint}")
    
    opensearch = OpenSearchVectorStore(
        collection_name="cybersecurity-attacks",
        host=endpoint,
        port=443
    )
    
    try:
        connected = await opensearch.connect()
        if connected:
            logger.info("✅ AWS OpenSearch setup completed")
            
            # Test basic functionality
            health = await opensearch.health_check()
            logger.info(f"Health check: {health}")
            
        else:
            logger.error("❌ Failed to connect to AWS OpenSearch")
            
    except Exception as e:
        logger.error(f"❌ AWS OpenSearch setup failed: {e}")
        print("Make sure:")
        print("  1. AWS credentials are configured")
        print("  2. OpenSearch domain exists and is accessible")
        print("  3. IAM permissions are set correctly")
    
    finally:
        await opensearch.disconnect()


async def test_vector_search():
    """Test vector search functionality"""
    logger.info("Testing vector search functionality")
    
    # Use environment to determine which OpenSearch to test
    from utils.environment_config import config
    
    if config.detector.is_aws():
        opensearch = OpenSearchVectorStore(
            collection_name="cybersecurity-attacks",
            host=config.vector_store.host,
            port=config.vector_store.port
        )
    else:
        opensearch = OpenSearchVectorStore(
            collection_name="cybersecurity-attacks",
            host="localhost",
            port=9200
        )
    
    try:
        connected = await opensearch.connect()
        if not connected:
            logger.error("❌ Could not connect to OpenSearch")
            return
        
        # Test document indexing
        test_doc = {
            "id": "test_001",
            "timestamp": "2024-01-01T00:00:00Z",
            "source_ip": "192.168.1.100",
            "dest_ip": "10.0.0.1",
            "attack_type": "test_attack",
            "attack_signature": "Test attack signature for validation",
            "severity_level": "medium",
            "text_content": "Test attack signature for validation",
            "embedding": [0.1] * 384  # Test embedding
        }
        
        # Index test document
        indexed = await opensearch.index_document(test_doc, "test_001")
        if indexed:
            logger.info("✅ Document indexing test passed")
        else:
            logger.error("❌ Document indexing test failed")
        
        # Wait for indexing
        await asyncio.sleep(2)
        
        # Test IP search
        ip_results = await opensearch.search_by_ip("192.168.1.100", limit=5)
        if ip_results:
            logger.info(f"✅ IP search test passed: found {len(ip_results)} results")
        else:
            logger.warning("⚠️ IP search test returned no results")
        
        # Test text search
        text_results = await opensearch.search_similar_attacks("test attack", limit=5)
        if text_results:
            logger.info(f"✅ Text search test passed: found {len(text_results)} results")
        else:
            logger.warning("⚠️ Text search test returned no results")
        
        # Test vector search
        test_vector = [0.1] * 384
        vector_results = await opensearch.search_by_vector(test_vector, limit=5)
        if vector_results:
            logger.info(f"✅ Vector search test passed: found {len(vector_results)} results")
        else:
            logger.warning("⚠️ Vector search test returned no results")
        
        # Cleanup test document
        deleted = await opensearch.delete_document("test_001")
        if deleted:
            logger.info("✅ Test document cleanup completed")
        
        logger.info("✅ All vector search tests completed")
        
    except Exception as e:
        logger.error(f"❌ Vector search test failed: {e}")
    
    finally:
        await opensearch.disconnect()


async def main():
    """Main setup function"""
    if len(sys.argv) < 2:
        print("Usage: python setup_opensearch.py [local|aws|test] [endpoint]")
        print("Commands:")
        print("  local - Setup local OpenSearch")
        print("  aws   - Setup AWS OpenSearch (provide endpoint)")
        print("  test  - Test vector search functionality")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    print("🔍 OpenSearch Setup Tool")
    print("=" * 40)
    
    if command == "local":
        await setup_local_opensearch()
    elif command == "aws":
        if len(sys.argv) < 3:
            print("❌ Please provide AWS OpenSearch endpoint")
            print("Example: python setup_opensearch.py aws search-cybershield-xxxxx.us-east-1.es.amazonaws.com")
            sys.exit(1)
        endpoint = sys.argv[2]
        await setup_aws_opensearch(endpoint)
    elif command == "test":
        await test_vector_search()
    else:
        print(f"❌ Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())