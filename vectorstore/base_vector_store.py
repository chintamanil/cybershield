# Base interface for vector stores to support both Milvus and OpenSearch
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from utils.logging_config import get_security_logger

logger = get_security_logger("base_vector_store")


class BaseVectorStore(ABC):
    """Abstract base class for vector store implementations"""
    
    def __init__(self, collection_name: str = "cybersecurity_attacks"):
        self.collection_name = collection_name
        self.is_connected = False
    
    @abstractmethod
    async def connect(self) -> bool:
        """Connect to the vector store"""
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        """Disconnect from the vector store"""
        pass
    
    @abstractmethod
    async def search_by_ip(self, ip_address: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search for historical attacks involving a specific IP address"""
        pass
    
    @abstractmethod
    async def search_similar_attacks(self, query_text: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search for similar attacks using vector similarity"""
        pass
    
    @abstractmethod
    async def search_by_vector(self, query_vector: List[float], limit: int = 10) -> List[Dict[str, Any]]:
        """Search using pre-computed vector embeddings"""
        pass
    
    @abstractmethod
    async def get_attack_stats(self, ip_address: str) -> Dict[str, Any]:
        """Get statistics about attacks involving an IP address"""
        pass
    
    @abstractmethod
    async def index_document(self, document: Dict[str, Any], doc_id: str = None) -> bool:
        """Index a single document"""
        pass
    
    @abstractmethod
    async def bulk_index(self, documents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Bulk index multiple documents"""
        pass
    
    @abstractmethod
    async def delete_document(self, doc_id: str) -> bool:
        """Delete a document by ID"""
        pass
    
    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """Check the health status of the vector store"""
        pass
    
    async def get_collection_stats(self) -> Dict[str, Any]:
        """Get statistics about the collection/index"""
        try:
            health = await self.health_check()
            return {
                "collection_name": self.collection_name,
                "connected": self.is_connected,
                "health": health
            }
        except Exception as e:
            logger.error(f"Failed to get collection stats: {e}")
            return {
                "collection_name": self.collection_name,
                "connected": False,
                "error": str(e)
            }


class VectorStoreFactory:
    """Factory for creating appropriate vector store based on environment"""
    
    @staticmethod
    def create_vector_store(provider: str = "auto", **kwargs) -> BaseVectorStore:
        """
        Create vector store instance based on provider
        
        Args:
            provider: "milvus", "opensearch", or "auto" for environment-based selection
            **kwargs: Additional configuration parameters
        
        Returns:
            BaseVectorStore instance
        """
        if provider == "auto":
            # Determine provider based on environment
            from utils.environment_config import config
            provider = config.vector_store.provider
        
        if provider == "milvus":
            from vectorstore.milvus_vector_store import MilvusVectorStore
            return MilvusVectorStore(**kwargs)
        elif provider == "opensearch":
            from vectorstore.opensearch_vector_store import OpenSearchVectorStore
            return OpenSearchVectorStore(**kwargs)
        else:
            raise ValueError(f"Unsupported vector store provider: {provider}")