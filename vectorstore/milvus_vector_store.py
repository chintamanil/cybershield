# Milvus vector store implementation using the base interface
from typing import List, Dict, Any, Optional
from pymilvus import connections, Collection, utility, FieldSchema, CollectionSchema, DataType
from vectorstore.base_vector_store import BaseVectorStore
from utils.logging_config import get_security_logger
from utils.device_config import create_performance_config

logger = get_security_logger("milvus_vector_store")


class MilvusVectorStore(BaseVectorStore):
    """Milvus implementation of the vector store interface"""
    
    def __init__(self, collection_name: str = "cybersecurity_attacks", host: str = "localhost", port: str = "19530"):
        super().__init__(collection_name)
        self.host = host
        self.port = port
        self.collection = None
        self.perf_config = create_performance_config()
        
    async def connect(self) -> bool:
        """Connect to Milvus and initialize collection"""
        try:
            logger.info("Connecting to Milvus", host=self.host, port=self.port)
            connections.connect(host=self.host, port=self.port)
            
            if utility.has_collection(self.collection_name):
                self.collection = Collection(self.collection_name)
                self.collection.load()  # Load collection into memory
                self.is_connected = True
                logger.info("Connected to existing collection", 
                           collection=self.collection_name,
                           count=self.collection.num_entities)
            else:
                logger.warning("Collection not found", collection=self.collection_name)
                self.collection = None
                self.is_connected = False
                
            return self.is_connected
                
        except Exception as e:
            logger.error("Milvus connection failed", error=str(e))
            self.collection = None
            self.is_connected = False
            return False
    
    async def disconnect(self) -> None:
        """Disconnect from Milvus"""
        try:
            if self.collection:
                self.collection.release()
            connections.disconnect(self.host)
            self.is_connected = False
            logger.info("Disconnected from Milvus")
        except Exception as e:
            logger.error(f"Milvus disconnect failed: {e}")
    
    async def search_by_ip(self, ip_address: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search for historical attacks involving a specific IP address"""
        if not self.is_connected or not self.collection:
            logger.warning("No collection available for search")
            return []
            
        try:
            # Search for IP as both source and destination
            filter_expr = f'source_ip == "{ip_address}" || dest_ip == "{ip_address}"'
            
            # Query the collection
            results = self.collection.query(
                expr=filter_expr,
                output_fields=[
                    "id", "timestamp", "source_ip", "dest_ip", "source_port", 
                    "dest_port", "protocol", "attack_type", "attack_signature",
                    "severity_level", "action_taken", "anomaly_score",
                    "malware_indicators", "geo_location", "log_source"
                ],
                limit=limit
            )
            
            logger.debug("Milvus search completed", 
                        ip=ip_address, 
                        results_count=len(results),
                        limit=limit)
            
            return results
            
        except Exception as e:
            logger.error("Milvus search failed", ip=ip_address, error=str(e))
            return []
    
    async def search_similar_attacks(self, query_text: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search for similar attacks using vector similarity"""
        if not self.is_connected or not self.collection:
            logger.warning("No collection available for similarity search")
            return []
            
        try:
            # This would require embedding the query text and doing vector search
            # For now, return empty list - can be implemented when embedding model is available
            logger.debug("Similarity search requested but not yet implemented", query=query_text)
            return []
            
        except Exception as e:
            logger.error("Similarity search failed", query=query_text, error=str(e))
            return []
    
    async def search_by_vector(self, query_vector: List[float], limit: int = 10) -> List[Dict[str, Any]]:
        """Search using pre-computed vector embeddings"""
        if not self.is_connected or not self.collection:
            logger.warning("No collection available for vector search")
            return []
            
        try:
            # Perform vector similarity search
            search_params = {"metric_type": "L2", "params": {"nprobe": 10}}
            
            results = self.collection.search(
                data=[query_vector],
                anns_field="embedding",
                param=search_params,
                limit=limit,
                output_fields=["id", "attack_type", "source_ip", "dest_ip", "timestamp"]
            )
            
            # Convert results to list of dictionaries
            formatted_results = []
            for hits in results:
                for hit in hits:
                    formatted_results.append({
                        "id": hit.id,
                        "score": hit.distance,
                        "entity": hit.entity
                    })
            
            return formatted_results
            
        except Exception as e:
            logger.error("Vector search failed", error=str(e))
            return []
    
    async def get_attack_stats(self, ip_address: str) -> Dict[str, Any]:
        """Get statistics about attacks involving an IP address"""
        if not self.is_connected or not self.collection:
            return {"error": "No collection available"}
            
        try:
            # Get all records for this IP
            records = await self.search_by_ip(ip_address, limit=1000)  # Get more for stats
            
            if not records:
                return {
                    "ip": ip_address,
                    "total_attacks": 0,
                    "attack_types": [],
                    "severity_levels": [],
                    "most_recent": None,
                    "risk_score": 0
                }
            
            # Analyze the records
            attack_types = {}
            severity_levels = {}
            timestamps = []
            
            for record in records:
                # Count attack types
                attack_type = record.get("attack_type", "unknown")
                attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
                
                # Count severity levels
                severity = record.get("severity_level", "unknown")
                severity_levels[severity] = severity_levels.get(severity, 0) + 1
                
                # Collect timestamps
                if record.get("timestamp"):
                    timestamps.append(record["timestamp"])
            
            # Calculate risk score based on attack patterns
            risk_score = min(100, len(records) * 10 + 
                           attack_types.get("Critical", 0) * 30 +
                           attack_types.get("High", 0) * 20)
            
            return {
                "ip": ip_address,
                "total_attacks": len(records),
                "attack_types": attack_types,
                "severity_levels": severity_levels,
                "most_recent": max(timestamps) if timestamps else None,
                "risk_score": risk_score,
                "is_source": any(r.get("source_ip") == ip_address for r in records),
                "is_destination": any(r.get("dest_ip") == ip_address for r in records)
            }
            
        except Exception as e:
            logger.error("Attack stats failed", ip=ip_address, error=str(e))
            return {"error": str(e)}
    
    async def index_document(self, document: Dict[str, Any], doc_id: str = None) -> bool:
        """Index a single document"""
        try:
            if not self.is_connected or not self.collection:
                return False
            
            # Convert document to Milvus format and insert
            entities = [document]
            self.collection.insert(entities)
            self.collection.flush()
            
            return True
            
        except Exception as e:
            logger.error(f"Document indexing failed: {e}")
            return False
    
    async def bulk_index(self, documents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Bulk index multiple documents"""
        try:
            if not self.is_connected or not self.collection:
                return {"success": False, "error": "No collection available"}
            
            # Insert documents in batches
            batch_size = 1000
            total_docs = len(documents)
            successful = 0
            
            for i in range(0, total_docs, batch_size):
                batch = documents[i:i+batch_size]
                try:
                    self.collection.insert(batch)
                    successful += len(batch)
                except Exception as e:
                    logger.error(f"Batch insert failed for batch {i//batch_size}: {e}")
            
            self.collection.flush()
            
            return {
                "success": True,
                "total_documents": total_docs,
                "successful": successful,
                "failed": total_docs - successful
            }
            
        except Exception as e:
            logger.error(f"Bulk indexing failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def delete_document(self, doc_id: str) -> bool:
        """Delete a document by ID"""
        try:
            if not self.is_connected or not self.collection:
                return False
            
            # Delete by primary key
            expr = f"id == {doc_id}"
            self.collection.delete(expr)
            
            return True
            
        except Exception as e:
            logger.error(f"Document deletion failed: {e}")
            return False
    
    async def health_check(self) -> Dict[str, Any]:
        """Check the health status of Milvus"""
        try:
            if not self.is_connected:
                return {"status": "disconnected"}
            
            # Check collection status
            if self.collection:
                count = self.collection.num_entities
                return {
                    "status": "healthy",
                    "collection": self.collection_name,
                    "document_count": count,
                    "host": self.host,
                    "port": self.port
                }
            else:
                return {"status": "no_collection"}
                
        except Exception as e:
            logger.error(f"Milvus health check failed: {e}")
            return {"status": "error", "error": str(e)}