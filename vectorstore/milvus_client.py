# Milvus client to store embeddings of logs and search for threats
from pymilvus import connections, Collection, utility, FieldSchema, CollectionSchema, DataType
from typing import List, Dict, Any
from utils.logging_config import get_security_logger
from utils.device_config import create_performance_config

logger = get_security_logger("milvus_client")

class CyberShieldVectorStore:
    """Enhanced vector store client for cybersecurity threat intelligence"""
    
    def __init__(self, collection_name: str = "cybersecurity_attacks"):
        self.collection_name = collection_name
        self.collection = None
        self.perf_config = create_performance_config()
        
    async def connect(self):
        """Connect to Milvus and initialize collection"""
        try:
            logger.info("Connecting to Milvus", host="localhost", port=19530)
            connections.connect(host='localhost', port='19530')
            
            if utility.has_collection(self.collection_name):
                self.collection = Collection(self.collection_name)
                self.collection.load()  # Load collection into memory
                logger.info("Connected to existing collection", 
                           collection=self.collection_name,
                           count=self.collection.num_entities)
            else:
                logger.warning("Collection not found", collection=self.collection_name)
                self.collection = None
                
        except Exception as e:
            logger.error("Milvus connection failed", error=str(e))
            self.collection = None
    
    async def search_by_ip(self, ip_address: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Search for historical attacks involving a specific IP address
        
        Args:
            ip_address: IP to search for (as source or destination)
            limit: Maximum number of results to return
            
        Returns:
            List of matching attack records
        """
        if not self.collection:
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
            
            logger.debug("Vector search completed", 
                        ip=ip_address, 
                        results_count=len(results),
                        limit=limit)
            
            return results
            
        except Exception as e:
            logger.error("Vector search failed", ip=ip_address, error=str(e))
            return []
    
    async def search_similar_attacks(self, query_text: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Search for similar attacks using vector similarity
        
        Args:
            query_text: Text description of the attack pattern
            limit: Maximum number of results to return
            
        Returns:
            List of similar attack records
        """
        if not self.collection:
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
    
    async def get_attack_stats(self, ip_address: str) -> Dict[str, Any]:
        """
        Get statistics about attacks involving an IP address
        
        Args:
            ip_address: IP to analyze
            
        Returns:
            Dictionary with attack statistics
        """
        if not self.collection:
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

def init_milvus():
    """Legacy function for backward compatibility"""
    try:
        logger.info("Connecting to Milvus", host="localhost", port=19530)
        connections.connect(host='localhost', port='19530')
        
        # Try to connect to cybersecurity_attacks collection first
        if utility.has_collection("cybersecurity_attacks"):
            collection = Collection("cybersecurity_attacks")
            logger.info("Using cybersecurity_attacks collection")
        elif utility.has_collection("log_vectors"):
            collection = Collection("log_vectors")
            logger.info("Using log_vectors collection")
        else:
            logger.info("Creating new collection", collection="log_vectors", dimension=384)
            fields = [
                FieldSchema(name="id", dtype=DataType.INT64, is_primary=True, auto_id=True),
                FieldSchema(name="embedding", dtype=DataType.FLOAT_VECTOR, dim=384)
            ]
            schema = CollectionSchema(fields, "Log vector index")
            collection = Collection("log_vectors", schema)
            logger.info("Collection created successfully", collection="log_vectors")
            
        logger.info("Milvus initialization complete", 
                   collection=collection.name, 
                   count=collection.num_entities)
        return collection
        
    except Exception as e:
        logger.error("Milvus initialization failed", error=str(e))
        raise
