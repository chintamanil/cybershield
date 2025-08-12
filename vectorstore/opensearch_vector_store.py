# OpenSearch vector store implementation for AWS deployment
import json
import hashlib
from typing import List, Dict, Any, Optional
from opensearchpy import OpenSearch, RequestsHttpConnection
from vectorstore.base_vector_store import BaseVectorStore
from utils.logging_config import get_security_logger
from utils.environment_config import config

logger = get_security_logger("opensearch_vector_store")


class OpenSearchVectorStore(BaseVectorStore):
    """OpenSearch implementation of the vector store interface with AWS support"""
    
    def __init__(self, collection_name: str = "cybersecurity_attacks", host: str = None, port: int = 443):
        super().__init__(collection_name)
        self.host = host or config.vector_store.host
        self.port = port
        self.client = None
        self.index_name = collection_name.lower().replace('_', '-')  # OpenSearch index naming
        
    async def connect(self) -> bool:
        """Connect to OpenSearch and initialize index"""
        try:
            logger.info("Connecting to OpenSearch", host=self.host, port=self.port)
            
            if config.detector.is_aws():
                # AWS OpenSearch with IAM authentication
                self.client = self._create_aws_client()
            else:
                # Local OpenSearch (if available)
                self.client = self._create_local_client()
            
            # Test connection
            info = self.client.info()
            logger.info("Connected to OpenSearch", version=info['version']['number'])
            
            # Create index if it doesn't exist
            await self._ensure_index_exists()
            
            self.is_connected = True
            return True
            
        except Exception as e:
            logger.error("OpenSearch connection failed", error=str(e))
            self.client = None
            self.is_connected = False
            return False
    
    def _create_aws_client(self) -> OpenSearch:
        """Create AWS OpenSearch client with IAM authentication"""
        try:
            from opensearchpy import AWSV4SignerAuth
            import boto3
            
            # Get AWS credentials
            credentials = boto3.Session().get_credentials()
            auth = AWSV4SignerAuth(credentials, config.llm.region or 'us-east-1')
            
            return OpenSearch(
                hosts=[{'host': self.host, 'port': self.port}],
                http_auth=auth,
                use_ssl=True,
                verify_certs=True,
                connection_class=RequestsHttpConnection,
                timeout=30
            )
            
        except ImportError:
            logger.error("AWS authentication requires opensearch-py with AWSV4SignerAuth")
            raise
    
    def _create_local_client(self) -> OpenSearch:
        """Create local OpenSearch client"""
        return OpenSearch(
            hosts=[{'host': self.host, 'port': self.port}],
            use_ssl=False,
            verify_certs=False,
            timeout=30
        )
    
    async def _ensure_index_exists(self) -> None:
        """Create index with proper mapping if it doesn't exist"""
        if self.client.indices.exists(index=self.index_name):
            logger.info(f"Index {self.index_name} already exists")
            return
        
        # Define index mapping with vector support
        mapping = {
            "settings": {
                "index": {
                    "knn": True,  # Enable k-NN search
                    "number_of_shards": 1,
                    "number_of_replicas": 0
                }
            },
            "mappings": {
                "properties": {
                    "id": {"type": "keyword"},
                    "timestamp": {"type": "date"},
                    "source_ip": {"type": "ip"},
                    "dest_ip": {"type": "ip"},
                    "source_port": {"type": "integer"},
                    "dest_port": {"type": "integer"},
                    "protocol": {"type": "keyword"},
                    "attack_type": {"type": "keyword"},
                    "attack_signature": {"type": "text"},
                    "severity_level": {"type": "keyword"},
                    "action_taken": {"type": "keyword"},
                    "anomaly_score": {"type": "float"},
                    "malware_indicators": {"type": "text"},
                    "geo_location": {"type": "geo_point"},
                    "log_source": {"type": "keyword"},
                    "embedding": {
                        "type": "knn_vector",
                        "dimension": 384,  # Sentence transformer dimension
                        "method": {
                            "name": "hnsw",
                            "space_type": "l2",
                            "engine": "nmslib"
                        }
                    },
                    "text_content": {"type": "text"},  # For full-text search
                    "indexed_at": {"type": "date"}
                }
            }
        }
        
        self.client.indices.create(index=self.index_name, body=mapping)
        logger.info(f"Created index {self.index_name} with vector support")
    
    async def disconnect(self) -> None:
        """Disconnect from OpenSearch"""
        try:
            if self.client:
                # OpenSearch client doesn't need explicit disconnection
                self.client = None
            self.is_connected = False
            logger.info("Disconnected from OpenSearch")
        except Exception as e:
            logger.error(f"OpenSearch disconnect failed: {e}")
    
    async def search_by_ip(self, ip_address: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search for historical attacks involving a specific IP address"""
        if not self.is_connected or not self.client:
            logger.warning("No OpenSearch client available for search")
            return []
            
        try:
            # Search for IP as both source and destination
            search_body = {
                "size": limit,
                "query": {
                    "bool": {
                        "should": [
                            {"term": {"source_ip": ip_address}},
                            {"term": {"dest_ip": ip_address}}
                        ]
                    }
                },
                "sort": [
                    {"timestamp": {"order": "desc"}}
                ]
            }
            
            response = self.client.search(
                index=self.index_name,
                body=search_body
            )
            
            results = [hit['_source'] for hit in response['hits']['hits']]
            
            logger.debug("OpenSearch IP search completed", 
                        ip=ip_address, 
                        results_count=len(results),
                        limit=limit)
            
            return results
            
        except Exception as e:
            logger.error("OpenSearch IP search failed", ip=ip_address, error=str(e))
            return []
    
    async def search_similar_attacks(self, query_text: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search for similar attacks using full-text search"""
        if not self.is_connected or not self.client:
            logger.warning("No OpenSearch client available for similarity search")
            return []
            
        try:
            # Use multi-match query for text similarity
            search_body = {
                "size": limit,
                "query": {
                    "multi_match": {
                        "query": query_text,
                        "fields": ["attack_signature", "malware_indicators", "text_content"],
                        "type": "best_fields",
                        "fuzziness": "AUTO"
                    }
                },
                "sort": [
                    {"_score": {"order": "desc"}},
                    {"timestamp": {"order": "desc"}}
                ]
            }
            
            response = self.client.search(
                index=self.index_name,
                body=search_body
            )
            
            results = []
            for hit in response['hits']['hits']:
                result = hit['_source']
                result['similarity_score'] = hit['_score']
                results.append(result)
            
            logger.debug("OpenSearch text similarity search completed", 
                        query=query_text[:50], 
                        results_count=len(results))
            
            return results
            
        except Exception as e:
            logger.error("OpenSearch similarity search failed", query=query_text, error=str(e))
            return []
    
    async def search_by_vector(self, query_vector: List[float], limit: int = 10) -> List[Dict[str, Any]]:
        """Search using pre-computed vector embeddings with k-NN"""
        if not self.is_connected or not self.client:
            logger.warning("No OpenSearch client available for vector search")
            return []
            
        try:
            # Use k-NN search
            search_body = {
                "size": limit,
                "query": {
                    "knn": {
                        "embedding": {
                            "vector": query_vector,
                            "k": limit
                        }
                    }
                }
            }
            
            response = self.client.search(
                index=self.index_name,
                body=search_body
            )
            
            results = []
            for hit in response['hits']['hits']:
                result = hit['_source']
                result['vector_score'] = hit['_score']
                result['doc_id'] = hit['_id']
                results.append(result)
            
            logger.debug("OpenSearch vector search completed", 
                        vector_dim=len(query_vector), 
                        results_count=len(results))
            
            return results
            
        except Exception as e:
            logger.error("OpenSearch vector search failed", error=str(e))
            return []
    
    async def get_attack_stats(self, ip_address: str) -> Dict[str, Any]:
        """Get statistics about attacks involving an IP address using aggregations"""
        if not self.is_connected or not self.client:
            return {"error": "No OpenSearch client available"}
            
        try:
            # Use aggregations for efficient statistics
            search_body = {
                "size": 0,  # Don't return documents, just aggregations
                "query": {
                    "bool": {
                        "should": [
                            {"term": {"source_ip": ip_address}},
                            {"term": {"dest_ip": ip_address}}
                        ]
                    }
                },
                "aggs": {
                    "attack_types": {
                        "terms": {"field": "attack_type", "size": 50}
                    },
                    "severity_levels": {
                        "terms": {"field": "severity_level", "size": 10}
                    },
                    "most_recent": {
                        "max": {"field": "timestamp"}
                    },
                    "avg_anomaly_score": {
                        "avg": {"field": "anomaly_score"}
                    },
                    "is_source": {
                        "filter": {"term": {"source_ip": ip_address}}
                    },
                    "is_destination": {
                        "filter": {"term": {"dest_ip": ip_address}}
                    }
                }
            }
            
            response = self.client.search(
                index=self.index_name,
                body=search_body
            )
            
            aggs = response['aggregations']
            total_attacks = response['hits']['total']['value']
            
            # Process attack types
            attack_types = {}
            for bucket in aggs['attack_types']['buckets']:
                attack_types[bucket['key']] = bucket['doc_count']
            
            # Process severity levels
            severity_levels = {}
            for bucket in aggs['severity_levels']['buckets']:
                severity_levels[bucket['key']] = bucket['doc_count']
            
            # Calculate risk score
            high_severity = attack_types.get('Critical', 0) + attack_types.get('High', 0)
            avg_anomaly = aggs['avg_anomaly_score']['value'] or 0
            risk_score = min(100, total_attacks * 5 + high_severity * 20 + avg_anomaly * 10)
            
            return {
                "ip": ip_address,
                "total_attacks": total_attacks,
                "attack_types": attack_types,
                "severity_levels": severity_levels,
                "most_recent": aggs['most_recent']['value_as_string'] if aggs['most_recent']['value'] else None,
                "risk_score": int(risk_score),
                "avg_anomaly_score": avg_anomaly,
                "is_source": aggs['is_source']['doc_count'] > 0,
                "is_destination": aggs['is_destination']['doc_count'] > 0
            }
            
        except Exception as e:
            logger.error("OpenSearch attack stats failed", ip=ip_address, error=str(e))
            return {"error": str(e)}
    
    async def index_document(self, document: Dict[str, Any], doc_id: str = None) -> bool:
        """Index a single document"""
        try:
            if not self.is_connected or not self.client:
                return False
            
            # Generate doc ID if not provided
            if not doc_id:
                doc_id = hashlib.md5(json.dumps(document, sort_keys=True).encode()).hexdigest()
            
            # Add indexing timestamp
            document['indexed_at'] = "now"
            
            response = self.client.index(
                index=self.index_name,
                id=doc_id,
                body=document
            )
            
            return response['result'] in ['created', 'updated']
            
        except Exception as e:
            logger.error(f"OpenSearch document indexing failed: {e}")
            return False
    
    async def bulk_index(self, documents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Bulk index multiple documents"""
        try:
            if not self.is_connected or not self.client:
                return {"success": False, "error": "No OpenSearch client available"}
            
            # Prepare bulk operations
            bulk_body = []
            for i, doc in enumerate(documents):
                # Add indexing timestamp
                doc['indexed_at'] = "now"
                
                # Generate doc ID
                doc_id = doc.get('id') or f"doc_{i}_{hashlib.md5(json.dumps(doc, sort_keys=True).encode()).hexdigest()[:8]}"
                
                # Add index operation
                bulk_body.append({
                    "index": {
                        "_index": self.index_name,
                        "_id": doc_id
                    }
                })
                bulk_body.append(doc)
            
            # Perform bulk operation
            response = self.client.bulk(body=bulk_body)
            
            # Count successes and failures
            successful = 0
            failed = 0
            errors = []
            
            for item in response['items']:
                if item['index']['status'] in [200, 201]:
                    successful += 1
                else:
                    failed += 1
                    errors.append(item['index'].get('error', 'Unknown error'))
            
            return {
                "success": True,
                "total_documents": len(documents),
                "successful": successful,
                "failed": failed,
                "errors": errors[:10]  # Limit error list
            }
            
        except Exception as e:
            logger.error(f"OpenSearch bulk indexing failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def delete_document(self, doc_id: str) -> bool:
        """Delete a document by ID"""
        try:
            if not self.is_connected or not self.client:
                return False
            
            response = self.client.delete(
                index=self.index_name,
                id=doc_id
            )
            
            return response['result'] == 'deleted'
            
        except Exception as e:
            logger.error(f"OpenSearch document deletion failed: {e}")
            return False
    
    async def health_check(self) -> Dict[str, Any]:
        """Check the health status of OpenSearch"""
        try:
            if not self.is_connected or not self.client:
                return {"status": "disconnected"}
            
            # Check cluster health
            cluster_health = self.client.cluster.health()
            
            # Check index statistics
            index_stats = {}
            if self.client.indices.exists(index=self.index_name):
                stats = self.client.indices.stats(index=self.index_name)
                index_stats = {
                    "document_count": stats['_all']['total']['docs']['count'],
                    "size_in_bytes": stats['_all']['total']['store']['size_in_bytes']
                }
            
            return {
                "status": "healthy",
                "cluster_status": cluster_health['status'],
                "cluster_name": cluster_health['cluster_name'],
                "index": self.index_name,
                "index_stats": index_stats,
                "host": self.host,
                "port": self.port
            }
                
        except Exception as e:
            logger.error(f"OpenSearch health check failed: {e}")
            return {"status": "error", "error": str(e)}
    
    async def search_complex(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Perform complex search with custom OpenSearch query"""
        try:
            if not self.is_connected or not self.client:
                return []
            
            response = self.client.search(
                index=self.index_name,
                body=query
            )
            
            results = []
            for hit in response['hits']['hits']:
                result = hit['_source']
                result['search_score'] = hit['_score']
                result['doc_id'] = hit['_id']
                results.append(result)
            
            return results
            
        except Exception as e:
            logger.error(f"OpenSearch complex search failed: {e}")
            return []