# Milvus client to store embeddings of logs and search for threats
from typing import Any

from pymilvus import (
    Collection,
    CollectionSchema,
    DataType,
    FieldSchema,
    connections,
    utility,
)

from utils.device_config import create_performance_config
from utils.logging_config import get_security_logger

logger = get_security_logger('milvus_client')


class CyberShieldVectorStore:
    """Enhanced vector store client for cybersecurity threat intelligence"""

    def __init__(self, collection_name: str = 'cybersecurity_attacks'):
        self.collection_name = collection_name
        self.collection = None
        self.perf_config = create_performance_config()

    def _get_search_params(self, collection_size: int) -> dict:
        """
        Get optimized search parameters based on collection size.

        Dynamically adjusts nprobe parameter for optimal balance between
        search accuracy and performance based on the collection size.

        Args:
            collection_size: Number of documents in collection

        Returns:
            Optimized search parameters for Milvus
        """
        # Increase nprobe for larger collections (balance speed vs accuracy)
        if collection_size > 100000:
            nprobe = 20  # High accuracy for large collections
        elif collection_size > 50000:
            nprobe = 15  # Balanced for medium collections
        else:
            nprobe = 10  # Fast for small collections

        return {
            'metric_type': 'IP',  # Inner Product (good for normalized embeddings)
            'params': {
                'nprobe': nprobe,  # Number of clusters to search
            },
        }

    async def connect(self):
        """Connect to Milvus and initialize collection"""
        try:
            logger.info('Connecting to Milvus', host='localhost', port=19530)
            connections.connect(host='localhost', port='19530')

            if utility.has_collection(self.collection_name):
                self.collection = Collection(self.collection_name)
                self.collection.load()  # Load collection into memory
                logger.info(
                    'Connected to existing collection',
                    collection=self.collection_name,
                    count=self.collection.num_entities,
                )
            else:
                logger.warning('Collection not found', collection=self.collection_name)
                self.collection = None

        except Exception as e:
            logger.error('Milvus connection failed', error=str(e))
            self.collection = None

    async def search_by_ip(
        self, ip_address: str, limit: int = 10
    ) -> list[dict[str, Any]]:
        """
        Search for historical attacks involving a specific IP address

        Args:
            ip_address: IP to search for (as source or destination)
            limit: Maximum number of results to return

        Returns:
            List of matching attack records
        """
        if not self.collection:
            logger.warning('No collection available for search')
            return []

        try:
            # Search for IP as both source and destination
            filter_expr = f'source_ip == "{ip_address}" || dest_ip == "{ip_address}"'

            # Query the collection
            results = self.collection.query(
                expr=filter_expr,
                output_fields=[
                    'id',
                    'timestamp',
                    'source_ip',
                    'dest_ip',
                    'source_port',
                    'dest_port',
                    'protocol',
                    'attack_type',
                    'attack_signature',
                    'severity_level',
                    'action_taken',
                    'anomaly_score',
                    'malware_indicators',
                    'geo_location',
                    'log_source',
                ],
                limit=limit,
            )

            logger.debug(
                'Vector search completed',
                ip=ip_address,
                results_count=len(results),
                limit=limit,
            )

            return results

        except Exception as e:
            logger.error('Vector search failed', ip=ip_address, error=str(e))
            return []

    async def search_similar_attacks(
        self,
        query_embedding: list[float],
        limit: int = 10,
        filter_expr: str | None = None,
        initial_limit: int | None = None,
        min_similarity: float = 0.3,
    ) -> list[dict[str, Any]]:
        """
        Search for similar attacks using vector similarity with optional filtering

        Implements three key optimizations:
        1. Over-fetching: Retrieves more candidates than needed for better recall
        2. Adaptive search params: Tunes nprobe based on collection size
        3. Similarity filtering: Removes low-relevance results for better precision

        Args:
            query_embedding: Vector embedding of the query text
            limit: Maximum number of results to return to user
            filter_expr: Optional Milvus filter expression for hybrid search
            initial_limit: Number of candidates to retrieve before filtering
                           (default: limit * 3 for better recall)
            min_similarity: Minimum similarity score threshold (0.0-1.0)
                           for Inner Product metric (default: 0.3)

        Returns:
            List of similar attack records with similarity scores above threshold
        """
        if not self.collection:
            logger.warning('No collection available for similarity search')
            return []

        try:
            # Optimization 1: Over-fetch candidates for better recall
            # Fetch 3x more results, then filter and return top-k
            fetch_limit = initial_limit or (limit * 3)

            # Optimization 2: Adaptive search parameters based on collection size
            collection_size = self.collection.num_entities
            search_params = self._get_search_params(collection_size)

            logger.debug(
                'Starting vector search',
                limit=limit,
                fetch_limit=fetch_limit,
                collection_size=collection_size,
                nprobe=search_params['params']['nprobe'],
                min_similarity=min_similarity,
            )

            # Execute vector similarity search with optional filtering
            results = self.collection.search(
                data=[query_embedding],
                anns_field='embedding',
                param=search_params,
                limit=fetch_limit,  # Fetch more for re-ranking
                expr=filter_expr,  # Milvus will filter BEFORE vector search
                output_fields=[
                    'id',
                    'timestamp',
                    'source_ip',
                    'dest_ip',
                    'source_port',
                    'dest_port',
                    'protocol',
                    'attack_type',
                    'attack_signature',
                    'severity_level',
                    'action_taken',
                    'anomaly_score',
                    'malware_indicators',
                    'geo_location',
                    'log_source',
                    'full_context',
                ],
            )

            # Optimization 3: Filter by similarity score and return top-k
            similar_attacks = []
            if results and len(results) > 0:
                for hit in results[0]:
                    similarity = float(hit.score)

                    # Only include results above similarity threshold
                    if similarity >= min_similarity:
                        attack_record = {
                            'id': hit.entity.get('id'),
                            'timestamp': hit.entity.get('timestamp'),
                            'source_ip': hit.entity.get('source_ip'),
                            'dest_ip': hit.entity.get('dest_ip'),
                            'source_port': hit.entity.get('source_port'),
                            'dest_port': hit.entity.get('dest_port'),
                            'protocol': hit.entity.get('protocol'),
                            'attack_type': hit.entity.get('attack_type'),
                            'attack_signature': hit.entity.get('attack_signature'),
                            'severity_level': hit.entity.get('severity_level'),
                            'action_taken': hit.entity.get('action_taken'),
                            'anomaly_score': hit.entity.get('anomaly_score'),
                            'malware_indicators': hit.entity.get('malware_indicators'),
                            'geo_location': hit.entity.get('geo_location'),
                            'log_source': hit.entity.get('log_source'),
                            'full_context': hit.entity.get('full_context'),
                            'similarity_score': similarity,
                        }
                        similar_attacks.append(attack_record)

                        # Stop if we have enough high-quality results
                        if len(similar_attacks) >= limit:
                            break

            logger.debug(
                'Vector similarity search completed',
                fetched_count=len(results[0]) if results and len(results) > 0 else 0,
                filtered_count=len(similar_attacks),
                returned_count=min(len(similar_attacks), limit),
                limit=limit,
            )

            return similar_attacks[:limit]  # Return exactly limit results

        except Exception as e:
            logger.error('Similarity search failed', error=str(e))
            return []

    async def get_attack_stats(self, ip_address: str) -> dict[str, Any]:
        """
        Get statistics about attacks involving an IP address

        Args:
            ip_address: IP to analyze

        Returns:
            Dictionary with attack statistics
        """
        if not self.collection:
            return {'error': 'No collection available'}

        try:
            # Get all records for this IP
            records = await self.search_by_ip(
                ip_address, limit=1000
            )  # Get more for stats

            if not records:
                return {
                    'ip': ip_address,
                    'total_attacks': 0,
                    'attack_types': [],
                    'severity_levels': [],
                    'most_recent': None,
                    'risk_score': 0,
                }

            # Analyze the records
            attack_types = {}
            severity_levels = {}
            timestamps = []

            for record in records:
                # Count attack types
                attack_type = record.get('attack_type', 'unknown')
                attack_types[attack_type] = attack_types.get(attack_type, 0) + 1

                # Count severity levels
                severity = record.get('severity_level', 'unknown')
                severity_levels[severity] = severity_levels.get(severity, 0) + 1

                # Collect timestamps
                if record.get('timestamp'):
                    timestamps.append(record['timestamp'])

            # Calculate risk score based on attack patterns
            risk_score = min(
                100,
                len(records) * 10
                + attack_types.get('Critical', 0) * 30
                + attack_types.get('High', 0) * 20,
            )

            return {
                'ip': ip_address,
                'total_attacks': len(records),
                'attack_types': attack_types,
                'severity_levels': severity_levels,
                'most_recent': max(timestamps) if timestamps else None,
                'risk_score': risk_score,
                'is_source': any(r.get('source_ip') == ip_address for r in records),
                'is_destination': any(r.get('dest_ip') == ip_address for r in records),
            }

        except Exception as e:
            logger.error('Attack stats failed', ip=ip_address, error=str(e))
            return {'error': str(e)}


def init_milvus():
    """Legacy function for backward compatibility"""
    try:
        logger.info('Connecting to Milvus', host='localhost', port=19530)
        connections.connect(host='localhost', port='19530')

        # Try to connect to cybersecurity_attacks collection first
        if utility.has_collection('cybersecurity_attacks'):
            collection = Collection('cybersecurity_attacks')
            logger.info('Using cybersecurity_attacks collection')
        elif utility.has_collection('log_vectors'):
            collection = Collection('log_vectors')
            logger.info('Using log_vectors collection')
        else:
            logger.info(
                'Creating new collection', collection='log_vectors', dimension=384
            )
            fields = [
                FieldSchema(
                    name='id', dtype=DataType.INT64, is_primary=True, auto_id=True
                ),
                FieldSchema(name='embedding', dtype=DataType.FLOAT_VECTOR, dim=384),
            ]
            schema = CollectionSchema(fields, 'Log vector index')
            collection = Collection('log_vectors', schema)
            logger.info('Collection created successfully', collection='log_vectors')

        logger.info(
            'Milvus initialization complete',
            collection=collection.name,
            count=collection.num_entities,
        )
        return collection

    except Exception as e:
        logger.error('Milvus initialization failed', error=str(e))
        raise
