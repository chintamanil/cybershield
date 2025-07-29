# Milvus client to store embeddings of logs
from pymilvus import connections, Collection, utility, FieldSchema, CollectionSchema, DataType
from utils.logging_config import get_security_logger

logger = get_security_logger("milvus_client")

def init_milvus():
    try:
        logger.info("Connecting to Milvus", host="localhost", port=19530)
        connections.connect(host='localhost', port='19530')
        
        if not utility.has_collection("log_vectors"):
            logger.info("Creating new collection", collection="log_vectors", dimension=384)
            fields = [
                FieldSchema(name="id", dtype=DataType.INT64, is_primary=True, auto_id=True),
                FieldSchema(name="embedding", dtype=DataType.FLOAT_VECTOR, dim=384)
            ]
            schema = CollectionSchema(fields, "Log vector index")
            Collection("log_vectors", schema)
            logger.info("Collection created successfully", collection="log_vectors")
        else:
            logger.info("Using existing collection", collection="log_vectors")
            
        collection = Collection("log_vectors")
        logger.info("Milvus initialization complete", 
                   collection="log_vectors", 
                   count=collection.num_entities)
        return collection
        
    except Exception as e:
        logger.error("Milvus initialization failed", error=str(e))
        raise
