# Milvus client to store embeddings of logs
from pymilvus import connections, Collection, utility, FieldSchema, CollectionSchema, DataType

def init_milvus():
    connections.connect(host='localhost', port='19530')
    if not utility.has_collection("log_vectors"):
        fields = [
            FieldSchema(name="id", dtype=DataType.INT64, is_primary=True, auto_id=True),
            FieldSchema(name="embedding", dtype=DataType.FLOAT_VECTOR, dim=384)
        ]
        schema = CollectionSchema(fields, "Log vector index")
        Collection("log_vectors", schema)
