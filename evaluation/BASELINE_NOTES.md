# Baseline Metrics Implementation Notes

**Status**: Evaluation infrastructure complete, baseline testing requires vector search integration

---

## Current Limitation

The `eval_harness.py` currently contains a **placeholder implementation** for retrieval evaluation:

```python
# evaluation/harness/eval_harness.py (lines 142-143)
# For now, assume perfect retrieval for demonstration
retrieved_passages = expected_passages[:10]  # Top 10
```

This simulates **perfect retrieval** where:
- Retrieved results = Expected results
- Recall@k = 1.0 (100%)
- Precision@k = 1.0 (100%)
- MRR = 1.0

**This is NOT a true baseline** - it's infrastructure testing only.

---

## To Run True Baseline Metrics

### Step 1: Implement Vector Embeddings

The golden dataset queries need to be converted to vector embeddings for Milvus similarity search.

**Required Changes**:

```python
# evaluation/harness/eval_harness.py

from sentence_transformers import SentenceTransformer

class EvalHarness:
    def __init__(self, ...):
        # Add embedding model
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')

    async def evaluate_retrieval(self, ...):
        for golden_query in queries_to_eval:
            query_text = golden_query['query']
            expected_passages = golden_query['relevant_passages']

            # Generate query embedding
            query_embedding = self.embedding_model.encode(query_text)

            # Perform actual vector search in Milvus
            search_params = {"metric_type": "L2", "params": {"nprobe": 10}}
            results = self.vector_store.collection.search(
                data=[query_embedding],
                anns_field="embedding",
                param=search_params,
                limit=10,
                output_fields=["id"]
            )

            # Extract retrieved document IDs
            retrieved_passages = [f"doc_{hit.id}" for hit in results[0]]

            # Now compute real metrics
            metrics = evaluate_retrieval(
                retrieved=retrieved_passages,
                relevant=expected_passages,
                k_values=k_values
            )
```

### Step 2: Ensure Milvus Collection Has Embeddings

The `cybersecurity_attacks` collection must have:
1. Vector embeddings for each record
2. An embedding field configured for similarity search
3. Proper index (IVF_FLAT or HNSW)

**Check Current Collection**:
```python
from pymilvus import connections, Collection

connections.connect(host='localhost', port='19530')
collection = Collection("cybersecurity_attacks")
print(collection.schema)  # Check if 'embedding' field exists
```

If embeddings don't exist, run:
```bash
# Re-run data ingestion with embeddings
python data/milvus_ingestion.py
```

### Step 3: Run Baseline Evaluation

```bash
# 1. Start Milvus
docker-compose up -d milvus

# 2. Ensure data is loaded
python data/milvus_ingestion.py

# 3. Run evaluation
python evaluation/harness/eval_harness.py
```

**Expected Output** (realistic baseline):
```
Aggregate Metrics:
  recall@1            : 0.450
  recall@5            : 0.720
  precision@1         : 0.450
  precision@5         : 0.144
  mrr                 : 0.620
```

---

## Why Baseline Metrics Matter

### Current State (Placeholder)
- Recall@5: 1.0 (100%) ← **Fake**
- No actual search happening
- Can't measure real system performance

### With True Baseline
- Recall@5: ~0.60-0.80 (realistic)
- Identifies retrieval quality issues
- Sets improvement targets

### Quality Gates Impact

**Current gates** will ALWAYS pass with placeholder:
```python
gates = {
    "recall@5": 0.90,    # ✅ Always passes (returns 1.0)
    "precision@5": 0.70, # ✅ Always passes (returns 1.0)
    "mrr": 0.80          # ✅ Always passes (returns 1.0)
}
```

**With real baseline**, gates will:
- Detect regressions in retrieval quality
- Block deployments with poor performance
- Track improvements over time

---

## Quick Win: Simulated Baseline

If you want to test the evaluation infrastructure **without** Milvus:

```python
# evaluation/harness/eval_harness.py

# Simulate realistic (imperfect) retrieval
import random

# Instead of:
retrieved_passages = expected_passages[:10]

# Use:
# Simulate 70% recall by randomly selecting some expected + some random
expected_sample = random.sample(expected_passages, k=min(7, len(expected_passages)))
random_docs = [f"doc_{random.randint(0, 40000)}" for _ in range(3)]
retrieved_passages = (expected_sample + random_docs)[:10]
```

This simulates:
- Recall@5: ~0.70
- Precision@5: ~0.70
- MRR: ~0.60

**Still not real**, but tests the evaluation pipeline with realistic scores.

---

## Action Items for True Baseline

- [ ] Add embedding generation to `eval_harness.py`
- [ ] Verify Milvus collection has `embedding` field
- [ ] Implement vector similarity search in evaluation
- [ ] Run baseline evaluation and document results
- [ ] Set quality gate thresholds based on baseline
- [ ] Track metrics over time in CI/CD

**Estimated Time**: 2-3 hours

---

**Status**: Infrastructure ✅ | Baseline Testing ⏳ Requires vector search integration

**Last Updated**: October 20, 2025
