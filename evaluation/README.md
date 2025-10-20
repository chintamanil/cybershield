# CyberShield Evaluation Infrastructure

Production-grade evaluation system for RAG retrieval quality assessment and citation validation.

---

## 🚀 Quick Start

### 1. Generate Golden Dataset

```bash
python evaluation/golden_sets/generate_golden_set.py
```

**Output**: `evaluation/golden_sets/threat_intel_queries.jsonl` (113 queries)

### 2. Run Evaluation Harness

```bash
# Ensure Milvus is running
docker-compose up -d milvus

# Run evaluation
python evaluation/harness/eval_harness.py
```

**Output**:
- `evaluation/reports/eval_report.html` - Visual dashboard
- `evaluation/reports/eval_report.json` - Machine-readable results
- Exit code: 0 (pass) or 1 (fail) based on quality gates

### 3. Test Citation Validator

```bash
python evaluation/validators/citation_validator.py
```

**Output**: Example validation with metrics and warnings

---

## 📂 Directory Structure

```
evaluation/
├── README.md                           # This file
├── IMPLEMENTATION_SUMMARY.md           # Detailed implementation docs
│
├── golden_sets/                        # Golden datasets for evaluation
│   ├── generate_golden_set.py         # Dataset generation script
│   └── threat_intel_queries.jsonl     # 113 query-passage pairs
│
├── metrics/                            # Retrieval metrics
│   ├── __init__.py
│   └── retrieval_metrics.py           # Recall@k, Precision@k, MRR, NDCG, F1
│
├── harness/                            # Evaluation harness
│   ├── __init__.py
│   └── eval_harness.py                # Quality gates, HTML reports
│
├── validators/                         # Citation & faithfulness validators
│   ├── __init__.py
│   └── citation_validator.py          # Citation compliance, hallucination detection
│
└── reports/                            # Auto-generated reports
    ├── eval_report.html               # (generated)
    └── eval_report.json               # (generated)
```

---

## 📊 Available Metrics

### Retrieval Metrics (`evaluation/metrics/retrieval_metrics.py`)

```python
from evaluation.metrics import (
    recall_at_k,
    precision_at_k,
    mean_reciprocal_rank,
    ndcg_at_k,
    f1_at_k,
    evaluate_retrieval,
    batch_evaluate
)

# Single query evaluation
metrics = evaluate_retrieval(
    retrieved=['doc_1', 'doc_2', 'doc_3'],
    relevant=['doc_1', 'doc_4'],
    k_values=[1, 3, 5, 10]
)

# Batch evaluation
aggregate = batch_evaluate(
    results=[
        {"retrieved": [...], "relevant": [...]},
        {"retrieved": [...], "relevant": [...]}
    ],
    k_values=[1, 3, 5, 10]
)
```

**Available Metrics**:
- `recall@k` - Fraction of relevant docs in top-k
- `precision@k` - Fraction of top-k that are relevant
- `mrr` - Mean Reciprocal Rank
- `ndcg@k` - Normalized Discounted Cumulative Gain
- `f1@k` - Harmonic mean of precision and recall

---

## ✅ Citation Validation

### Basic Citation Validation

```python
from evaluation.validators import validate_citations

answer = "The IP is malicious [doc_123] and part of botnet [doc_456]."
passages = [
    {"id": "doc_123", "text": "IP 192.168.1.100 detected in attack"},
    {"id": "doc_456", "text": "Botnet activity observed"}
]

result = validate_citations(answer, passages)

print(f"Valid citations: {result['valid_citations']}")
print(f"Compliance: {result['citation_compliance']:.2%}")
print(f"Passed: {result['validation_passed']}")
```

### Comprehensive Validation (Recommended)

```python
from evaluation.validators import comprehensive_validation

result = comprehensive_validation(answer, passages)

# Check all validation aspects
print(f"Citations: {result['citations']['validation_passed']}")
print(f"Coverage: {result['coverage']['coverage_passed']}")
print(f"Hallucination: {result['hallucination']['has_hallucination']}")
print(f"Overall: {result['overall_passed']}")
print(f"Confidence: {result['confidence_score']:.2f}")
```

### Hallucination Detection

```python
from evaluation.validators import detect_hallucination

result = detect_hallucination(answer, passages, strict_mode=True)

if result['has_hallucination']:
    print(f"⚠️ Hallucination score: {result['hallucination_score']:.2f}")
    print(f"Invalid citations: {result['invalid_citations']}")
    print(f"Uncited claims: {result['uncited_claims']}")
```

---

## 🎯 Quality Gates

Default quality gates in `eval_harness.py`:

```python
gates = {
    "recall@5": 0.90,              # 90% of relevant docs in top-5
    "precision@5": 0.70,           # 70% of top-5 are relevant
    "mrr": 0.80,                   # Mean reciprocal rank ≥ 0.80
    "min_category_recall@5": 0.85  # All categories ≥ 85% recall
}
```

**Custom Gates**:

```python
from evaluation.harness import EvalHarness

harness = EvalHarness()
harness.load_golden_set()
await harness.connect_vector_store()

report = await harness.evaluate_retrieval()

# Custom quality gates
custom_gates = {
    "recall@3": 0.95,
    "precision@3": 0.80,
    "mrr": 0.85
}

passed = harness.check_quality_gates(report, gates=custom_gates)
```

---

## 📈 Golden Dataset

### Dataset Statistics

- **Total Queries**: 113
- **Categories**: 9
- **Average Passages per Query**: 30-50
- **Data Source**: 40,000 cybersecurity attack records

### Query Categories

1. **IP Reputation** (30) - "What attacks involved IP 192.168.1.100?"
2. **Attack Type** (9) - "Find all Malware attacks"
3. **Severity** (12) - "Show High severity attacks"
4. **Protocol** (3) - "Find TCP protocol attacks"
5. **Port Scan** (10) - "Find attacks on port 443"
6. **Geo-location** (10) - "Find attacks from Mumbai"
7. **Malware IoC** (10) - "Find attacks with IoC detected"
8. **Attack Signature** (10) - "Find attacks matching Known Pattern A"
9. **Combined** (19) - "Show High severity DDoS attacks"

### Regenerate Dataset

```bash
# Regenerate with default settings
python evaluation/golden_sets/generate_golden_set.py

# Custom generation (edit script parameters)
# QUERY_CATEGORIES["ip_reputation"]["count"] = 50  # Increase IP queries
```

---

## 🔧 Integration

### ReAct Workflow Integration

```python
# workflows/react_workflow.py
from evaluation.validators import comprehensive_validation

async def synthesize_final_answer(state: State) -> Dict:
    final_answer = llm.generate(...)

    # Validate citations
    validation = comprehensive_validation(
        answer=final_answer,
        retrieved_passages=state["retrieved_passages"]
    )

    if not validation["overall_passed"]:
        logger.warning("citation_validation_failed",
                      confidence=validation["confidence_score"])

    return {
        "final_answer": final_answer,
        "validation": validation
    }
```

### API Endpoint Integration

```python
# server/main.py
from evaluation.validators import validate_citations

@app.post("/analyze")
async def analyze(request: AnalyzeRequest):
    result = await supervisor.process(request.text)

    # Add citation validation to response
    if result.get("answer") and result.get("retrieved_passages"):
        validation = validate_citations(
            answer=result["answer"],
            retrieved_passages=result["retrieved_passages"]
        )
        result["citation_validation"] = validation

    return result
```

### CI/CD Integration

```yaml
# .github/workflows/eval.yml
name: Retrieval Quality Check
on: [push, pull_request]

jobs:
  evaluate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Start Milvus
        run: docker-compose up -d milvus
      - name: Run Evaluation
        run: python evaluation/harness/eval_harness.py
      - name: Upload Report
        uses: actions/upload-artifact@v2
        with:
          name: eval-report
          path: evaluation/reports/
```

---

## 📊 Example Reports

### Console Output

```
============================================================
Evaluation Complete
============================================================
Total Queries: 113

Aggregate Metrics:
  recall@1            : 0.950
  recall@3            : 0.970
  recall@5            : 0.985
  precision@1         : 0.850
  precision@5         : 0.720
  mrr                 : 0.890
  f1@5                : 0.795

✅ All quality gates PASSED
```

### HTML Report

Auto-generated at `evaluation/reports/eval_report.html`:
- Summary statistics
- Aggregate metrics table
- Per-category breakdown
- Visual indicators for pass/fail

### JSON Report

Machine-readable format at `evaluation/reports/eval_report.json`:

```json
{
  "timestamp": "2025-10-20T14:45:00",
  "total_queries": 113,
  "aggregate_metrics": {
    "recall@5": 0.985,
    "precision@5": 0.720,
    "mrr": 0.890
  },
  "category_metrics": {
    "ip_reputation": {
      "recall@5": 0.990,
      "precision@5": 0.750
    }
  }
}
```

---

## 🐛 Troubleshooting

### Issue: "Failed to connect to Milvus"

**Solution**:
```bash
# Check if Milvus is running
docker-compose ps milvus

# Start Milvus
docker-compose up -d milvus

# Wait for initialization
sleep 10

# Verify connection
python -c "from pymilvus import connections; connections.connect(host='localhost', port='19530')"
```

### Issue: "Collection not found"

**Solution**:
```bash
# Run data ingestion to create collection
python data/milvus_ingestion.py

# Verify collection exists
python -c "from pymilvus import utility, connections; connections.connect(host='localhost', port='19530'); print(utility.list_collections())"
```

### Issue: "No module named 'evaluation'"

**Solution**:
```bash
# Add evaluation to pyproject.toml packages
# packages = ["agents", "tools", ..., "evaluation"]

# Reinstall package
uv pip install -e .
```

---

## 📚 References

- **RAG Best Practices**: `docs/RAG_ANALYSIS_AND_ENHANCEMENTS.md`
- **Implementation Summary**: `evaluation/IMPLEMENTATION_SUMMARY.md`
- **Retrieval Metrics**: [Information Retrieval Metrics](https://en.wikipedia.org/wiki/Evaluation_measures_(information_retrieval))
- **Citation Validation**: [Faithfulness in RAG Systems](https://arxiv.org/abs/2312.10997)

---

## 🎓 Advanced Usage

### Custom Metrics

```python
from evaluation.metrics.retrieval_metrics import evaluate_retrieval

# Evaluate with custom k values
metrics = evaluate_retrieval(
    retrieved=results,
    relevant=ground_truth,
    k_values=[1, 5, 10, 20, 50]  # Custom k values
)
```

### Category-Specific Evaluation

```python
from evaluation.harness import EvalHarness

harness = EvalHarness()
harness.load_golden_set()

# Filter by category
ip_queries = [q for q in harness.golden_queries if q['category'] == 'ip_reputation']

# Evaluate specific category
# ... custom evaluation logic ...
```

### Batch Processing with Progress

```python
from tqdm import tqdm

for query in tqdm(golden_queries, desc="Evaluating"):
    metrics = evaluate_retrieval(...)
    # Process metrics
```

---

**Version**: 1.0
**Last Updated**: October 20, 2025
**Maintainer**: CyberShield Team
