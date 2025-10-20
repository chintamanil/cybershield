"""Evaluation infrastructure for retrieval quality assessment."""

from evaluation.harness.eval_harness import EvalHarness
from evaluation.metrics.retrieval_metrics import (
    batch_evaluate,
    evaluate_retrieval,
    f1_at_k,
    mean_reciprocal_rank,
    ndcg_at_k,
    precision_at_k,
    recall_at_k,
)
from evaluation.validators.citation_validator import (
    comprehensive_validation,
    validate_citations,
)

__all__ = [
    # Harness
    'EvalHarness',
    # Metrics
    'recall_at_k',
    'precision_at_k',
    'mean_reciprocal_rank',
    'ndcg_at_k',
    'f1_at_k',
    'evaluate_retrieval',
    'batch_evaluate',
    # Validators
    'validate_citations',
    'comprehensive_validation',
]
