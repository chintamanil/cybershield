"""
Retrieval metrics for evaluating vector search quality.

Implements industry-standard metrics:
- Recall@k: Fraction of relevant documents retrieved in top-k
- Precision@k: Fraction of retrieved documents that are relevant
- MRR (Mean Reciprocal Rank): Average of reciprocal ranks of first relevant document
- NDCG@k: Normalized Discounted Cumulative Gain (position-aware metric)
"""

from typing import Any, Dict, List, Set

from utils.logging_config import get_security_logger

logger = get_security_logger('retrieval_metrics')


def recall_at_k(retrieved: List[str], relevant: List[str], k: int) -> float:
    """
    Calculate Recall@k: fraction of relevant documents found in top-k results.

    Args:
        retrieved: List of retrieved document IDs (ordered by relevance)
        relevant: List of relevant document IDs (ground truth)
        k: Number of top results to consider

    Returns:
        Recall@k score (0.0 to 1.0)

    Example:
        >>> recall_at_k(['doc1', 'doc2', 'doc3'], ['doc1', 'doc4'], k=2)
        0.5  # Found 1 out of 2 relevant docs in top-2
    """
    if not relevant:
        logger.warning('recall_at_k called with empty relevant set')
        return 0.0

    retrieved_set = set(retrieved[:k])
    relevant_set = set(relevant)

    hits = len(retrieved_set & relevant_set)
    recall = hits / len(relevant_set)

    logger.debug(
        'recall_at_k calculated',
        k=k,
        hits=hits,
        total_relevant=len(relevant_set),
        recall=recall,
    )

    return recall


def precision_at_k(retrieved: List[str], relevant: List[str], k: int) -> float:
    """
    Calculate Precision@k: fraction of top-k results that are relevant.

    Args:
        retrieved: List of retrieved document IDs (ordered by relevance)
        relevant: List of relevant document IDs (ground truth)
        k: Number of top results to consider

    Returns:
        Precision@k score (0.0 to 1.0)

    Example:
        >>> precision_at_k(['doc1', 'doc2', 'doc3'], ['doc1', 'doc4'], k=2)
        0.5  # 1 out of 2 retrieved docs is relevant
    """
    if k == 0:
        return 0.0

    retrieved_set = set(retrieved[:k])
    relevant_set = set(relevant)

    hits = len(retrieved_set & relevant_set)
    precision = hits / k

    logger.debug(
        'precision_at_k calculated',
        k=k,
        hits=hits,
        total_retrieved=k,
        precision=precision,
    )

    return precision


def mean_reciprocal_rank(retrieved: List[str], relevant: List[str]) -> float:
    """
    Calculate Mean Reciprocal Rank (MRR): reciprocal of rank of first relevant document.

    MRR rewards systems that rank relevant documents higher. Perfect score is 1.0
    (relevant doc at rank 1), 0.5 (rank 2), 0.33 (rank 3), etc.

    Args:
        retrieved: List of retrieved document IDs (ordered by relevance)
        relevant: List of relevant document IDs (ground truth)

    Returns:
        MRR score (0.0 to 1.0)

    Example:
        >>> mean_reciprocal_rank(['doc2', 'doc1', 'doc3'], ['doc1'])
        0.5  # First relevant doc at position 2, so 1/2 = 0.5
    """
    if not relevant:
        logger.warning('mean_reciprocal_rank called with empty relevant set')
        return 0.0

    relevant_set = set(relevant)

    for rank, doc_id in enumerate(retrieved, start=1):
        if doc_id in relevant_set:
            mrr = 1.0 / rank
            logger.debug(
                'mean_reciprocal_rank calculated',
                first_relevant_rank=rank,
                mrr=mrr,
            )
            return mrr

    # No relevant documents found
    logger.debug('mean_reciprocal_rank calculated', first_relevant_rank=None, mrr=0.0)
    return 0.0


def ndcg_at_k(
    retrieved: List[str],
    relevant: List[str],
    k: int,
    relevance_scores: Dict[str, float] = None,
) -> float:
    """
    Calculate Normalized Discounted Cumulative Gain (NDCG@k).

    NDCG is a position-aware metric that rewards relevant documents ranked higher.
    Uses logarithmic discount factor: gain / log2(rank + 1).

    Args:
        retrieved: List of retrieved document IDs (ordered by relevance)
        relevant: List of relevant document IDs (ground truth)
        k: Number of top results to consider
        relevance_scores: Optional dict mapping doc_id -> relevance score (0.0-1.0)
                         If None, binary relevance is assumed (1.0 for relevant, 0.0 otherwise)

    Returns:
        NDCG@k score (0.0 to 1.0)

    Example:
        >>> ndcg_at_k(['doc1', 'doc2', 'doc3'], ['doc1', 'doc2'], k=3)
        1.0  # Perfect ranking: both relevant docs at top
    """
    import math

    if not relevant or k == 0:
        return 0.0

    relevant_set = set(relevant)

    # Calculate DCG (Discounted Cumulative Gain)
    dcg = 0.0
    for rank, doc_id in enumerate(retrieved[:k], start=1):
        if doc_id in relevant_set:
            # Get relevance score (binary or graded)
            rel_score = relevance_scores.get(doc_id, 1.0) if relevance_scores else 1.0
            dcg += rel_score / math.log2(rank + 1)

    # Calculate IDCG (Ideal DCG) - best possible ranking
    idcg = 0.0
    ideal_ranking = sorted(
        relevant[:k],
        key=lambda doc_id: relevance_scores.get(doc_id, 1.0)
        if relevance_scores
        else 1.0,
        reverse=True,
    )
    for rank, doc_id in enumerate(ideal_ranking, start=1):
        rel_score = relevance_scores.get(doc_id, 1.0) if relevance_scores else 1.0
        idcg += rel_score / math.log2(rank + 1)

    # NDCG = DCG / IDCG
    ndcg = dcg / idcg if idcg > 0 else 0.0

    logger.debug(
        'ndcg_at_k calculated',
        k=k,
        dcg=dcg,
        idcg=idcg,
        ndcg=ndcg,
    )

    return ndcg


def f1_at_k(retrieved: List[str], relevant: List[str], k: int) -> float:
    """
    Calculate F1@k: harmonic mean of precision@k and recall@k.

    F1 score balances precision and recall, useful when both are important.

    Args:
        retrieved: List of retrieved document IDs (ordered by relevance)
        relevant: List of relevant document IDs (ground truth)
        k: Number of top results to consider

    Returns:
        F1@k score (0.0 to 1.0)
    """
    precision = precision_at_k(retrieved, relevant, k)
    recall = recall_at_k(retrieved, relevant, k)

    if precision + recall == 0:
        return 0.0

    f1 = 2 * (precision * recall) / (precision + recall)

    logger.debug(
        'f1_at_k calculated',
        k=k,
        precision=precision,
        recall=recall,
        f1=f1,
    )

    return f1


def evaluate_retrieval(
    retrieved: List[str],
    relevant: List[str],
    k_values: List[int] = [1, 3, 5, 10],
) -> Dict[str, Any]:
    """
    Comprehensive retrieval evaluation across multiple k values.

    Args:
        retrieved: List of retrieved document IDs (ordered by relevance)
        relevant: List of relevant document IDs (ground truth)
        k_values: List of k values to evaluate at (default: [1, 3, 5, 10])

    Returns:
        Dictionary with all metrics:
        {
            'recall@1': float, 'recall@3': float, ...
            'precision@1': float, 'precision@3': float, ...
            'f1@1': float, 'f1@3': float, ...
            'ndcg@1': float, 'ndcg@3': float, ...
            'mrr': float,
            'retrieved_count': int,
            'relevant_count': int
        }
    """
    metrics = {
        'retrieved_count': len(retrieved),
        'relevant_count': len(relevant),
        'mrr': mean_reciprocal_rank(retrieved, relevant),
    }

    for k in k_values:
        metrics[f'recall@{k}'] = recall_at_k(retrieved, relevant, k)
        metrics[f'precision@{k}'] = precision_at_k(retrieved, relevant, k)
        metrics[f'f1@{k}'] = f1_at_k(retrieved, relevant, k)
        metrics[f'ndcg@{k}'] = ndcg_at_k(retrieved, relevant, k)

    logger.info(
        'retrieval_evaluation_complete',
        metrics={
            k: round(v, 3) if isinstance(v, float) else v for k, v in metrics.items()
        },
    )

    return metrics


def batch_evaluate(
    results: List[Dict[str, Any]], k_values: List[int] = [1, 3, 5, 10]
) -> Dict[str, Any]:
    """
    Evaluate multiple retrieval results and compute aggregate metrics.

    Args:
        results: List of dicts with 'retrieved' and 'relevant' keys
                 [{'retrieved': [...], 'relevant': [...]}, ...]
        k_values: List of k values to evaluate at

    Returns:
        Dictionary with averaged metrics across all queries:
        {
            'recall@1': float (mean), 'recall@1_std': float,
            'precision@1': float (mean), 'precision@1_std': float,
            ...
            'mrr': float (mean), 'mrr_std': float,
            'num_queries': int
        }
    """
    import statistics

    if not results:
        logger.warning('batch_evaluate called with empty results')
        return {}

    # Collect all metrics for each query
    all_metrics = []
    for result in results:
        retrieved = result.get('retrieved', [])
        relevant = result.get('relevant', [])
        metrics = evaluate_retrieval(retrieved, relevant, k_values)
        all_metrics.append(metrics)

    # Compute mean and std for each metric
    aggregated = {'num_queries': len(results)}

    # Get all metric keys (excluding counts)
    metric_keys = [
        k
        for k in all_metrics[0].keys()
        if k not in ['retrieved_count', 'relevant_count']
    ]

    for key in metric_keys:
        values = [m[key] for m in all_metrics]
        aggregated[key] = statistics.mean(values)
        if len(values) > 1:
            aggregated[f'{key}_std'] = statistics.stdev(values)
        else:
            aggregated[f'{key}_std'] = 0.0

    logger.info(
        'batch_evaluation_complete',
        num_queries=len(results),
        avg_metrics={
            k: round(v, 3) if isinstance(v, float) else v
            for k, v in aggregated.items()
            if not k.endswith('_std')
        },
    )

    return aggregated
