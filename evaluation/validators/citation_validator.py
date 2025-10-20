"""
Citation Validator for RAG Faithfulness.

Validates that LLM-generated answers cite retrieved passages correctly.
Enforces citation compliance and detects hallucinations.
"""

import re
from typing import Any, Dict, List

from utils.logging_config import get_security_logger

logger = get_security_logger('citation_validator')


def validate_citations(answer: str, retrieved_passages: List[Dict]) -> Dict[str, Any]:
    """
    Validate that answer cites retrieved passages.

    Args:
        answer: LLM-generated answer with [doc_XXX] citations
        retrieved_passages: List of {"id": "doc_123", "text": "..."}

    Returns:
        {
            "has_citations": bool,
            "citation_count": int,
            "valid_citations": int,
            "invalid_citations": int,
            "citation_compliance": float,
            "cited_passages": List[str],
            "uncited_passages": List[str],
            "validation_passed": bool
        }
    """
    # Extract citations from answer
    citation_pattern = r'\[doc_(\d+)\]'
    citations = re.findall(citation_pattern, answer)
    cited_ids = {f'doc_{c}' for c in citations}

    # Get retrieved passage IDs
    retrieved_ids = {p['id'] for p in retrieved_passages}

    # Check validity
    valid_citations = cited_ids & retrieved_ids
    invalid_citations = cited_ids - retrieved_ids
    uncited_passages = retrieved_ids - cited_ids

    # Calculate compliance
    has_citations = len(citations) > 0
    citation_compliance = len(valid_citations) / len(citations) if citations else 0.0

    # Validation passes if:
    # 1. Answer has at least one citation
    # 2. All citations are valid (no hallucinated citations)
    # 3. Citation compliance >= 0.80
    validation_passed = (
        has_citations and len(invalid_citations) == 0 and citation_compliance >= 0.80
    )

    result = {
        'has_citations': has_citations,
        'citation_count': len(citations),
        'valid_citations': len(valid_citations),
        'invalid_citations': list(invalid_citations),  # Return list, not count
        'citation_compliance': citation_compliance,
        'cited_passages': list(valid_citations),
        'uncited_passages': list(uncited_passages),
        'validation_passed': validation_passed,
    }

    logger.info(
        'citation_validation',
        has_citations=has_citations,
        citation_count=len(citations),
        compliance=citation_compliance,
        validation_passed=validation_passed,
    )

    if invalid_citations:
        logger.warning(
            'invalid_citations_detected',
            invalid=list(invalid_citations),
            count=len(invalid_citations),
        )

    if len(uncited_passages) > len(cited_ids):
        logger.warning(
            'many_uncited_passages',
            uncited_count=len(uncited_passages),
            cited_count=len(cited_ids),
        )

    return result


def enforce_citation_format(answer: str) -> str:
    """
    Enforce proper citation format in answer.

    Normalizes various citation formats to standard [doc_XXX] format.

    Args:
        answer: LLM-generated answer with potentially inconsistent citations

    Returns:
        Answer with normalized citation format
    """
    # Normalize various formats
    # [Document 123] -> [doc_123]
    answer = re.sub(r'\[Document\s+(\d+)\]', r'[doc_\1]', answer, flags=re.IGNORECASE)

    # (doc 123) -> [doc_123]
    answer = re.sub(r'\(doc\s+(\d+)\)', r'[doc_\1]', answer, flags=re.IGNORECASE)

    # [source_123] -> [doc_123]
    answer = re.sub(r'\[source_(\d+)\]', r'[doc_\1]', answer, flags=re.IGNORECASE)

    # [ref123] -> [doc_123]
    answer = re.sub(r'\[ref(\d+)\]', r'[doc_\1]', answer, flags=re.IGNORECASE)

    logger.debug('citation_format_enforced')

    return answer


def add_missing_citations(
    answer: str, retrieved_passages: List[Dict], min_citations: int = 1
) -> str:
    """
    Add citations to answer if missing.

    Args:
        answer: LLM-generated answer without citations
        retrieved_passages: List of {"id": "doc_123", "text": "..."}
        min_citations: Minimum number of citations to add

    Returns:
        Answer with added citations
    """
    # Check if already has citations
    citation_pattern = r'\[doc_(\d+)\]'
    existing_citations = re.findall(citation_pattern, answer)

    if len(existing_citations) >= min_citations:
        logger.debug('answer_has_sufficient_citations', count=len(existing_citations))
        return answer

    # Add citations from top retrieved passages
    citations_to_add = min(
        min_citations - len(existing_citations), len(retrieved_passages)
    )

    if citations_to_add > 0:
        citation_text = ' '.join(
            [f'[{retrieved_passages[i]["id"]}]' for i in range(citations_to_add)]
        )
        answer = f'{answer} {citation_text}'

        logger.info(
            'citations_added',
            added_count=citations_to_add,
            total_citations=citations_to_add + len(existing_citations),
        )

    return answer


def validate_answer_coverage(
    answer: str, retrieved_passages: List[Dict], min_coverage: float = 0.5
) -> Dict[str, Any]:
    """
    Validate that answer covers content from retrieved passages.

    Args:
        answer: LLM-generated answer
        retrieved_passages: List of {"id": "doc_123", "text": "..."}
        min_coverage: Minimum fraction of passages that should be referenced

    Returns:
        {
            "coverage": float,
            "covered_passages": int,
            "total_passages": int,
            "coverage_passed": bool
        }
    """
    # Extract citations
    citation_pattern = r'\[doc_(\d+)\]'
    cited_ids = set(re.findall(citation_pattern, answer))

    # Calculate coverage
    total_passages = len(retrieved_passages)
    covered_passages = sum(
        1 for p in retrieved_passages if p['id'].replace('doc_', '') in cited_ids
    )

    coverage = covered_passages / total_passages if total_passages > 0 else 0.0
    coverage_passed = coverage >= min_coverage

    result = {
        'coverage': coverage,
        'covered_passages': covered_passages,
        'total_passages': total_passages,
        'coverage_passed': coverage_passed,
    }

    logger.info(
        'answer_coverage_validation',
        coverage=coverage,
        covered=covered_passages,
        total=total_passages,
        passed=coverage_passed,
    )

    return result


def detect_hallucination(
    answer: str,
    retrieved_passages: List[Dict],
    strict_mode: bool = True,
) -> Dict[str, Any]:
    """
    Detect potential hallucinations in answer.

    Args:
        answer: LLM-generated answer with citations
        retrieved_passages: List of {"id": "doc_123", "text": "..."}
        strict_mode: If True, require all claims to be cited

    Returns:
        {
            "has_hallucination": bool,
            "invalid_citations": List[str],
            "uncited_claims": int,
            "hallucination_score": float (0.0 = no hallucination, 1.0 = high hallucination)
        }
    """
    # Validate citations
    validation = validate_citations(answer, retrieved_passages)

    # Hallucination indicators
    has_invalid_citations = len(validation['invalid_citations']) > 0
    low_citation_compliance = validation['citation_compliance'] < 0.80

    # Count sentences without citations (potential uncited claims)
    sentences = re.split(r'[.!?]+', answer)
    sentences = [s.strip() for s in sentences if s.strip()]

    uncited_sentences = 0
    for sentence in sentences:
        if not re.search(r'\[doc_\d+\]', sentence):
            uncited_sentences += 1

    uncited_claim_ratio = uncited_sentences / len(sentences) if sentences else 0.0

    # Hallucination score
    # Weighted combination of invalid citations and uncited claims
    hallucination_score = (
        0.5
        * (len(validation['invalid_citations']) / max(1, validation['citation_count']))
        + 0.5 * uncited_claim_ratio
    )

    # Determine if hallucination detected
    has_hallucination = has_invalid_citations or (
        strict_mode and uncited_claim_ratio > 0.3
    )

    result = {
        'has_hallucination': has_hallucination,
        'invalid_citations': validation['invalid_citations'],
        'uncited_claims': uncited_sentences,
        'hallucination_score': hallucination_score,
        'confidence': 1.0 - hallucination_score,
    }

    logger.info(
        'hallucination_detection',
        has_hallucination=has_hallucination,
        score=hallucination_score,
        invalid_citations=len(validation['invalid_citations']),
        uncited_claims=uncited_sentences,
    )

    if has_hallucination:
        logger.warning(
            'potential_hallucination_detected',
            hallucination_score=hallucination_score,
            invalid_citations=validation['invalid_citations'],
        )

    return result


def comprehensive_validation(
    answer: str,
    retrieved_passages: List[Dict],
) -> Dict[str, Any]:
    """
    Run comprehensive validation on answer.

    Combines citation validation, coverage check, and hallucination detection.

    Args:
        answer: LLM-generated answer
        retrieved_passages: List of {"id": "doc_123", "text": "..."}

    Returns:
        {
            "citations": Dict (from validate_citations),
            "coverage": Dict (from validate_answer_coverage),
            "hallucination": Dict (from detect_hallucination),
            "overall_passed": bool,
            "confidence_score": float
        }
    """
    # Normalize citation format
    normalized_answer = enforce_citation_format(answer)

    # Run all validations
    citations = validate_citations(normalized_answer, retrieved_passages)
    coverage = validate_answer_coverage(normalized_answer, retrieved_passages)
    hallucination = detect_hallucination(normalized_answer, retrieved_passages)

    # Overall validation
    overall_passed = (
        citations['validation_passed']
        and coverage['coverage_passed']
        and not hallucination['has_hallucination']
    )

    # Confidence score
    confidence_score = (
        citations['citation_compliance'] * 0.4
        + coverage['coverage'] * 0.3
        + hallucination['confidence'] * 0.3
    )

    result = {
        'citations': citations,
        'coverage': coverage,
        'hallucination': hallucination,
        'overall_passed': overall_passed,
        'confidence_score': confidence_score,
    }

    logger.info(
        'comprehensive_validation_complete',
        overall_passed=overall_passed,
        confidence_score=confidence_score,
    )

    return result


# Example usage
if __name__ == '__main__':
    # Test citation validation
    test_answer = """
    The IP address 192.168.1.100 has been involved in multiple DDoS attacks [doc_123].
    According to our threat intelligence, this IP is associated with a known botnet [doc_456].
    Additional analysis shows connections to malicious domains [doc_789].
    """

    test_passages = [
        {'id': 'doc_123', 'text': 'DDoS attack from 192.168.1.100'},
        {'id': 'doc_456', 'text': 'Botnet activity detected'},
        {'id': 'doc_789', 'text': 'Malicious domain connections'},
        {'id': 'doc_999', 'text': 'Additional context'},
    ]

    result = comprehensive_validation(test_answer, test_passages)

    print('\nCitation Validation Results:')
    print(f'  Overall Passed: {result["overall_passed"]}')
    print(f'  Confidence Score: {result["confidence_score"]:.2f}')
    print(f'\n  Citations:')
    print(f'    Valid: {result["citations"]["valid_citations"]}')
    print(f'    Invalid: {result["citations"]["invalid_citations"]}')
    print(f'    Compliance: {result["citations"]["citation_compliance"]:.2%}')
    print(f'\n  Coverage:')
    print(
        f'    Covered Passages: {result["coverage"]["covered_passages"]}/{result["coverage"]["total_passages"]}'
    )
    print(f'    Coverage: {result["coverage"]["coverage"]:.2%}')
    print(f'\n  Hallucination:')
    print(f'    Detected: {result["hallucination"]["has_hallucination"]}')
    print(f'    Score: {result["hallucination"]["hallucination_score"]:.2f}')
