# PII processing activity for Temporal workflow
import time
from typing import Dict, Any, List, Tuple

from temporalio import activity

from ..models import PIIAnalysis
from agents.pii_agent import PIIAgent
from utils.logging_config import get_security_logger

logger = get_security_logger("pii_processing_activity")


@activity.defn
async def pii_analysis_activity(text: str) -> PIIAnalysis:
    """
    Perform PII detection and masking on input text.

    This activity replaces the PII processing from the LangGraph workflow
    and provides comprehensive PII detection, masking, and analysis.
    """
    activity_start_time = time.time()

    try:
        activity.heartbeat("Starting PII analysis")

        logger.info(
            "Starting PII analysis",
            text_length=len(text)
        )

        if not text or len(text.strip()) == 0:
            logger.info("No text provided for PII analysis")
            return _create_empty_pii_analysis("No text provided")

        # Initialize PII Agent
        pii_agent = PIIAgent(memory=None)  # No memory needed for stateless analysis

        # Send heartbeat before PII detection
        activity.heartbeat("Detecting PII patterns")

        # Use PII agent to both detect and mask PII in one step
        try:
            # PII agent's mask_pii returns Tuple[str, Dict] - extract both parts
            masking_result = await pii_agent.mask_pii(text)  # Let it create its own session

            # Extract masked text and mapping from the tuple
            if isinstance(masking_result, (list, tuple)) and len(masking_result) >= 2:
                masked_text = str(masking_result[0])  # Ensure it's a string
                pii_mapping = masking_result[1]   # Get the PII mapping dict
                pii_detected = bool(pii_mapping)  # True if any PII was found

                # Additional validation to ensure masked_text is really a string
                if not isinstance(masked_text, str):
                    logger.warning(f"Masked text is not a string: {type(masked_text)}, converting...")
                    masked_text = str(masked_text)
            else:
                # Fallback if unexpected format
                logger.warning(f"Unexpected masking result format: {type(masking_result)}")
                masked_text = str(masking_result) if masking_result else text
                pii_mapping = {}
                pii_detected = False

        except Exception as e:
            logger.warning(f"PII agent masking failed, using fallback: {e}")
            # Use fallback detection and masking
            pii_detection_result = await _fallback_pii_detection(text)
            masked_text = await _fallback_pii_masking(text, pii_detection_result)
            pii_mapping = pii_detection_result.get("pii_mapping", {})
            pii_detected = pii_detection_result.get("pii_detected", False)

        # Send heartbeat before analysis
        activity.heartbeat("Analyzing PII detection results")

        # Process and analyze results
        # Create detection result in expected format for _process_pii_results
        detection_result_for_processing = {
            "pii_detected": pii_detected,
            "detected_entities": [],  # We'll extract from mapping
            "pii_mapping": pii_mapping
        }

        # Convert mapping to detected entities for compatibility
        for mask_token, pii_info in pii_mapping.items():
            detection_result_for_processing["detected_entities"].append({
                "type": pii_info.get("type", "unknown"),
                "value": pii_info.get("original", ""),
                "start": pii_info.get("position", [0, 0])[0],
                "end": pii_info.get("position", [0, 0])[1],
                "confidence": 0.8  # Default confidence
            })

        pii_analysis = _process_pii_results(text, masked_text, detection_result_for_processing)

        execution_time = time.time() - activity_start_time

        logger.info(
            "PII analysis completed successfully",
            pii_detected=pii_analysis.pii_detected,
            pii_types_count=len(pii_analysis.pii_types),
            pii_locations_count=len(pii_analysis.pii_locations),
            execution_time=execution_time
        )

        return pii_analysis

    except Exception as e:
        execution_time = time.time() - activity_start_time
        logger.error(f"PII analysis failed: {e}", execution_time=execution_time)

        return _create_empty_pii_analysis(f"Analysis failed: {str(e)}")


async def _fallback_pii_detection(text: str) -> Dict[str, Any]:
    """Fallback PII detection using simple regex patterns"""
    import re

    pii_patterns = {
        "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "phone": r'\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b',
        "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
        "credit_card": r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
        "ip_address": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    }

    detected_pii = []
    pii_mapping = {}

    for pii_type, pattern in pii_patterns.items():
        matches = re.finditer(pattern, text)
        for match in matches:
            start, end = match.span()
            detected_pii.append({
                "type": pii_type,
                "value": match.group(),
                "start": start,
                "end": end,
                "confidence": 0.8  # Default confidence for regex matches
            })

            # Create mapping for masking
            pii_id = f"PII_{pii_type.upper()}_{len(pii_mapping) + 1}"
            pii_mapping[pii_id] = {
                "original": match.group(),
                "type": pii_type,
                "start": start,
                "end": end
            }

    return {
        "pii_detected": len(detected_pii) > 0,
        "detected_entities": detected_pii,
        "pii_mapping": pii_mapping
    }


async def _fallback_pii_masking(text: str, detection_result: Dict[str, Any]) -> str:
    """Fallback PII masking implementation"""
    if not isinstance(detection_result, dict):
        return text

    masked_text = text
    pii_mapping = detection_result.get("pii_mapping", {})

    # Sort by position (descending) to avoid index shifting during replacement
    sorted_entities = sorted(
        pii_mapping.items(),
        key=lambda x: x[1].get("start", 0),
        reverse=True
    )

    for pii_id, pii_info in sorted_entities:
        start = pii_info.get("start", 0)
        end = pii_info.get("end", start)
        pii_type = pii_info.get("type", "UNKNOWN")

        # Create mask based on PII type
        if pii_type == "email":
            mask = "[EMAIL_REDACTED]"
        elif pii_type == "phone":
            mask = "[PHONE_REDACTED]"
        elif pii_type == "ssn":
            mask = "[SSN_REDACTED]"
        elif pii_type == "credit_card":
            mask = "[CARD_REDACTED]"
        else:
            mask = f"[{pii_type.upper()}_REDACTED]"

        # Replace in text
        if start < len(masked_text) and end <= len(masked_text):
            masked_text = masked_text[:start] + mask + masked_text[end:]

    return masked_text


def _process_pii_results(original_text: str, masked_text: str, detection_result: Dict[str, Any]) -> PIIAnalysis:
    """Process PII detection results into PIIAnalysis model"""

    # Handle different result formats
    if isinstance(detection_result, dict):
        pii_detected = detection_result.get("pii_detected", False)
        detected_entities = detection_result.get("detected_entities", [])
        pii_mapping = detection_result.get("pii_mapping", {})
    else:
        pii_detected = False
        detected_entities = []
        pii_mapping = {}

    # Extract PII types
    pii_types = list(set([
        entity.get("type", "unknown") for entity in detected_entities
    ]))

    # Create PII locations
    pii_locations = []
    for entity in detected_entities[:20]:  # Limit to first 20 for performance
        pii_locations.append({
            "type": entity.get("type", "unknown"),
            "start": entity.get("start", 0),
            "end": entity.get("end", 0),
            "value": entity.get("value", ""),
            "confidence": entity.get("confidence", 0.8)
        })

    # Calculate confidence scores
    confidence_scores = _calculate_pii_confidence_scores(detected_entities, pii_types, original_text)

    return PIIAnalysis(
        pii_detected=pii_detected,
        pii_types=pii_types,
        masked_text=masked_text,
        pii_locations=pii_locations,
        confidence_scores=confidence_scores
    )


def _calculate_pii_confidence_scores(
    detected_entities: List[Dict[str, Any]],
    pii_types: List[str],
    original_text: str
) -> Dict[str, float]:
    """Calculate confidence scores for PII analysis"""
    confidence_scores = {}

    # Overall confidence based on detection quality
    if detected_entities:
        # Use average confidence from detected entities
        entity_confidences = [entity.get("confidence", 0.8) for entity in detected_entities]
        confidence_scores["overall"] = sum(entity_confidences) / len(entity_confidences)
    else:
        # High confidence that no PII was found if text is substantial
        if len(original_text) > 100:
            confidence_scores["overall"] = 0.9
        else:
            confidence_scores["overall"] = 0.7

    # Type-specific confidence scores
    for pii_type in pii_types:
        type_entities = [e for e in detected_entities if e.get("type") == pii_type]
        if type_entities:
            type_confidences = [e.get("confidence", 0.8) for e in type_entities]
            confidence_scores[pii_type] = sum(type_confidences) / len(type_confidences)

    # Detection accuracy confidence
    confidence_scores["detection_accuracy"] = confidence_scores.get("overall", 0.8)

    # Masking effectiveness confidence
    if detected_entities:
        confidence_scores["masking_effectiveness"] = 0.95  # High confidence in masking
    else:
        confidence_scores["masking_effectiveness"] = 1.0  # Perfect masking if no PII

    return confidence_scores


def _create_empty_pii_analysis(reason: str) -> PIIAnalysis:
    """Create empty PII analysis result"""
    return PIIAnalysis(
        pii_detected=False,
        pii_types=[],
        masked_text="",
        pii_locations=[],
        confidence_scores={
            "overall": 0.0,
            "detection_accuracy": 0.0,
            "masking_effectiveness": 0.0
        }
    )


# Helper functions for advanced PII analysis

def _is_likely_sensitive_context(text: str, entity_position: int) -> bool:
    """Check if PII entity appears in a sensitive context"""
    # Extract surrounding text
    start = max(0, entity_position - 50)
    end = min(len(text), entity_position + 50)
    context = text[start:end].lower()

    # Sensitive context keywords
    sensitive_keywords = [
        "password", "secret", "confidential", "private", "internal",
        "login", "credential", "key", "token", "authorization"
    ]

    return any(keyword in context for keyword in sensitive_keywords)


def _assess_pii_risk_level(pii_types: List[str], pii_locations: List[Dict]) -> str:
    """Assess overall risk level of detected PII"""
    if not pii_types:
        return "low"

    # High-risk PII types
    high_risk_types = ["ssn", "credit_card", "passport", "driver_license"]
    medium_risk_types = ["phone", "email", "address"]

    # Check for high-risk types
    if any(pii_type in high_risk_types for pii_type in pii_types):
        return "high"

    # Check for multiple medium-risk types
    medium_risk_count = sum(1 for pii_type in pii_types if pii_type in medium_risk_types)
    if medium_risk_count >= 3:
        return "high"
    elif medium_risk_count >= 2:
        return "medium"
    elif medium_risk_count >= 1:
        return "low"

    # Default to low risk
    return "low"