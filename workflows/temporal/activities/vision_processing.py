# Vision processing activity for Temporal workflow
import time
from typing import Dict, Any, Optional, List

from temporalio import activity

from ..models import VisionAnalysis
from agents.vision_agent import VisionAgent
from utils.logging_config import get_security_logger

logger = get_security_logger("vision_processing_activity")


@activity.defn
async def vision_analysis_activity(image_data: bytes) -> VisionAnalysis:
    """
    Perform computer vision analysis on image data.

    This activity replaces the vision processing from the LangGraph workflow
    and provides comprehensive image analysis including OCR and security assessment.
    """
    activity_start_time = time.time()

    try:
        activity.heartbeat("Starting vision analysis")

        logger.info(
            "Starting vision analysis",
            image_size=len(image_data) if image_data else 0
        )

        if not image_data:
            logger.warning("No image data provided for vision analysis")
            return _create_empty_vision_analysis("No image data provided")

        # Initialize Vision Agent
        vision_agent = VisionAgent(memory=None)  # No memory needed for stateless analysis

        # Send heartbeat before OCR processing
        activity.heartbeat("Performing OCR text extraction")

        # Extract text from image using OCR
        ocr_result = await vision_agent.extract_text_from_image(image_data)
        ocr_text = ocr_result.get("text", "") if isinstance(ocr_result, dict) else str(ocr_result)

        # Send heartbeat before object detection
        activity.heartbeat("Performing object detection")

        # Detect objects in image
        try:
            object_detection_result = await vision_agent.analyze_image_content(image_data)
            detected_objects = object_detection_result.get("objects", []) if isinstance(object_detection_result, dict) else []
        except Exception as e:
            logger.warning(f"Object detection failed: {e}")
            detected_objects = []

        # Send heartbeat before security assessment
        activity.heartbeat("Performing security assessment")

        # Perform security assessment of image content
        security_assessment = await _assess_image_security(ocr_text, detected_objects, image_data)

        # Send heartbeat before PII detection in images
        activity.heartbeat("Detecting PII in image")

        # Check for PII in extracted text
        pii_in_images = await _detect_pii_in_image_text(ocr_text)

        # Calculate confidence scores
        confidence_scores = _calculate_vision_confidence_scores(ocr_text, detected_objects, security_assessment)

        execution_time = time.time() - activity_start_time

        result = VisionAnalysis(
            ocr_text=ocr_text,
            detected_objects=detected_objects,
            security_assessment=security_assessment,
            pii_in_images=pii_in_images,
            confidence_scores=confidence_scores
        )

        logger.info(
            "Vision analysis completed successfully",
            ocr_text_length=len(ocr_text),
            objects_detected=len(detected_objects),
            pii_found=len(pii_in_images),
            execution_time=execution_time
        )

        return result

    except Exception as e:
        execution_time = time.time() - activity_start_time
        logger.error(f"Vision analysis failed: {e}", execution_time=execution_time)

        return _create_empty_vision_analysis(f"Analysis failed: {str(e)}")


async def _assess_image_security(ocr_text: str, detected_objects: List[Dict], image_data: bytes) -> Dict[str, Any]:
    """Assess security implications of image content"""
    security_assessment = {
        "risk_level": "low",
        "threats_detected": [],
        "recommendations": [],
        "analysis_details": {}
    }

    # Analyze OCR text for security keywords
    if ocr_text:
        security_keywords = [
            "password", "secret", "key", "token", "credential",
            "login", "admin", "root", "database", "config",
            "api_key", "private", "confidential", "internal"
        ]

        found_keywords = [keyword for keyword in security_keywords if keyword.lower() in ocr_text.lower()]

        if found_keywords:
            security_assessment["risk_level"] = "high"
            security_assessment["threats_detected"].append({
                "type": "sensitive_text",
                "description": f"Potentially sensitive keywords found: {', '.join(found_keywords)}",
                "severity": "high"
            })
            security_assessment["recommendations"].append(
                "Review image for exposed credentials or sensitive information"
            )

    # Analyze detected objects for security concerns
    if detected_objects:
        security_objects = []
        for obj in detected_objects:
            obj_name = obj.get("name", "").lower()
            if any(keyword in obj_name for keyword in ["screen", "monitor", "computer", "terminal", "console"]):
                security_objects.append(obj)

        if security_objects:
            security_assessment["threats_detected"].append({
                "type": "screen_content",
                "description": f"Screen or computer interface detected: {len(security_objects)} objects",
                "severity": "medium"
            })
            security_assessment["recommendations"].append(
                "Verify no sensitive information is visible on screens in image"
            )

    # Check image metadata for security concerns
    security_assessment["analysis_details"] = {
        "image_size": len(image_data),
        "ocr_text_length": len(ocr_text),
        "objects_count": len(detected_objects),
        "security_keywords_found": len([t for t in security_assessment["threats_detected"] if t["type"] == "sensitive_text"])
    }

    # Overall risk assessment
    threat_count = len(security_assessment["threats_detected"])
    if threat_count == 0:
        security_assessment["risk_level"] = "low"
        security_assessment["recommendations"].append("No significant security threats detected in image")
    elif threat_count == 1:
        security_assessment["risk_level"] = "medium"
    else:
        security_assessment["risk_level"] = "high"

    return security_assessment


async def _detect_pii_in_image_text(ocr_text: str) -> List[str]:
    """Detect PII in extracted OCR text"""
    pii_found = []

    if not ocr_text:
        return pii_found

    import re

    # Email addresses
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = re.findall(email_pattern, ocr_text)
    if emails:
        pii_found.extend([f"Email: {email}" for email in emails[:3]])  # Limit to first 3

    # Phone numbers (simple pattern)
    phone_pattern = r'\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b'
    phones = re.findall(phone_pattern, ocr_text)
    if phones:
        pii_found.extend([f"Phone: {''.join(phone)}" for phone in phones[:3]])  # Limit to first 3

    # Social Security Numbers (US format)
    ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
    ssns = re.findall(ssn_pattern, ocr_text)
    if ssns:
        pii_found.extend([f"SSN: {ssn}" for ssn in ssns[:2]])  # Limit to first 2

    # Credit Card Numbers (simple pattern)
    cc_pattern = r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'
    credit_cards = re.findall(cc_pattern, ocr_text)
    if credit_cards:
        pii_found.extend([f"Credit Card: {cc}" for cc in credit_cards[:2]])  # Limit to first 2

    # IP Addresses (could be PII in some contexts)
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = re.findall(ip_pattern, ocr_text)
    if ips:
        # Only consider private/internal IPs as potential PII
        private_ips = [ip for ip in ips if _is_private_ip(ip)]
        if private_ips:
            pii_found.extend([f"Private IP: {ip}" for ip in private_ips[:3]])

    return pii_found


def _is_private_ip(ip: str) -> bool:
    """Check if IP address is in private range"""
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False

        first_octet = int(parts[0])
        second_octet = int(parts[1])

        # Private IP ranges
        if first_octet == 10:  # 10.0.0.0/8
            return True
        elif first_octet == 172 and 16 <= second_octet <= 31:  # 172.16.0.0/12
            return True
        elif first_octet == 192 and second_octet == 168:  # 192.168.0.0/16
            return True

        return False
    except (ValueError, IndexError):
        return False


def _calculate_vision_confidence_scores(
    ocr_text: str,
    detected_objects: List[Dict],
    security_assessment: Dict[str, Any]
) -> Dict[str, float]:
    """Calculate confidence scores for vision analysis components"""
    confidence_scores = {}

    # OCR confidence based on text length and quality
    if ocr_text:
        text_length = len(ocr_text.strip())
        if text_length > 100:
            confidence_scores["ocr"] = 0.9
        elif text_length > 50:
            confidence_scores["ocr"] = 0.8
        elif text_length > 10:
            confidence_scores["ocr"] = 0.7
        else:
            confidence_scores["ocr"] = 0.5
    else:
        confidence_scores["ocr"] = 0.1

    # Object detection confidence
    if detected_objects:
        # Use average confidence from detected objects if available
        obj_confidences = [obj.get("confidence", 0.7) for obj in detected_objects]
        confidence_scores["object_detection"] = sum(obj_confidences) / len(obj_confidences)
    else:
        confidence_scores["object_detection"] = 0.3

    # Security assessment confidence
    threats_count = len(security_assessment.get("threats_detected", []))
    if threats_count > 0:
        confidence_scores["security_assessment"] = 0.9
    elif ocr_text or detected_objects:
        confidence_scores["security_assessment"] = 0.7
    else:
        confidence_scores["security_assessment"] = 0.4

    # Overall confidence
    component_scores = list(confidence_scores.values())
    confidence_scores["overall"] = sum(component_scores) / len(component_scores) if component_scores else 0.5

    return confidence_scores


def _create_empty_vision_analysis(reason: str) -> VisionAnalysis:
    """Create empty vision analysis result"""
    return VisionAnalysis(
        ocr_text="",
        detected_objects=[],
        security_assessment={
            "risk_level": "low",
            "threats_detected": [],
            "recommendations": [f"Vision analysis not performed: {reason}"],
            "analysis_details": {}
        },
        pii_in_images=[],
        confidence_scores={"overall": 0.0, "ocr": 0.0, "object_detection": 0.0, "security_assessment": 0.0}
    )