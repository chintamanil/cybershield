# VisionAgent handles image processing, OCR, and risk detection
import base64
import io
import logging
from typing import Dict, List, Union
from PIL import Image
import pytesseract
import cv2
import numpy as np
from transformers import pipeline
import torch

logger = logging.getLogger(__name__)

class VisionAgent:
    """
    Vision AI agent for image processing and security analysis.
    Handles OCR, content classification, and risk detection.
    """
    
    def __init__(self, memory=None):
        self.memory = memory
        self.ocr_engine = 'tesseract'
        
        # Initialize image classification models
        try:
            # Content safety classifier
            self.safety_classifier = pipeline(
                "image-classification",
                model="google/vit-base-patch16-224",
                device=0 if torch.cuda.is_available() else -1
            )
            
            # Initialize OCR confidence threshold
            self.ocr_confidence_threshold = 60
            
        except Exception as e:
            logger.warning(f"Failed to initialize vision models: {e}")
            self.safety_classifier = None
    
    async def extract_text_from_image(self, image_data: Union[str, bytes, Image.Image]) -> Dict:
        """
        Extract text from image using OCR.
        
        Args:
            image_data: Base64 string, bytes, or PIL Image
            
        Returns:
            Dict containing extracted text and confidence scores
        """
        try:
            # Convert input to PIL Image
            image = self._prepare_image(image_data)
            
            # Preprocess image for better OCR
            processed_image = self._preprocess_for_ocr(image)
            
            # Extract text with confidence scores
            ocr_data = pytesseract.image_to_data(
                processed_image, 
                output_type=pytesseract.Output.DICT
            )
            
            # Filter high-confidence text
            extracted_text = []
            confidences = []
            
            for i, confidence in enumerate(ocr_data['conf']):
                if int(confidence) > self.ocr_confidence_threshold:
                    text = ocr_data['text'][i].strip()
                    if text:
                        extracted_text.append(text)
                        confidences.append(int(confidence))
            
            full_text = ' '.join(extracted_text)
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0
            
            result = {
                'text': full_text,
                'confidence': avg_confidence,
                'word_count': len(extracted_text),
                'raw_ocr_data': ocr_data
            }
            
            # Store in memory if available
            if self.memory:
                await self.memory.store_ocr_result(result)
            
            return result
            
        except Exception as e:
            logger.error(f"OCR extraction failed: {e}")
            return {'text': '', 'confidence': 0, 'error': str(e)}
    
    async def classify_image_content(self, image_data: Union[str, bytes, Image.Image]) -> Dict:
        """
        Classify image content for security risks.
        
        Args:
            image_data: Base64 string, bytes, or PIL Image
            
        Returns:
            Dict containing classification results and risk scores
        """
        try:
            if not self.safety_classifier:
                return {'error': 'Safety classifier not available'}
            
            image = self._prepare_image(image_data)
            
            # Run classification
            results = self.safety_classifier(image)
            
            # Analyze for security risks
            risk_analysis = self._analyze_security_risks(results, image)
            
            classification_result = {
                'classifications': results,
                'risk_level': risk_analysis['risk_level'],
                'security_flags': risk_analysis['flags'],
                'confidence': max([r['score'] for r in results]) if results else 0
            }
            
            # Store in memory if available
            if self.memory:
                await self.memory.store_image_classification(classification_result)
            
            return classification_result
            
        except Exception as e:
            logger.error(f"Image classification failed: {e}")
            return {'error': str(e), 'risk_level': 'unknown'}
    
    async def detect_sensitive_content(self, image_data: Union[str, bytes, Image.Image]) -> Dict:
        """
        Detect potentially sensitive content in images.
        
        Args:
            image_data: Base64 string, bytes, or PIL Image
            
        Returns:
            Dict containing sensitive content analysis
        """
        try:
            # Extract text for PII detection
            ocr_result = await self.extract_text_from_image(image_data)
            
            # Classify image content
            classification_result = await self.classify_image_content(image_data)
            
            # Detect potential PII in extracted text
            pii_indicators = self._detect_pii_in_text(ocr_result.get('text', ''))
            
            # Analyze image properties
            image = self._prepare_image(image_data)
            image_properties = self._analyze_image_properties(image)
            
            return {
                'text_analysis': {
                    'extracted_text': ocr_result.get('text', ''),
                    'pii_detected': pii_indicators,
                    'text_confidence': ocr_result.get('confidence', 0)
                },
                'content_analysis': classification_result,
                'image_properties': image_properties,
                'overall_risk': self._calculate_overall_risk(
                    pii_indicators, 
                    classification_result.get('risk_level', 'low'),
                    image_properties
                )
            }
            
        except Exception as e:
            logger.error(f"Sensitive content detection failed: {e}")
            return {'error': str(e)}
    
    def _prepare_image(self, image_data: Union[str, bytes, Image.Image]) -> Image.Image:
        """Convert various image formats to PIL Image."""
        if isinstance(image_data, Image.Image):
            return image_data
        
        if isinstance(image_data, str):
            # Assume base64 encoded
            try:
                image_bytes = base64.b64decode(image_data)
                return Image.open(io.BytesIO(image_bytes))
            except:
                # Try as file path
                return Image.open(image_data)
        
        if isinstance(image_data, bytes):
            return Image.open(io.BytesIO(image_data))
        
        raise ValueError("Unsupported image data format")
    
    def _preprocess_for_ocr(self, image: Image.Image) -> np.ndarray:
        """Preprocess image for better OCR results."""
        # Convert PIL to OpenCV format
        cv_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
        
        # Convert to grayscale
        gray = cv2.cvtColor(cv_image, cv2.COLOR_BGR2GRAY)
        
        # Apply denoising
        denoised = cv2.fastNlMeansDenoising(gray)
        
        # Apply adaptive thresholding
        thresh = cv2.adaptiveThreshold(
            denoised, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
        )
        
        return thresh
    
    def _analyze_security_risks(self, classifications: List[Dict], image: Image.Image) -> Dict:
        """Analyze classification results for security risks."""
        high_risk_categories = [
            'weapon', 'violence', 'explicit', 'drug', 'illegal',
            'document', 'id_card', 'passport', 'credit_card'
        ]
        
        flags = []
        max_risk_score = 0
        
        for result in classifications:
            label = result['label'].lower()
            score = result['score']
            
            # Check for high-risk categories
            for risk_category in high_risk_categories:
                if risk_category in label and score > 0.3:
                    flags.append({
                        'category': risk_category,
                        'confidence': score,
                        'label': result['label']
                    })
                    max_risk_score = max(max_risk_score, score)
        
        # Determine overall risk level
        if max_risk_score > 0.7:
            risk_level = 'high'
        elif max_risk_score > 0.4:
            risk_level = 'medium'
        elif flags:
            risk_level = 'low'
        else:
            risk_level = 'none'
        
        return {
            'risk_level': risk_level,
            'flags': flags,
            'max_risk_score': max_risk_score
        }
    
    def _detect_pii_in_text(self, text: str) -> List[Dict]:
        """Detect PII patterns in extracted text."""
        import re
        
        pii_patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
            'ip_address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        }
        
        detected_pii = []
        
        for pii_type, pattern in pii_patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                detected_pii.append({
                    'type': pii_type,
                    'matches': matches,
                    'count': len(matches)
                })
        
        return detected_pii
    
    def _analyze_image_properties(self, image: Image.Image) -> Dict:
        """Analyze image properties for additional context."""
        return {
            'dimensions': image.size,
            'format': image.format,
            'mode': image.mode,
            'has_transparency': image.mode in ('RGBA', 'LA') or 'transparency' in image.info,
            'file_size_estimate': len(image.tobytes())
        }
    
    def _calculate_overall_risk(self, pii_indicators: List[Dict], 
                               content_risk: str, image_properties: Dict) -> str:
        """Calculate overall risk score based on all factors."""
        risk_scores = {
            'none': 0,
            'low': 1,
            'medium': 2,
            'high': 3
        }
        
        # Start with content risk
        total_risk = risk_scores.get(content_risk, 0)
        
        # Add PII risk
        if pii_indicators:
            pii_risk = min(len(pii_indicators), 2)  # Cap at medium risk
            total_risk += pii_risk
        
        # Determine final risk level
        if total_risk >= 4:
            return 'high'
        elif total_risk >= 2:
            return 'medium'
        elif total_risk >= 1:
            return 'low'
        else:
            return 'none'
    
    async def process_image(self, image_data: Union[str, bytes, Image.Image]) -> Dict:
        """
        Complete image processing pipeline.
        
        Args:
            image_data: Image in various formats
            
        Returns:
            Comprehensive analysis results
        """
        try:
            # Run all analysis components
            ocr_result = await self.extract_text_from_image(image_data)
            classification_result = await self.classify_image_content(image_data)
            sensitive_content = await self.detect_sensitive_content(image_data)
            
            # Compile comprehensive report
            return {
                'status': 'success',
                'ocr': ocr_result,
                'classification': classification_result,
                'sensitive_analysis': sensitive_content,
                'recommendations': self._generate_recommendations(sensitive_content)
            }
            
        except Exception as e:
            logger.error(f"Image processing failed: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate security recommendations based on analysis."""
        recommendations = []
        
        overall_risk = analysis.get('overall_risk', 'none')
        
        if overall_risk in ['high', 'medium']:
            recommendations.append("Review image content before sharing or processing")
        
        pii_detected = analysis.get('text_analysis', {}).get('pii_detected', [])
        if pii_detected:
            recommendations.append("PII detected in image text - consider redaction")
        
        content_analysis = analysis.get('content_analysis', {})
        if content_analysis.get('risk_level') in ['high', 'medium']:
            recommendations.append("Potentially sensitive visual content detected")
        
        if not recommendations:
            recommendations.append("No significant security risks detected")
        
        return recommendations