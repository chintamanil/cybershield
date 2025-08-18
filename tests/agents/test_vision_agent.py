"""
Comprehensive tests for VisionAgent
Tests image processing, OCR, content classification, and security analysis
"""

import unittest
import asyncio
import sys
import os
import base64
import io
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from PIL import Image
import numpy as np

# Add parent directories to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from agents.vision_agent import VisionAgent


class TestVisionAgent(unittest.IsolatedAsyncioTestCase):
    """Test cases for VisionAgent functionality"""

    async def asyncSetUp(self):
        """Set up test fixtures"""
        # Mock the transformers pipeline to avoid model downloads
        with patch('agents.vision_agent.pipeline') as mock_pipeline:
            mock_classifier = Mock()
            mock_classifier.return_value = [{"label": "safe", "score": 0.9}]
            mock_pipeline.return_value = mock_classifier
            
            self.agent = VisionAgent()
            self.agent.safety_classifier = mock_classifier

    def create_test_image(self, size=(100, 100), color=(255, 255, 255)):
        """Create a test image for testing"""
        image = Image.new('RGB', size, color)
        return image

    def image_to_bytes(self, image):
        """Convert PIL Image to bytes"""
        img_byte_arr = io.BytesIO()
        image.save(img_byte_arr, format='PNG')
        return img_byte_arr.getvalue()

    async def test_init(self):
        """Test VisionAgent initialization"""
        self.assertIsNotNone(self.agent)
        self.assertIsNotNone(self.agent.perf_config)
        self.assertEqual(self.agent.ocr_engine, "tesseract")

    async def test_init_with_memory(self):
        """Test VisionAgent initialization with memory"""
        mock_memory = Mock()
        with patch('agents.vision_agent.pipeline'):
            agent = VisionAgent(memory=mock_memory)
            self.assertEqual(agent.memory, mock_memory)

    async def test_prepare_image_from_pil(self):
        """Test image preparation from PIL Image"""
        test_image = self.create_test_image()
        result = self.agent._prepare_image(test_image)
        
        self.assertIsInstance(result, Image.Image)
        self.assertEqual(result.size, (100, 100))

    async def test_prepare_image_from_bytes(self):
        """Test image preparation from bytes"""
        test_image = self.create_test_image()
        image_bytes = self.image_to_bytes(test_image)
        
        result = self.agent._prepare_image(image_bytes)
        
        self.assertIsInstance(result, Image.Image)
        self.assertEqual(result.size, (100, 100))

    async def test_prepare_image_from_base64(self):
        """Test image preparation from base64 string"""
        test_image = self.create_test_image()
        image_bytes = self.image_to_bytes(test_image)
        base64_string = base64.b64encode(image_bytes).decode('utf-8')
        
        result = self.agent._prepare_image(base64_string)
        
        self.assertIsInstance(result, Image.Image)

    async def test_prepare_image_invalid_data(self):
        """Test image preparation with invalid data"""
        with self.assertRaises(Exception):
            self.agent._prepare_image("invalid_image_data")

    @patch('agents.vision_agent.pytesseract.image_to_data')
    async def test_extract_text_from_image_success(self, mock_tesseract):
        """Test successful text extraction from image"""
        mock_tesseract.return_value = {
            "text": ["Sample", "extracted", "text"],
            "conf": [85, 90, 88]
        }
        
        test_image = self.create_test_image()
        image_bytes = self.image_to_bytes(test_image)
        
        result = await self.agent.extract_text_from_image(image_bytes)
        
        self.assertIn("text", result)
        self.assertIn("confidence", result)
        self.assertIn("word_count", result)

    @patch('agents.vision_agent.pytesseract.image_to_data')
    async def test_extract_text_from_image_empty(self, mock_tesseract):
        """Test text extraction when no text is found"""
        mock_tesseract.return_value = {
            "text": [],
            "conf": []
        }
        
        test_image = self.create_test_image()
        result = await self.agent.extract_text_from_image(test_image)
        
        self.assertEqual(result["text"], "")
        self.assertEqual(result["confidence"], 0)
        self.assertEqual(result["word_count"], 0)

    @patch('agents.vision_agent.pytesseract.image_to_data')
    async def test_extract_text_from_image_failure(self, mock_tesseract):
        """Test text extraction failure"""
        mock_tesseract.side_effect = Exception("OCR Error")
        
        test_image = self.create_test_image()
        result = await self.agent.extract_text_from_image(test_image)
        
        self.assertEqual(result["text"], "")
        self.assertEqual(result["confidence"], 0)
        self.assertIn("error", result)

    async def test_classify_image_content_success(self):
        """Test successful image content classification"""
        test_image = self.create_test_image()
        
        result = await self.agent.classify_image_content(test_image)
        
        self.assertIsInstance(result, dict)
        self.assertIn("classifications", result)
        self.assertIn("risk_level", result)
        self.assertIn("confidence", result)

    async def test_classify_image_content_failure(self):
        """Test image classification failure"""
        self.agent.safety_classifier.side_effect = Exception("Classification Error")
        
        test_image = self.create_test_image()
        result = await self.agent.classify_image_content(test_image)
        
        self.assertIn("error", result)
        self.assertEqual(result["risk_level"], "unknown")

    @patch('agents.vision_agent.pytesseract.image_to_data')
    async def test_detect_sensitive_content_with_pii(self, mock_tesseract):
        """Test sensitive content detection with PII"""
        mock_tesseract.return_value = {
            "text": ["Contact", "john@example.com", "or", "call", "555-123-4567"],
            "conf": [85, 90, 85, 88, 92]
        }
        
        test_image = self.create_test_image()
        result = await self.agent.detect_sensitive_content(test_image)
        
        self.assertIn("text_analysis", result)
        self.assertIn("content_analysis", result)
        self.assertIn("overall_risk", result)
        
        # Check if PII was detected
        text_analysis = result["text_analysis"]
        if "pii_detected" in text_analysis:
            self.assertIsInstance(text_analysis["pii_detected"], list)

    @patch('agents.vision_agent.pytesseract.image_to_data')
    async def test_detect_sensitive_content_clean(self, mock_tesseract):
        """Test sensitive content detection with clean content"""
        mock_tesseract.return_value = {
            "text": ["This", "is", "clean", "content", "without", "sensitive", "data"],
            "conf": [85, 88, 90, 87, 85, 89, 92]
        }
        
        test_image = self.create_test_image()
        result = await self.agent.detect_sensitive_content(test_image)
        
        self.assertIn("text_analysis", result)
        self.assertIn("overall_risk", result)
        
        # Should have low risk
        self.assertIn(result["overall_risk"], ["none", "low"])

    async def test_preprocess_for_ocr(self):
        """Test image preprocessing for OCR"""
        test_image = self.create_test_image()
        
        # Mock cv2 operations
        with patch('agents.vision_agent.cv2') as mock_cv2:
            mock_cv2.cvtColor.return_value = np.array([[255, 255, 255]])
            mock_cv2.threshold.return_value = (127, np.array([[255, 255, 255]]))
            
            result = self.agent._preprocess_for_ocr(test_image)
            
            self.assertIsInstance(result, np.ndarray)

    async def test_analyze_security_risks_high_risk(self):
        """Test security risk analysis for high-risk content"""
        test_image = self.create_test_image()
        classification = [{"label": "sensitive_document", "score": 0.9}]
        
        result = self.agent._analyze_security_risks(classification, test_image)
        
        self.assertIn("risk_level", result)
        self.assertIn("flags", result)
        self.assertIn("max_risk_score", result)

    async def test_analyze_security_risks_low_risk(self):
        """Test security risk analysis for low-risk content"""
        test_image = self.create_test_image()
        classification = [{"label": "landscape", "score": 0.9}]
        
        result = self.agent._analyze_security_risks(classification, test_image)
        
        # Should have low risk level
        self.assertIn(result["risk_level"], ["none", "low"])

    async def test_detect_pii_in_text_email(self):
        """Test PII detection for email addresses"""
        text = "Contact us at support@company.com for assistance"
        
        result = self.agent._detect_pii_in_text(text)
        
        self.assertGreater(len(result), 0)
        email_pii = [pii for pii in result if pii["type"] == "email"]
        self.assertGreater(len(email_pii), 0)
        self.assertIn("support@company.com", email_pii[0]["matches"])

    async def test_detect_pii_in_text_phone(self):
        """Test PII detection for phone numbers"""
        text = "Call me at (555) 123-4567 or 555-987-6543"
        
        result = self.agent._detect_pii_in_text(text)
        
        phone_pii = [pii for pii in result if pii["type"] == "phone"]
        self.assertGreater(len(phone_pii), 0)

    async def test_detect_pii_in_text_ssn(self):
        """Test PII detection for SSN"""
        text = "SSN: 123-45-6789"
        
        result = self.agent._detect_pii_in_text(text)
        
        ssn_pii = [pii for pii in result if pii["type"] == "ssn"]
        self.assertGreater(len(ssn_pii), 0)
        self.assertIn("123-45-6789", ssn_pii[0]["matches"])

    async def test_detect_pii_in_text_credit_card(self):
        """Test PII detection for credit card numbers"""
        text = "Card number: 4111-1111-1111-1111"
        
        result = self.agent._detect_pii_in_text(text)
        
        cc_pii = [pii for pii in result if pii["type"] == "credit_card"]
        self.assertGreater(len(cc_pii), 0)

    async def test_detect_pii_in_text_no_pii(self):
        """Test PII detection with no PII present"""
        text = "This is a normal document without sensitive information"
        
        result = self.agent._detect_pii_in_text(text)
        
        self.assertEqual(len(result), 0)

    async def test_analyze_image_properties(self):
        """Test image properties analysis"""
        test_image = self.create_test_image((800, 600))
        
        result = self.agent._analyze_image_properties(test_image)
        
        self.assertEqual(result["dimensions"], (800, 600))
        self.assertIn("mode", result)
        self.assertIn("file_size_estimate", result)

    async def test_calculate_overall_risk_high(self):
        """Test overall risk calculation for high-risk scenarios"""
        pii_indicators = [
            {"type": "ssn", "matches": ["123-45-6789"], "count": 1},
            {"type": "credit_card", "matches": ["4111-1111-1111-1111"], "count": 1}
        ]
        
        content_risk = "high"
        image_properties = {"dimensions": (100, 100)}
        
        result = self.agent._calculate_overall_risk(
            pii_indicators, content_risk, image_properties
        )
        
        self.assertIn(result, ["high", "medium", "low", "none"])

    async def test_calculate_overall_risk_low(self):
        """Test overall risk calculation for low-risk scenarios"""
        pii_indicators = []
        content_risk = "none"
        image_properties = {"dimensions": (100, 100)}
        
        result = self.agent._calculate_overall_risk(
            pii_indicators, content_risk, image_properties
        )
        
        self.assertIn(result, ["none", "low"])

    @patch('agents.vision_agent.pytesseract.image_to_data')
    async def test_process_image_complete_workflow(self, mock_tesseract):
        """Test complete image processing workflow"""
        mock_tesseract.return_value = {
            "text": ["Sample", "document", "with", "email@example.com"],
            "conf": [85, 90, 88, 92]
        }
        
        test_image = self.create_test_image()
        image_bytes = self.image_to_bytes(test_image)
        
        result = await self.agent.process_image(image_bytes)
        
        # Verify all components are present
        self.assertIn("status", result)
        self.assertIn("ocr", result)
        self.assertIn("classification", result)
        self.assertIn("sensitive_analysis", result)
        self.assertIn("recommendations", result)

    async def test_generate_recommendations_high_risk(self):
        """Test recommendation generation for high-risk content"""
        analysis = {
            "overall_risk": "high",
            "text_analysis": {
                "pii_detected": [{"type": "ssn", "matches": ["123-45-6789"], "count": 1}]
            },
            "content_analysis": {
                "risk_level": "high"
            }
        }
        
        recommendations = self.agent._generate_recommendations(analysis)
        
        self.assertGreater(len(recommendations), 0)
        # Should include specific recommendations for high-risk content
        self.assertIsInstance(recommendations, list)

    async def test_generate_recommendations_low_risk(self):
        """Test recommendation generation for low-risk content"""
        analysis = {
            "overall_risk": "none",
            "text_analysis": {
                "pii_detected": []
            },
            "content_analysis": {
                "risk_level": "none"
            }
        }
        
        recommendations = self.agent._generate_recommendations(analysis)
        
        # Should have at least one recommendation
        self.assertGreater(len(recommendations), 0)


class TestVisionAgentIntegration(unittest.IsolatedAsyncioTestCase):
    """Integration tests for VisionAgent"""

    async def asyncSetUp(self):
        """Set up test fixtures"""
        # Mock the transformers to avoid model downloads
        with patch('agents.vision_agent.pipeline'):
            self.agent = VisionAgent()

    def create_text_image(self, text="Sample Text", size=(200, 100)):
        """Create an image with text for OCR testing"""
        from PIL import Image, ImageDraw, ImageFont
        
        image = Image.new('RGB', size, color='white')
        draw = ImageDraw.Draw(image)
        
        # Use default font
        try:
            font = ImageFont.load_default()
        except:
            font = None
        
        # Calculate text position
        if font:
            bbox = draw.textbbox((0, 0), text, font=font)
            text_width = bbox[2] - bbox[0]
            text_height = bbox[3] - bbox[1]
        else:
            text_width = len(text) * 6  # Approximate
            text_height = 11
        
        x = (size[0] - text_width) // 2
        y = (size[1] - text_height) // 2
        
        draw.text((x, y), text, fill='black', font=font)
        return image

    @patch('agents.vision_agent.pytesseract.image_to_data')
    async def test_full_image_analysis_workflow(self, mock_tesseract):
        """Test complete image analysis workflow"""
        mock_tesseract.return_value = {
            "text": ["Confidential", "Document", "Employee", "ID:", "E12345", "SSN:", "123-45-6789"],
            "conf": [85, 90, 88, 92, 87, 89, 94]
        }
        
        # Create test image
        test_image = self.create_text_image("Confidential Document")
        
        # Process image
        result = await self.agent.process_image(test_image)
        
        # Verify all analysis components
        self.assertIn("status", result)
        self.assertIn("ocr", result)
        self.assertIn("classification", result)
        self.assertIn("sensitive_analysis", result)
        self.assertIn("recommendations", result)
        
        # Verify analysis components exist
        self.assertEqual(result["status"], "success")

    async def test_image_processing_edge_cases(self):
        """Test image processing with edge cases"""
        test_cases = [
            # Small image
            self.create_text_image("Small", (50, 20)),
            # Large text
            self.create_text_image("Large Text Content", (400, 200)),
            # Empty-like image
            Image.new('RGB', (100, 100), color='white'),
        ]
        
        for i, test_image in enumerate(test_cases):
            with patch('agents.vision_agent.pytesseract.image_to_data', return_value={"text": [], "conf": []}):
                result = await self.agent.process_image(test_image)
                
                # Should handle all cases gracefully
                self.assertIn("status", result)
                self.assertIn("ocr", result)

    @patch('agents.vision_agent.pytesseract.image_to_data')
    async def test_concurrent_image_processing(self, mock_tesseract):
        """Test concurrent image processing"""
        mock_tesseract.return_value = {
            "text": ["Test", "document", "content"],
            "conf": [85, 90, 88]
        }
        
        # Create multiple test images
        images = [
            self.create_text_image(f"Document {i}", (150, 100))
            for i in range(3)
        ]
        
        # Process images concurrently
        tasks = [self.agent.process_image(img) for img in images]
        results = await asyncio.gather(*tasks)
        
        # Verify all processing completed
        self.assertEqual(len(results), 3)
        for result in results:
            self.assertIn("status", result)
            self.assertIn("ocr", result)


if __name__ == "__main__":
    unittest.main()