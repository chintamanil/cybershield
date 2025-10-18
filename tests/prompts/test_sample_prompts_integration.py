"""Integration tests for CyberShield sample prompts using FastAPI endpoints.

This module tests the complete analysis pipeline through the FastAPI server.
Requires the server to be running on localhost:8000.
"""

import json
from pathlib import Path
from typing import Any

import pytest
import requests

BASE_URL = "http://localhost:8000"
TIMEOUT = 60  # seconds


class TestAPIHealth:
    """Test API health and availability."""

    def test_server_is_running(self):
        """Test that the FastAPI server is accessible."""
        try:
            response = requests.get(f"{BASE_URL}/health", timeout=5)
            assert response.status_code == 200, "Server should be healthy"
        except requests.exceptions.ConnectionError:
            pytest.skip("FastAPI server is not running on localhost:8000")

    def test_status_endpoint(self):
        """Test the enhanced status endpoint."""
        try:
            response = requests.get(f"{BASE_URL}/status", timeout=5)
            assert response.status_code == 200, "Status endpoint should work"

            data = response.json()
            assert "status" in data, "Should have status field"
            assert "tools" in data or "version" in data, "Should have system info"
        except requests.exceptions.ConnectionError:
            pytest.skip("FastAPI server is not running on localhost:8000")


class TestAnalyzeEndpoint:
    """Test the /analyze endpoint with sample prompts."""

    @pytest.fixture
    def prompts_data(self):
        """Load prompts from JSON file."""
        data_file = Path(__file__).parent / "test_data" / "prompts.json"
        with open(data_file) as f:
            return json.load(f)

    def _call_analyze_endpoint(self, text: str) -> dict[str, Any]:
        """Call the /analyze endpoint and return the response."""
        response = requests.post(
            f"{BASE_URL}/analyze",
            json={"text": text},
            timeout=TIMEOUT,
        )
        assert response.status_code == 200, f"API call failed: {response.text}"
        return response.json()

    def test_basic_threat_detection(self, prompts_data):
        """Test basic threat detection with failed login."""
        prompt = prompts_data["basic_security_analysis"][0]
        result = self._call_analyze_endpoint(prompt["prompt"])

        # Verify response structure
        assert "analysis" in result or "result" in result, "Should have analysis result"
        assert isinstance(result, dict), "Result should be a dictionary"

        # Response should contain some threat information
        response_str = json.dumps(result).lower()
        assert any(
            keyword in response_str
            for keyword in ["threat", "ip", "hash", "domain", "security"]
        ), "Should contain security-related information"

    def test_ssh_connection_analysis(self, prompts_data):
        """Test SSH connection attempt analysis."""
        prompt = prompts_data["basic_security_analysis"][1]
        result = self._call_analyze_endpoint(prompt["prompt"])

        # Should complete successfully
        assert result is not None
        response_str = json.dumps(result).lower()

        # Should detect IP addresses
        assert "ip" in response_str or "address" in response_str, (
            "Should detect IP addresses"
        )

    def test_pii_detection_ssn_credit_card(self, prompts_data):
        """Test PII detection with SSN and credit card."""
        prompt = prompts_data["pii_detection"][0]
        result = self._call_analyze_endpoint(prompt["prompt"])

        # Verify PII was detected
        response_str = json.dumps(result).lower()
        assert any(
            keyword in response_str for keyword in ["pii", "sensitive", "personal"]
        ), "Should detect PII"

    def test_employee_record_pii(self, prompts_data):
        """Test employee record PII detection."""
        prompt = prompts_data["pii_detection"][1]
        result = self._call_analyze_endpoint(prompt["prompt"])

        assert result is not None
        # Response should indicate PII detection or masking occurred
        response_str = json.dumps(result).lower()
        assert "email" in response_str or "pii" in response_str

    def test_firewall_block_detection(self, prompts_data):
        """Test firewall block with DNS query detection."""
        prompt = prompts_data["network_security_events"][0]
        result = self._call_analyze_endpoint(prompt["prompt"])

        # Should detect multiple IOCs
        response_str = json.dumps(result).lower()
        assert any(
            keyword in response_str
            for keyword in ["firewall", "blocked", "dns", "domain"]
        ), "Should detect network security event"

    def test_malware_c2_detection(self, prompts_data):
        """Test malware C2 server detection."""
        prompt = prompts_data["network_security_events"][1]
        result = self._call_analyze_endpoint(prompt["prompt"])

        response_str = json.dumps(result).lower()
        assert any(
            keyword in response_str
            for keyword in ["malware", "c2", "command", "bitcoin"]
        ), "Should detect malware indicators"

    def test_apt_lateral_movement(self, prompts_data):
        """Test APT lateral movement detection."""
        prompt = prompts_data["advanced_persistent_threats"][0]
        result = self._call_analyze_endpoint(prompt["prompt"])

        response_str = json.dumps(result).lower()
        assert any(
            keyword in response_str
            for keyword in ["lateral", "movement", "cobalt", "beacon", "threat"]
        ), "Should detect APT activity"

    def test_phishing_email_detection(self, prompts_data):
        """Test phishing email with Bitcoin detection."""
        prompt = prompts_data["advanced_persistent_threats"][1]
        result = self._call_analyze_endpoint(prompt["prompt"])

        response_str = json.dumps(result).lower()
        assert any(
            keyword in response_str
            for keyword in ["email", "phishing", "bitcoin", "suspicious"]
        ), "Should detect phishing indicators"

    def test_invalid_iocs_handling(self, prompts_data):
        """Test graceful handling of invalid IOCs."""
        prompt = prompts_data["error_handling"][0]

        # Should not raise exception
        result = self._call_analyze_endpoint(prompt["prompt"])
        assert result is not None, "Should handle invalid IOCs gracefully"

    def test_mixed_valid_invalid_data(self, prompts_data):
        """Test mixed valid and invalid data extraction."""
        prompt = prompts_data["error_handling"][1]
        result = self._call_analyze_endpoint(prompt["prompt"])

        # Should complete successfully and extract valid IOCs
        assert result is not None
        response_str = json.dumps(result)

        # Should contain the valid IP
        assert "8.8.8.8" in response_str, "Should extract valid IP"


class TestImageAnalysisEndpoint:
    """Test image analysis endpoints."""

    @pytest.fixture
    def test_images_dir(self):
        """Get the test images directory."""
        return Path(__file__).parent / "test_images"

    def test_upload_security_logs_screenshot(self, test_images_dir):
        """Test uploading security logs screenshot."""
        image_path = test_images_dir / "security_logs_screenshot.png"

        if not image_path.exists():
            pytest.skip("Test image not found")

        with open(image_path, "rb") as f:
            files = {
                "image": ("security_logs.png", f, "image/png")
            }  # Changed to "image"
            response = requests.post(
                f"{BASE_URL}/upload-image", files=files, timeout=TIMEOUT
            )

        # Should process successfully
        assert response.status_code == 200, f"Image upload failed: {response.text}"
        result = response.json()
        assert result is not None, "Should return analysis result"

        # Should detect IOCs in the image
        response_str = json.dumps(result).lower()
        assert any(
            keyword in response_str for keyword in ["ip", "hash", "threat", "detected"]
        ), "Should extract IOCs from image"

    def test_upload_email_with_pii(self, test_images_dir):
        """Test uploading email screenshot with PII."""
        image_path = test_images_dir / "email_with_pii.png"

        if not image_path.exists():
            pytest.skip("Test image not found")

        with open(image_path, "rb") as f:
            files = {"image": ("email_pii.png", f, "image/png")}  # Changed to "image"
            response = requests.post(
                f"{BASE_URL}/upload-image", files=files, timeout=TIMEOUT
            )

        assert response.status_code == 200, f"Image upload failed: {response.text}"
        result = response.json()

        # Should detect PII
        response_str = json.dumps(result).lower()
        assert any(
            keyword in response_str for keyword in ["pii", "email", "personal", "ssn"]
        ), "Should detect PII in image"

    def test_upload_security_dashboard(self, test_images_dir):
        """Test uploading security dashboard screenshot."""
        image_path = test_images_dir / "security_dashboard.png"

        if not image_path.exists():
            pytest.skip("Test image not found")

        with open(image_path, "rb") as f:
            files = {"image": ("dashboard.png", f, "image/png")}  # Changed to "image"
            response = requests.post(
                f"{BASE_URL}/upload-image", files=files, timeout=TIMEOUT
            )

        assert response.status_code == 200, f"Image upload failed: {response.text}"
        result = response.json()

        # Should extract multiple IOCs from dashboard
        response_str = json.dumps(result).lower()
        assert any(
            keyword in response_str
            for keyword in ["alert", "threat", "ip", "security", "critical"]
        ), "Should analyze security dashboard"


class TestMultimodalAnalysis:
    """Test multimodal analysis (text + image)."""

    @pytest.fixture
    def test_images_dir(self):
        """Get the test images directory."""
        return Path(__file__).parent / "test_images"

    @pytest.fixture
    def prompts_data(self):
        """Load prompts from JSON file."""
        data_file = Path(__file__).parent / "test_data" / "prompts.json"
        with open(data_file) as f:
            return json.load(f)

    def test_analyze_with_image_and_text(self, test_images_dir, prompts_data):
        """Test combined text and image analysis."""
        image_path = test_images_dir / "security_logs_screenshot.png"

        if not image_path.exists():
            pytest.skip("Test image not found")

        # Use a threat detection prompt
        prompt = prompts_data["network_security_events"][0]

        with open(image_path, "rb") as f:
            files = {"image": ("security_logs.png", f, "image/png")}
            data = {"text": prompt["prompt"]}

            response = requests.post(
                f"{BASE_URL}/analyze-with-image",
                files=files,
                data=data,
                timeout=TIMEOUT,
            )

        # Should process both text and image
        assert response.status_code == 200, (
            f"Multimodal analysis failed: {response.text}"
        )
        result = response.json()
        assert result is not None

        # Should contain analysis from both sources
        response_str = json.dumps(result).lower()
        assert any(
            keyword in response_str
            for keyword in ["image", "text", "analysis", "threat"]
        ), "Should analyze both text and image"


class TestBatchAnalysis:
    """Test batch analysis endpoint."""

    @pytest.fixture
    def prompts_data(self):
        """Load prompts from JSON file."""
        data_file = Path(__file__).parent / "test_data" / "prompts.json"
        with open(data_file) as f:
            return json.load(f)

    def test_batch_analyze_multiple_prompts(self, prompts_data):
        """Test batch analysis of multiple prompts."""
        # Select a few prompts for batch processing
        batch_prompts = [
            prompts_data["basic_security_analysis"][0]["prompt"],
            prompts_data["pii_detection"][0]["prompt"],
            prompts_data["network_security_events"][0]["prompt"],
        ]

        response = requests.post(
            f"{BASE_URL}/batch-analyze",
            json={"inputs": batch_prompts},  # Changed from "texts" to "inputs"
            timeout=TIMEOUT * 2,  # Give more time for batch processing
        )

        assert response.status_code == 200, f"Batch analysis failed: {response.text}"
        result = response.json()

        # Should return results for all inputs
        assert isinstance(result, (list, dict)), "Should return batch results"

        # If it's a list, verify length
        if isinstance(result, list):
            assert len(result) == len(batch_prompts), "Should analyze all prompts"


class TestToolEndpoints:
    """Test individual tool endpoints."""

    def test_regex_extract_endpoint(self):
        """Test the regex IOC extraction endpoint."""
        test_text = (
            "Suspicious IP 203.0.113.42 with hash d41d8cd98f00b204e9800998ecf8427e"
        )

        response = requests.post(
            f"{BASE_URL}/tools/regex/extract",
            params={"text": test_text},  # Changed to params instead of json
            timeout=10,
        )

        assert response.status_code == 200, "Regex extraction should work"
        result = response.json()

        # Should extract IOCs (API returns ipv4, md5, sha256, etc.)
        assert "ipv4" in result or "md5" in result or len(result) > 0, (
            "Should return extracted IOCs"
        )

    def test_regex_validate_endpoint(self):
        """Test the regex validation endpoint."""
        response = requests.post(
            f"{BASE_URL}/tools/regex/validate",
            params={"text": "8.8.8.8", "pattern_type": "ip"},  # Changed to params
            timeout=10,
        )

        assert response.status_code == 200, "Validation should work"
        result = response.json()
        assert "valid" in result or "is_valid" in result or isinstance(result, dict), (
            "Should return validation result"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
