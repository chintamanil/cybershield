"""Automated pytest tests for CyberShield sample prompts.

This module contains unit tests for all sample prompts from the README.
Tests individual components without requiring the FastAPI server.
"""

import json
from pathlib import Path

import pytest

# Import agents and tools
from agents.log_parser import LogParserAgent
from agents.pii_agent import PIIAgent
from tools.regex_checker import RegexChecker


class TestBasicSecurityAnalysis:
    """Test basic security analysis prompts."""

    @pytest.fixture
    def log_parser(self):
        """Create a log parser agent for testing."""
        return LogParserAgent()

    @pytest.fixture
    def regex_checker(self):
        """Create a regex checker for IOC extraction."""
        return RegexChecker()

    @pytest.fixture
    def prompts_data(self):
        """Load prompts from JSON file."""
        data_file = Path(__file__).parent / "test_data" / "prompts.json"
        with open(data_file) as f:
            return json.load(f)

    def test_failed_login_with_hash_and_domain(self, regex_checker, prompts_data):
        """Test detection of failed login with hash and domain."""
        prompt = prompts_data["basic_security_analysis"][0]
        result = regex_checker.extract_all_iocs(prompt["prompt"])

        # Verify IP extraction
        assert len(result.get("ipv4", [])) > 0, "Should detect IP address"
        assert "198.51.100.5" in result.get("ipv4", [])

        # Verify hash extraction
        assert (
            len(
                result.get("md5", [])
                + result.get("sha1", [])
                + result.get("sha256", [])
            )
            > 0
        ), "Should detect hash"
        assert "d41d8cd98f00b204e9800998ecf8427e" in result.get("md5", []) + result.get(
            "sha1", []
        ) + result.get("sha256", [])

        # Verify domain extraction
        assert len(result.get("domain", [])) > 0, "Should detect domain"
        assert "malware-c2.example.com" in result.get("domain", [])

    def test_ssh_connection_attempt(self, regex_checker, prompts_data):
        """Test detection of SSH connection attempt."""
        prompt = prompts_data["basic_security_analysis"][1]
        result = regex_checker.extract_all_iocs(prompt["prompt"])

        # Should detect both IPs
        assert len(result.get("ipv4", [])) >= 2, "Should detect multiple IPs"
        assert "192.168.1.100" in result.get("ipv4", [])
        assert "203.0.113.42" in result.get("ipv4", [])


class TestPIIDetection:
    """Test PII detection prompts."""

    @pytest.fixture
    def pii_agent(self):
        """Create a PII agent for testing."""
        return PIIAgent()

    @pytest.fixture
    def regex_checker(self):
        """Create a regex checker for PII extraction."""
        return RegexChecker()

    @pytest.fixture
    def prompts_data(self):
        """Load prompts from JSON file."""
        data_file = Path(__file__).parent / "test_data" / "prompts.json"
        with open(data_file) as f:
            return json.load(f)

    @pytest.mark.asyncio
    async def test_user_with_ssn_and_credit_card(self, pii_agent, prompts_data):
        """Test detection of SSN and credit card in text."""
        prompt = prompts_data["pii_detection"][0]
        masked_text, pii_map = await pii_agent.mask_pii(prompt["prompt"])
        result = {"masked_text": masked_text, "detected_pii": list(pii_map.keys())}

        # Verify PII detection occurred
        assert result is not None
        assert len(result.get("detected_pii", [])) > 0, "Should detect PII"

        # The masked text should not contain original PII
        masked_text = result.get("masked_text", "")
        assert "123-45-6789" not in masked_text, "SSN should be masked"
        assert "4532-1234-5678-9012" not in masked_text, "Credit card should be masked"

    @pytest.mark.asyncio
    async def test_employee_record_pii(self, pii_agent, prompts_data):
        """Test detection of employee record PII."""
        prompt = prompts_data["pii_detection"][1]
        masked_text, pii_map = await pii_agent.mask_pii(prompt["prompt"])
        result = {"masked_text": masked_text, "detected_pii": list(pii_map.keys())}

        # Verify email detection
        assert result is not None
        masked_text = result.get("masked_text", "")
        # Original email should be masked
        assert "jane.smith@company.org" not in masked_text or "[EMAIL]" in masked_text


class TestNetworkSecurityEvents:
    """Test network security event prompts."""

    @pytest.fixture
    def regex_checker(self):
        """Create a regex checker for testing."""
        return RegexChecker()

    @pytest.fixture
    def prompts_data(self):
        """Load prompts from JSON file."""
        data_file = Path(__file__).parent / "test_data" / "prompts.json"
        with open(data_file) as f:
            return json.load(f)

    def test_firewall_block_with_dns_query(self, regex_checker, prompts_data):
        """Test detection of firewall block with DNS query."""
        prompt = prompts_data["network_security_events"][0]
        result = regex_checker.extract_all_iocs(prompt["prompt"])

        # Verify IOC extraction
        assert "185.220.101.42" in result.get("ipv4", []), "Should detect IP"
        assert "bitcoin-miner.ru" in result.get("domain", []), "Should detect domain"
        assert "5d41402abc4b2a76b9719d911017c592" in result.get("md5", []) + result.get(
            "sha1", []
        ) + result.get("sha256", []), "Should detect hash"

    def test_malware_c2_server_detection(self, regex_checker, prompts_data):
        """Test detection of malware C2 server."""
        prompt = prompts_data["network_security_events"][1]
        result = regex_checker.extract_all_iocs(prompt["prompt"])

        # Verify domain extraction (including .onion)
        assert len(result.get("domain", [])) > 0, "Should detect domain"

        # Verify Bitcoin address
        assert len(result.get("bitcoin_address", [])) > 0, (
            "Should detect Bitcoin address"
        )
        assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in result.get("bitcoin_address", [])

        # Verify SHA256 hash
        assert (
            len(
                result.get("md5", [])
                + result.get("sha1", [])
                + result.get("sha256", [])
            )
            > 0
        ), "Should detect hash"


class TestAdvancedPersistentThreats:
    """Test advanced persistent threat prompts."""

    @pytest.fixture
    def regex_checker(self):
        """Create a regex checker for testing."""
        return RegexChecker()

    @pytest.fixture
    def prompts_data(self):
        """Load prompts from JSON file."""
        data_file = Path(__file__).parent / "test_data" / "prompts.json"
        with open(data_file) as f:
            return json.load(f)

    def test_lateral_movement_with_cobalt_strike(self, regex_checker, prompts_data):
        """Test detection of lateral movement with Cobalt Strike."""
        prompt = prompts_data["advanced_persistent_threats"][0]
        result = regex_checker.extract_all_iocs(prompt["prompt"])

        # Verify IP addresses for lateral movement
        assert "10.0.0.15" in result.get("ipv4", []), "Should detect source IP"
        assert "10.0.0.25" in result.get("ipv4", []), "Should detect destination IP"

        # Verify email/credential
        assert len(result.get("email", [])) > 0, "Should detect email"

        # Verify hash
        assert (
            len(
                result.get("md5", [])
                + result.get("sha1", [])
                + result.get("sha256", [])
            )
            > 0
        ), "Should detect payload hash"

    def test_phishing_email_with_bitcoin(self, regex_checker, prompts_data):
        """Test detection of phishing email with Bitcoin."""
        prompt = prompts_data["advanced_persistent_threats"][1]
        result = regex_checker.extract_all_iocs(prompt["prompt"])

        # Verify email detection
        assert len(result.get("email", [])) > 0, "Should detect email"
        assert "suspicious.sender@temp-mail.org" in result.get("email", [])

        # Verify Bitcoin address (P2SH format starting with 3)
        assert len(result.get("bitcoin_address", [])) > 0, (
            "Should detect Bitcoin address"
        )

        # Verify attachment hash
        assert (
            len(
                result.get("md5", [])
                + result.get("sha1", [])
                + result.get("sha256", [])
            )
            > 0
        ), "Should detect attachment hash"


class TestErrorHandling:
    """Test error handling and edge cases."""

    @pytest.fixture
    def regex_checker(self):
        """Create a regex checker for testing."""
        return RegexChecker()

    @pytest.fixture
    def prompts_data(self):
        """Load prompts from JSON file."""
        data_file = Path(__file__).parent / "test_data" / "prompts.json"
        with open(data_file) as f:
            return json.load(f)

    def test_invalid_iocs(self, regex_checker, prompts_data):
        """Test graceful handling of invalid IOCs."""
        prompt = prompts_data["error_handling"][0]

        # Should not raise exception
        result = regex_checker.extract_all_iocs(prompt["prompt"])

        # Should return empty or minimal results (no false positives)
        assert isinstance(result, dict), "Should return dict"
        # Check for actual keys returned by extract_all_iocs
        assert isinstance(result.get("ipv4", []), list), "Should have ipv4 results"

        # Invalid IOCs should not be extracted
        assert "300.400.500.600" not in result.get("ipv4", []), (
            "Should not detect invalid IP"
        )
        assert "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ" not in result.get(
            "md5", []
        ) + result.get("sha1", []) + result.get("sha256", []), (
            "Should not detect invalid hash"
        )

    def test_mixed_valid_invalid_data(self, regex_checker, prompts_data):
        """Test extraction of valid IOCs from mixed data."""
        prompt = prompts_data["error_handling"][1]
        result = regex_checker.extract_all_iocs(prompt["prompt"])

        # Should extract valid data
        assert "8.8.8.8" in result.get("ipv4", []), "Should detect valid IP"
        assert "d41d8cd98f00b204e9800998ecf8427e" in result.get("md5", []) + result.get(
            "sha1", []
        ) + result.get("sha256", []), "Should detect valid hash"

        # Should not extract invalid data
        assert "999.999.999.999" not in result.get("ipv4", []), (
            "Should not detect invalid IP"
        )
        assert "INVALID_HASH_FORMAT" not in result.get("md5", []) + result.get(
            "sha1", []
        ) + result.get("sha256", []), "Should not detect invalid hash"

    def test_rate_limiting_multiple_ips(self, regex_checker, prompts_data):
        """Test extraction of multiple IPs (stress test)."""
        prompt = prompts_data["error_handling"][2]
        result = regex_checker.extract_all_iocs(prompt["prompt"])

        # Should extract all 10 IPs
        assert len(result.get("ipv4", [])) == 10, "Should detect all 10 IPs"

        # Verify specific IPs
        for i in range(1, 11):
            assert f"192.168.1.{i}" in result.get("ipv4", []), (
                f"Should detect 192.168.1.{i}"
            )


class TestImageAnalysis:
    """Test image analysis functionality."""

    @pytest.fixture
    def test_images_dir(self):
        """Get the test images directory."""
        return Path(__file__).parent / "test_images"

    def test_security_logs_screenshot_exists(self, test_images_dir):
        """Test that security logs screenshot exists."""
        image_path = test_images_dir / "security_logs_screenshot.png"
        assert image_path.exists(), "Security logs screenshot should exist"
        assert image_path.is_file(), "Should be a file"

    def test_email_with_pii_exists(self, test_images_dir):
        """Test that email with PII screenshot exists."""
        image_path = test_images_dir / "email_with_pii.png"
        assert image_path.exists(), "Email with PII screenshot should exist"
        assert image_path.is_file(), "Should be a file"

    def test_security_dashboard_exists(self, test_images_dir):
        """Test that security dashboard exists."""
        image_path = test_images_dir / "security_dashboard.png"
        assert image_path.exists(), "Security dashboard should exist"
        assert image_path.is_file(), "Should be a file"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
