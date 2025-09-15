# Test script for Temporal models (without SDK dependencies)
import sys
import os

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from workflows.temporal.models import (
    AnalysisRequest,
    AnalysisType,
    IOCs,
    create_empty_iocs,
    validate_analysis_request,
    merge_iocs,
    RiskLevel,
    calculate_overall_risk_level,
)

def test_analysis_request():
    """Test AnalysisRequest model"""
    print("Testing AnalysisRequest model...")

    # Test basic creation
    request = AnalysisRequest(
        text="Test security analysis with IP 192.168.1.1",
        analysis_type=AnalysisType.COMPREHENSIVE,
        request_id="test-001"
    )

    assert request.text == "Test security analysis with IP 192.168.1.1"
    assert request.analysis_type == AnalysisType.COMPREHENSIVE
    assert request.request_id == "test-001"
    assert request.image_data is None
    assert request.context == {}  # Should be initialized to empty dict

    print("✅ AnalysisRequest creation test passed")

    # Test validation
    errors = validate_analysis_request(request)
    assert len(errors) == 0, f"Should have no validation errors, got: {errors}"
    print("✅ AnalysisRequest validation test passed")

    # Test validation with empty text
    empty_request = AnalysisRequest(
        text="",
        analysis_type=AnalysisType.BASIC,
        request_id="test-002"
    )
    errors = validate_analysis_request(empty_request)
    assert len(errors) > 0, "Should have validation errors for empty text"
    print("✅ AnalysisRequest empty text validation test passed")


def test_iocs_model():
    """Test IOCs model"""
    print("Testing IOCs model...")

    # Test empty IOCs
    empty_iocs = create_empty_iocs()
    assert len(empty_iocs.ips) == 0
    assert len(empty_iocs.domains) == 0
    assert len(empty_iocs.hashes) == 0
    print("✅ Empty IOCs test passed")

    # Test IOCs with data
    iocs = IOCs(
        ips=["192.168.1.1", "10.0.0.1"],
        domains=["example.com", "test.org"],
        hashes=["d41d8cd98f00b204e9800998ecf8427e"],
        urls=["http://example.com"],
        emails=["test@example.com"],
        file_paths=["/etc/passwd"]
    )

    assert len(iocs.ips) == 2
    assert len(iocs.domains) == 2
    assert len(iocs.hashes) == 1
    print("✅ IOCs with data test passed")

    # Test merging IOCs
    iocs1 = IOCs(
        ips=["1.1.1.1"],
        domains=["domain1.com"],
        hashes=["hash1"],
        urls=["url1"],
        emails=["email1"],
        file_paths=["path1"]
    )

    iocs2 = IOCs(
        ips=["2.2.2.2", "1.1.1.1"],  # Duplicate IP should be deduplicated
        domains=["domain2.com"],
        hashes=["hash2"],
        urls=["url2"],
        emails=["email2"],
        file_paths=["path2"]
    )

    merged = merge_iocs([iocs1, iocs2])
    assert len(merged.ips) == 2  # Should deduplicate
    assert len(merged.domains) == 2
    assert "1.1.1.1" in merged.ips
    assert "2.2.2.2" in merged.ips
    print("✅ IOCs merging test passed")


def test_risk_assessment():
    """Test risk assessment logic"""
    print("Testing risk assessment...")

    # Test risk level escalation
    from workflows.temporal.models import ThreatAnalysis

    # Low risk threat analysis
    low_risk_analysis = ThreatAnalysis(
        tool_results=[],
        threat_summary={},
        risk_assessment={"low": 5, "medium": 0, "high": 0, "critical": 0},
        high_risk_indicators=[],
        recommendations=[]
    )

    risk_level = calculate_overall_risk_level(low_risk_analysis)
    assert risk_level == RiskLevel.LOW
    print("✅ Low risk assessment test passed")

    # High risk threat analysis
    high_risk_analysis = ThreatAnalysis(
        tool_results=[],
        threat_summary={},
        risk_assessment={"low": 0, "medium": 0, "high": 3, "critical": 1},
        high_risk_indicators=[],
        recommendations=[]
    )

    risk_level = calculate_overall_risk_level(high_risk_analysis)
    assert risk_level == RiskLevel.CRITICAL
    print("✅ High risk assessment test passed")


def test_analysis_type():
    """Test analysis type enum"""
    print("Testing AnalysisType enum...")

    assert AnalysisType.BASIC == "basic"
    assert AnalysisType.COMPREHENSIVE == "comprehensive"
    assert AnalysisType.THREAT_INTEL == "threat_intel"
    assert AnalysisType.VISION_ANALYSIS == "vision_analysis"
    assert AnalysisType.PII_DETECTION == "pii_detection"

    print("✅ AnalysisType enum test passed")


def test_model_conversion():
    """Test model conversion functions"""
    print("Testing model conversion...")

    # Test LangChain state conversion
    from workflows.temporal.models import convert_langchain_state_to_request

    langchain_state = {
        "input_text": "Test security analysis",
        "input_image": b"fake_image_data",
        "request_id": "langchain-001",
        "session_id": "session-123",
        "context": {"source": "legacy"}
    }

    request = convert_langchain_state_to_request(langchain_state)
    assert request.text == "Test security analysis"
    assert request.image_data == b"fake_image_data"
    assert request.request_id == "langchain-001"
    assert request.session_id == "session-123"
    assert request.context == {"source": "legacy"}

    print("✅ LangChain state conversion test passed")


def main():
    """Run all model tests"""
    print("🔧 Running Temporal Models Tests")
    print("=" * 50)

    tests = [
        ("AnalysisRequest Model", test_analysis_request),
        ("IOCs Model", test_iocs_model),
        ("Risk Assessment", test_risk_assessment),
        ("AnalysisType Enum", test_analysis_type),
        ("Model Conversion", test_model_conversion),
    ]

    passed = 0
    total = len(tests)

    for test_name, test_func in tests:
        print(f"\n📋 Running {test_name}...")
        try:
            test_func()
            passed += 1
            print(f"✅ {test_name} completed")
        except Exception as e:
            print(f"❌ {test_name} failed: {e}")
            import traceback
            traceback.print_exc()

    print("\n" + "=" * 50)
    print(f"🎯 Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All model tests passed! Temporal models are working correctly.")
        return True
    else:
        print("⚠️ Some tests failed. Please review and fix model issues.")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)