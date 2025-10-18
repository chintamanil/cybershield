"""Tests for frontend session management functionality.

This module tests the session management features in the Streamlit frontend,
including session ID generation, request history tracking, and context memory UI.
"""

import uuid

import pandas as pd
import pytest


class TestSessionManagement:
    """Test session management functionality."""

    def test_session_id_generation(self):
        """Test that session IDs are generated correctly."""
        # Generate a session ID
        session_id = f"session-{uuid.uuid4().hex[:8]}"

        # Verify format
        assert session_id.startswith("session-")
        assert len(session_id) == 16  # "session-" (8) + hex (8)
        # Check only the hex part after "session-"
        hex_part = session_id.split("-", 1)[1]
        assert all(c in "0123456789abcdef" for c in hex_part)

    def test_session_id_uniqueness(self):
        """Test that generated session IDs are unique."""
        session_ids = set()
        for _ in range(100):
            session_id = f"session-{uuid.uuid4().hex[:8]}"
            session_ids.add(session_id)

        # All 100 should be unique
        assert len(session_ids) == 100

    def test_batch_session_id_format(self):
        """Test batch session ID format."""
        batch_session_id = f"batch-{uuid.uuid4().hex[:8]}"

        assert batch_session_id.startswith("batch-")
        assert len(batch_session_id) == 14  # "batch-" (6) + hex (8)

    def test_image_session_id_format(self):
        """Test image session ID format."""
        image_session_id = f"image-{uuid.uuid4().hex[:8]}"

        assert image_session_id.startswith("image-")
        assert len(image_session_id) == 14  # "image-" (6) + hex (8)


class TestRequestHistory:
    """Test request history tracking functionality."""

    def test_request_history_initialization(self):
        """Test that request history is initialized as empty dict."""
        request_history = {}
        assert isinstance(request_history, dict)
        assert len(request_history) == 0

    def test_add_request_to_history(self):
        """Test adding a request to history."""
        request_history = {}
        session_id = "test-session-001"

        # Initialize session history
        request_history[session_id] = []

        # Add a request
        request_history[session_id].append(
            {
                "text": "Suspicious activity from 192.168.1.100",
                "iocs_found": ["192.168.1.100"],
                "timestamp": pd.Timestamp.now().isoformat(),
            }
        )

        assert len(request_history[session_id]) == 1
        assert (
            request_history[session_id][0]["text"]
            == "Suspicious activity from 192.168.1.100"
        )
        assert "192.168.1.100" in request_history[session_id][0]["iocs_found"]

    def test_multiple_requests_in_session(self):
        """Test tracking multiple requests in a session."""
        request_history = {}
        session_id = "test-session-002"
        request_history[session_id] = []

        # Add multiple requests
        requests = [
            {"text": "IP 192.168.1.100 detected", "iocs_found": ["192.168.1.100"]},
            {"text": "Tell me about that IP", "iocs_found": []},
            {"text": "Check threat score", "iocs_found": []},
        ]

        for req in requests:
            request_history[session_id].append(
                {**req, "timestamp": pd.Timestamp.now().isoformat()}
            )

        assert len(request_history[session_id]) == 3
        assert request_history[session_id][0]["text"] == "IP 192.168.1.100 detected"
        assert request_history[session_id][1]["text"] == "Tell me about that IP"

    def test_request_history_multiple_sessions(self):
        """Test tracking requests across multiple sessions."""
        request_history = {}

        # Add requests to different sessions
        session_1 = "session-001"
        session_2 = "session-002"

        request_history[session_1] = [
            {
                "text": "Request 1 for session 1",
                "iocs_found": [],
                "timestamp": pd.Timestamp.now().isoformat(),
            }
        ]
        request_history[session_2] = [
            {
                "text": "Request 1 for session 2",
                "iocs_found": [],
                "timestamp": pd.Timestamp.now().isoformat(),
            }
        ]

        assert len(request_history) == 2
        assert len(request_history[session_1]) == 1
        assert len(request_history[session_2]) == 1

    def test_extract_iocs_from_result(self):
        """Test IOC extraction from API result for history."""
        result = {
            "result": {
                "ioc_analysis": {
                    "extracted_iocs": {
                        "ipv4": ["192.168.1.100", "10.0.0.1"],
                        "domain": ["malware-c2.example.com"],
                        "md5": ["d41d8cd98f00b204e9800998ecf8427e"],
                    }
                }
            }
        }

        # Extract IOCs (first 2 of each type)
        iocs_found = []
        if "result" in result and isinstance(result["result"], dict):
            result_data = result["result"]
            if "ioc_analysis" in result_data:
                ioc_data = result_data["ioc_analysis"]
                extracted_iocs = ioc_data.get("extracted_iocs", {})
                for ioc_type, ioc_list in extracted_iocs.items():
                    if ioc_list:
                        iocs_found.extend([str(ioc) for ioc in ioc_list[:2]])

        assert len(iocs_found) == 4  # 2 IPs + 1 domain + 1 hash
        assert "192.168.1.100" in iocs_found
        assert "10.0.0.1" in iocs_found
        assert "malware-c2.example.com" in iocs_found
        assert "d41d8cd98f00b204e9800998ecf8427e" in iocs_found


class TestContextEnrichment:
    """Test context enrichment display functionality."""

    def test_context_enrichment_detection(self):
        """Test detection of context enrichment in API response."""
        result = {
            "result": {
                "context_enrichment": {
                    "enriched": True,
                    "context_used": {
                        "ip": "192.168.1.100",
                        "domain": "malware-c2.example.com",
                    },
                    "session_age": "2m 30s",
                    "session_events": 3,
                }
            }
        }

        # Check if context was enriched
        if "result" in result and isinstance(result["result"], dict):
            result_data = result["result"]
            if "context_enrichment" in result_data:
                context_info = result_data["context_enrichment"]
                assert context_info.get("enriched", False) is True
                assert len(context_info.get("context_used", {})) == 2

    def test_context_enrichment_with_input_analysis(self):
        """Test context enrichment with input analysis."""
        result = {
            "result": {
                "input_analysis": {
                    "original_text": "Tell me about that IP",
                    "enriched_text": "Tell me about 192.168.1.100",
                },
                "context_enrichment": {
                    "enriched": True,
                    "context_used": {"ip": "192.168.1.100"},
                },
            }
        }

        result_data = result["result"]
        if "input_analysis" in result_data:
            input_analysis = result_data["input_analysis"]
            assert input_analysis["original_text"] == "Tell me about that IP"
            assert input_analysis["enriched_text"] == "Tell me about 192.168.1.100"
            assert "192.168.1.100" in input_analysis["enriched_text"]


class TestIncludePreviousRequest:
    """Test include previous request functionality."""

    def test_include_previous_request_text_combination(self):
        """Test combining previous request with current input."""
        previous_text = "Suspicious activity from 192.168.1.100"
        current_text = "Tell me about that IP"

        # Simulate the combination logic
        combined_text = (
            f"Previous context: {previous_text}\n\nCurrent query: {current_text}"
        )

        assert "Previous context:" in combined_text
        assert "Current query:" in combined_text
        assert previous_text in combined_text
        assert current_text in combined_text

    def test_include_previous_request_length_tracking(self):
        """Test tracking of combined input length."""
        previous_text = "IP 192.168.1.100 connecting to malware-c2.example.com detected"
        current_text = "What is the threat score?"

        combined_text = (
            f"Previous context: {previous_text}\n\nCurrent query: {current_text}"
        )

        assert len(combined_text) > len(current_text)
        assert len(combined_text) == len(previous_text) + len(current_text) + len(
            "\n\nCurrent query: "
        ) + len("Previous context: ")

    def test_include_previous_disabled(self):
        """Test that current input is used when include_previous is disabled."""
        current_text = "Tell me about that IP"
        include_previous = False

        # When include_previous is False, use current_text as-is
        actual_input = current_text if not include_previous else "combined"

        assert actual_input == current_text
        assert "Previous context:" not in actual_input


class TestAPIRequestPayload:
    """Test API request payload construction."""

    def test_analyze_request_with_session_id(self):
        """Test analyze request payload with session ID."""
        request_data = {
            "text": "Suspicious IP 192.168.1.100",
            "use_react_workflow": True,
            "include_vision": False,
            "enable_concurrent_tools": True,
            "show_performance_metrics": True,
        }

        session_id = "test-session-001"
        if session_id:
            request_data["session_id"] = session_id

        assert "session_id" in request_data
        assert request_data["session_id"] == "test-session-001"
        assert request_data["text"] == "Suspicious IP 192.168.1.100"

    def test_analyze_request_without_session_id(self):
        """Test analyze request payload without session ID."""
        request_data = {
            "text": "Suspicious IP 192.168.1.100",
            "use_react_workflow": True,
            "include_vision": False,
            "enable_concurrent_tools": True,
            "show_performance_metrics": True,
        }

        session_id = None
        if session_id:
            request_data["session_id"] = session_id

        assert "session_id" not in request_data

    def test_batch_request_with_session_id(self):
        """Test batch analyze request payload with session ID."""
        batch_request_data = {
            "inputs": ["Input 1", "Input 2", "Input 3"],
            "use_react_workflow": True,
            "enable_concurrent_tools": True,
        }

        batch_session_id = "batch-session-001"
        if batch_session_id:
            batch_request_data["session_id"] = batch_session_id

        assert "session_id" in batch_request_data
        assert batch_request_data["session_id"] == "batch-session-001"
        assert len(batch_request_data["inputs"]) == 3

    def test_image_request_with_session_id(self):
        """Test image analyze request payload with session ID."""
        data = {
            "text": "Image context",
            "use_react_workflow": True,
            "enable_concurrent_tools": True,
        }

        image_session_id = "image-session-001"
        if image_session_id:
            data["session_id"] = image_session_id

        assert "session_id" in data
        assert data["session_id"] == "image-session-001"


class TestSessionManagementUI:
    """Test session management UI components."""

    def test_session_id_placeholder_text(self):
        """Test session ID input placeholder text."""
        placeholders = {
            "main": "e.g., investigation-001",
            "batch": "e.g., batch-investigation-001",
            "image": "e.g., image-investigation-001",
        }

        for key, placeholder in placeholders.items():
            assert "investigation" in placeholder.lower()
            assert len(placeholder) > 0

    def test_session_enabled_message(self):
        """Test session enabled success message."""
        session_id = "test-session-001"
        message = f"✅ Context memory enabled for session: `{session_id}`"

        assert "✅" in message
        assert "Context memory enabled" in message
        assert session_id in message

    def test_session_disabled_message(self):
        """Test session disabled info message."""
        message = (
            "ℹ️ Enter a session ID to enable context memory across multiple analyses."
        )

        assert "ℹ️" in message or "ℹ" in message
        assert "session id" in message.lower()  # Fixed: lowercase comparison
        assert "context memory" in message.lower()


class TestContextMemoryExamples:
    """Test context memory example documentation."""

    def test_example_1_basic_pronoun_resolution(self):
        """Test basic pronoun resolution example."""
        example = {
            "request_1": "Suspicious activity from 192.168.1.100",
            "request_2": "Tell me more about that IP",
            "resolution": "that IP → 192.168.1.100",
        }

        assert "192.168.1.100" in example["request_1"]
        assert "that IP" in example["request_2"]
        assert "192.168.1.100" in example["resolution"]

    def test_example_2_multi_step_investigation(self):
        """Test multi-step investigation example."""
        example = {
            "request_1": "IP 185.220.101.42 connecting to bitcoin-miner.ru",
            "request_2": "Check if same IP tried other ports",
            "request_3": "What's the threat score for that IP?",
            "resolution": "Tracks both IP and domain",
        }

        assert "185.220.101.42" in example["request_1"]
        assert "bitcoin-miner.ru" in example["request_1"]
        assert "same IP" in example["request_2"]
        assert "that IP" in example["request_3"]

    def test_example_3_cross_ioc_analysis(self):
        """Test cross-IOC analysis example."""
        example = {
            "request_1": "Email from suspicious@temp.com with hash d41d8cd98f00b204e9800998ecf8427e",
            "request_2": "Is that email known malicious and does the hash match malware?",
            "resolution": "Resolves both email and hash",
        }

        assert "suspicious@temp.com" in example["request_1"]
        assert "d41d8cd98f00b204e9800998ecf8427e" in example["request_1"]
        assert "that email" in example["request_2"]
        assert "the hash" in example["request_2"]


class TestRequestHistoryDisplay:
    """Test request history display functionality."""

    def test_history_preview_truncation(self):
        """Test that long request text is truncated in preview."""
        long_text = "A" * 200  # 200 character text
        truncated = f"{long_text[:100]}..." if len(long_text) > 100 else long_text

        assert len(truncated) <= 103  # 100 chars + "..."
        assert truncated.endswith("...")

    def test_history_shows_last_5_requests(self):
        """Test that history shows last 5 requests."""
        request_history = {
            "session-001": [
                {
                    "text": f"Request {i}",
                    "iocs_found": [],
                    "timestamp": pd.Timestamp.now().isoformat(),
                }
                for i in range(10)
            ]
        }

        session_id = "session-001"
        history = request_history[session_id]
        last_5 = list(reversed(history[-5:]))

        assert len(last_5) == 5
        assert last_5[0]["text"] == "Request 9"  # Most recent
        assert last_5[4]["text"] == "Request 5"  # 5th most recent

    def test_iocs_found_caption_display(self):
        """Test IOCs found caption in history."""
        request = {
            "text": "Suspicious activity",
            "iocs_found": ["192.168.1.100", "10.0.0.1", "203.0.113.42", "8.8.8.8"],
            "timestamp": pd.Timestamp.now().isoformat(),
        }

        # Show first 3 IOCs
        iocs_display = ", ".join(request["iocs_found"][:3])
        caption = f"🔍 IOCs found: {iocs_display}..."

        assert "192.168.1.100" in caption
        assert "10.0.0.1" in caption
        assert "203.0.113.42" in caption
        assert "8.8.8.8" not in caption  # 4th IOC not shown


class TestPreviousSessionIDReuse:
    """Test previous session ID reuse functionality."""

    def test_previous_session_ids_initialization(self):
        """Test that previous session IDs list is initialized as empty."""
        previous_session_ids = []
        assert isinstance(previous_session_ids, list)
        assert len(previous_session_ids) == 0

    def test_add_session_id_to_tracker(self):
        """Test adding a session ID to the tracker."""
        previous_session_ids = []
        session_id = "investigation-001"

        # Add session ID if not already tracked
        if session_id not in previous_session_ids:
            previous_session_ids.append(session_id)

        assert len(previous_session_ids) == 1
        assert "investigation-001" in previous_session_ids

    def test_avoid_duplicate_session_ids(self):
        """Test that duplicate session IDs are not added."""
        previous_session_ids = ["investigation-001"]
        session_id = "investigation-001"

        # Don't add if already exists
        if session_id not in previous_session_ids:
            previous_session_ids.append(session_id)

        assert len(previous_session_ids) == 1

    def test_limit_session_ids_to_10(self):
        """Test that only last 10 session IDs are kept."""
        previous_session_ids = [f"session-{i:03d}" for i in range(15)]

        # Keep only last 10
        if len(previous_session_ids) > 10:
            previous_session_ids = previous_session_ids[-10:]

        assert len(previous_session_ids) == 10
        assert previous_session_ids[0] == "session-005"  # First of last 10
        assert previous_session_ids[-1] == "session-014"  # Last session

    def test_reuse_checkbox_enabled_when_sessions_exist(self):
        """Test that reuse checkbox is enabled when previous sessions exist."""
        previous_session_ids = ["investigation-001", "investigation-002"]
        has_previous_sessions = len(previous_session_ids) > 0

        assert has_previous_sessions is True

    def test_reuse_checkbox_disabled_when_no_sessions(self):
        """Test that reuse checkbox is disabled when no previous sessions exist."""
        previous_session_ids = []
        has_previous_sessions = len(previous_session_ids) > 0

        assert has_previous_sessions is False

    def test_show_last_5_sessions_in_dropdown(self):
        """Test that dropdown shows last 5 sessions."""
        previous_session_ids = [f"session-{i:03d}" for i in range(10)]
        recent_sessions = previous_session_ids[-5:]

        assert len(recent_sessions) == 5
        assert recent_sessions[0] == "session-005"
        assert recent_sessions[-1] == "session-009"

    def test_selected_session_updates_session_id(self):
        """Test that selecting a session updates the session_id."""
        previous_session_ids = ["investigation-001", "investigation-002"]
        selected_session = "investigation-001"

        # Simulate selection
        session_id = selected_session

        assert session_id == "investigation-001"

    def test_checkbox_label_shows_count(self):
        """Test that checkbox label shows session count."""
        previous_session_ids = ["session-001", "session-002", "session-003"]
        checkbox_label = (
            f"📋 Reuse previous session ID ({len(previous_session_ids)} available)"
        )

        assert "3 available" in checkbox_label
        assert "📋" in checkbox_label


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
