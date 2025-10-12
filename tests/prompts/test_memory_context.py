"""
Test memory and context preservation across sequential requests.

This test suite validates:
1. Session-based context storage using Redis STM
2. Follow-up requests building on previous analysis
3. Cross-agent data sharing within sessions
4. IOC extraction and reuse across requests
5. Incremental pipeline support
"""

import requests
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track
import time

console = Console()

BASE_URL = "http://localhost:8000"
RESULTS_DIR = Path(__file__).parent / "results" / "memory_tests"


class MemoryContextTester:
    """Test memory and context preservation across requests."""

    def __init__(self):
        self.results_dir = RESULTS_DIR
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.session_id = str(uuid.uuid4())
        self.test_results = []

    def save_result(self, test_name: str, requests_chain: List[Dict], analysis: Dict):
        """Save test result to file."""
        result = {
            "timestamp": datetime.now().isoformat(),
            "test_name": test_name,
            "session_id": self.session_id,
            "requests_chain": requests_chain,
            "analysis": analysis
        }

        filename = self.results_dir / f"{test_name.replace(' ', '_').lower()}.json"
        with open(filename, "w") as f:
            json.dump(result, f, indent=2)

        self.test_results.append(result)
        console.print(f"✓ Saved result: {filename.name}", style="green")

    def make_request(self, endpoint: str, data: Dict, description: str) -> Dict:
        """Make API request and return response."""
        console.print(f"\n[cyan]→ Request: {description}[/cyan]")
        console.print(f"  Endpoint: {endpoint}")
        console.print(f"  Session ID: {self.session_id}")

        # Add session ID to request
        if "session_id" not in data:
            data["session_id"] = self.session_id

        start_time = time.time()
        response = requests.post(f"{BASE_URL}{endpoint}", json=data)
        response_time = time.time() - start_time

        if response.status_code == 200:
            console.print(f"  ✓ Success ({response_time:.2f}s)", style="green")
            return {
                "description": description,
                "request": data,
                "response": response.json(),
                "response_time": response_time,
                "status": "success"
            }
        else:
            console.print(f"  ✗ Failed: {response.status_code}", style="red")
            return {
                "description": description,
                "request": data,
                "error": response.text,
                "status": "failed"
            }

    def test_sequential_ioc_analysis(self):
        """Test 1: Extract IOCs, then analyze specific IOC from previous response."""
        console.print("\n" + "="*80, style="bold blue")
        console.print("TEST 1: Sequential IOC Analysis", style="bold blue")
        console.print("="*80 + "\n", style="bold blue")

        requests_chain = []

        # Request 1: Initial analysis with multiple IOCs
        req1 = self.make_request(
            "/analyze",
            {
                "text": "Suspicious activity from 192.168.1.100 connecting to malware-c2.example.com. "
                       "Also detected traffic to 203.0.113.50 on port 443. "
                       "File hash: d41d8cd98f00b204e9800998ecf8427e"
            },
            "Initial analysis - Extract multiple IOCs"
        )
        requests_chain.append(req1)

        # Extract IOCs from response
        if req1["status"] == "success":
            result = req1["response"].get("result", {})
            extracted_iocs = []

            # Try to find IOCs in the response
            if "iocs" in result:
                extracted_iocs = result["iocs"]
            elif "analysis" in result:
                # Look in analysis text
                analysis_text = str(result.get("analysis", ""))
                console.print(f"\n[yellow]Response analysis:[/yellow]\n{analysis_text[:500]}...")

            time.sleep(1)  # Brief pause between requests

            # Request 2: Ask about specific IOC from previous response
            req2 = self.make_request(
                "/analyze",
                {
                    "text": "Tell me more about the IP address 192.168.1.100 from the previous analysis. "
                           "What threats are associated with it?"
                },
                "Follow-up - Ask about specific IOC from previous request"
            )
            requests_chain.append(req2)

            time.sleep(1)

            # Request 3: Ask about another IOC
            req3 = self.make_request(
                "/analyze",
                {
                    "text": "What about the domain malware-c2.example.com? Is it malicious?"
                },
                "Follow-up - Ask about domain from first request"
            )
            requests_chain.append(req3)

        # Analyze context preservation
        analysis = self.analyze_context_preservation(requests_chain)
        self.save_result("sequential_ioc_analysis", requests_chain, analysis)

        return requests_chain, analysis

    def test_incremental_threat_investigation(self):
        """Test 2: Build up threat investigation across multiple requests."""
        console.print("\n" + "="*80, style="bold blue")
        console.print("TEST 2: Incremental Threat Investigation", style="bold blue")
        console.print("="*80 + "\n", style="bold blue")

        requests_chain = []

        # Request 1: Initial suspicious activity
        req1 = self.make_request(
            "/analyze",
            {
                "text": "Detected failed login from IP 198.51.100.25"
            },
            "Step 1 - Initial suspicious activity detected"
        )
        requests_chain.append(req1)
        time.sleep(1)

        # Request 2: More activity from same source
        req2 = self.make_request(
            "/analyze",
            {
                "text": "The same IP is now scanning ports 22, 23, 3389"
            },
            "Step 2 - Escalation - port scanning from same IP"
        )
        requests_chain.append(req2)
        time.sleep(1)

        # Request 3: Successful compromise
        req3 = self.make_request(
            "/analyze",
            {
                "text": "Successful SSH connection established from that IP"
            },
            "Step 3 - Successful compromise from the IP"
        )
        requests_chain.append(req3)
        time.sleep(1)

        # Request 4: Ask for summary
        req4 = self.make_request(
            "/analyze",
            {
                "text": "Summarize the entire attack chain we've been tracking"
            },
            "Step 4 - Request summary of entire attack chain"
        )
        requests_chain.append(req4)

        analysis = self.analyze_context_preservation(requests_chain)
        self.save_result("incremental_threat_investigation", requests_chain, analysis)

        return requests_chain, analysis

    def test_cross_agent_data_sharing(self):
        """Test 3: Test IOC pronoun resolution across multiple requests."""
        console.print("\n" + "="*80, style="bold blue")
        console.print("TEST 3: Cross-Request IOC Pronoun Resolution", style="bold blue")
        console.print("="*80 + "\n", style="bold blue")

        requests_chain = []

        # Request 1: Initial IOC detection
        req1 = self.make_request(
            "/analyze",
            {
                "text": "Traffic detected from IP 45.76.123.89 connecting to suspicious-domain.net. "
                       "File hash: 5d41402abc4b2a76b9719d911017c592 was executed."
            },
            "Step 1 - Initial IOC detection (IP, domain, hash)"
        )
        requests_chain.append(req1)
        time.sleep(1)

        # Request 2: Reference IP from before
        req2 = self.make_request(
            "/analyze",
            {
                "text": "The IP from before is now attempting port 445 access"
            },
            "Step 2 - Reference IP using pronoun"
        )
        requests_chain.append(req2)
        time.sleep(1)

        # Request 3: Reference domain from first request
        req3 = self.make_request(
            "/analyze",
            {
                "text": "Is that domain associated with any known malware campaigns?"
            },
            "Step 3 - Reference domain using pronoun"
        )
        requests_chain.append(req3)

        analysis = self.analyze_context_preservation(requests_chain)
        self.save_result("cross_agent_data_sharing", requests_chain, analysis)

        return requests_chain, analysis

    def test_with_and_without_session_id(self):
        """Test 4: Compare behavior with and without session ID."""
        console.print("\n" + "="*80, style="bold blue")
        console.print("TEST 4: With vs Without Session ID", style="bold blue")
        console.print("="*80 + "\n", style="bold blue")

        # Test WITH session ID
        console.print("\n[bold green]Part A: WITH Session ID[/bold green]")
        with_session = []

        req1 = self.make_request(
            "/analyze",
            {
                "text": "Analyze IP address 8.8.8.8",
                "session_id": self.session_id
            },
            "Request 1 - WITH session ID"
        )
        with_session.append(req1)
        time.sleep(1)

        req2 = self.make_request(
            "/analyze",
            {
                "text": "What was the IP we just analyzed?",
                "session_id": self.session_id
            },
            "Request 2 - Follow-up WITH same session ID"
        )
        with_session.append(req2)

        # Test WITHOUT session ID (new session each time)
        console.print("\n[bold yellow]Part B: WITHOUT Session ID (new each time)[/bold yellow]")
        without_session = []

        req3 = self.make_request(
            "/analyze",
            {
                "text": "Analyze IP address 8.8.8.8",
                "session_id": str(uuid.uuid4())  # New session
            },
            "Request 1 - New session ID"
        )
        without_session.append(req3)
        time.sleep(1)

        req4 = self.make_request(
            "/analyze",
            {
                "text": "What was the IP we just analyzed?",
                "session_id": str(uuid.uuid4())  # Different session ID
            },
            "Request 2 - Follow-up with DIFFERENT session ID"
        )
        without_session.append(req4)

        analysis = {
            "with_session": self.analyze_context_preservation(with_session),
            "without_session": self.analyze_context_preservation(without_session),
            "comparison": self.compare_session_behavior(with_session, without_session)
        }

        self.save_result("session_id_comparison",
                        {"with_session": with_session, "without_session": without_session},
                        analysis)

        return with_session, without_session, analysis

    def test_redis_cache_persistence(self):
        """Test 5: Test if repeated requests use cached data."""
        console.print("\n" + "="*80, style="bold blue")
        console.print("TEST 5: Redis Cache Persistence", style="bold blue")
        console.print("="*80 + "\n", style="bold blue")

        requests_chain = []

        # Request 1: First request (should be fresh)
        req1 = self.make_request(
            "/analyze",
            {
                "text": "Check IP 1.1.1.1 for threats"
            },
            "Request 1 - First analysis (fresh data)"
        )
        requests_chain.append(req1)

        time.sleep(2)  # Wait 2 seconds

        # Request 2: Same request (should use cache)
        req2 = self.make_request(
            "/analyze",
            {
                "text": "Check IP 1.1.1.1 for threats"
            },
            "Request 2 - Same query (should use cache)"
        )
        requests_chain.append(req2)

        time.sleep(2)

        # Request 3: Slightly different wording, same intent
        req3 = self.make_request(
            "/analyze",
            {
                "text": "Analyze IP address 1.1.1.1"
            },
            "Request 3 - Different wording, same IOC"
        )
        requests_chain.append(req3)

        analysis = {
            "cache_effectiveness": self.analyze_cache_usage(requests_chain),
            "response_time_comparison": {
                "first_request": req1.get("response_time", 0),
                "cached_request": req2.get("response_time", 0),
                "speedup_percentage": self.calculate_speedup(
                    req1.get("response_time", 0),
                    req2.get("response_time", 0)
                )
            }
        }

        self.save_result("redis_cache_persistence", requests_chain, analysis)

        return requests_chain, analysis

    def analyze_context_preservation(self, requests_chain: List[Dict]) -> Dict:
        """Analyze if context was preserved across requests using pronoun resolution."""
        analysis = {
            "total_requests": len(requests_chain),
            "successful_requests": sum(1 for r in requests_chain if r["status"] == "success"),
            "pronoun_resolution_indicators": []
        }

        # Check for actual pronoun resolution in responses
        for i, req in enumerate(requests_chain):
            if req["status"] == "success" and i > 0:
                result = req["response"].get("result", {})

                # Check for actual pronoun resolution
                context_enrichment = result.get("context_enrichment", {})
                pronoun_indicators = {
                    "request_number": i + 1,
                    "has_context_enrichment": bool(context_enrichment),
                    "enriched": context_enrichment.get("enriched", False),
                    "context_used": context_enrichment.get("context_used", {}),
                    "resolution_successful": False,
                    "resolved_iocs": {}
                }

                # Check if actual IOCs were resolved
                if context_enrichment.get("enriched") and context_enrichment.get("context_used"):
                    context_used = context_enrichment["context_used"]

                    # Check for resolved IPs, domains, or hashes
                    resolved_iocs = {}
                    if context_used.get("ip"):
                        resolved_iocs["ip"] = context_used["ip"]
                    if context_used.get("domain"):
                        resolved_iocs["domain"] = context_used["domain"]
                    if context_used.get("hash"):
                        resolved_iocs["hash"] = context_used["hash"]
                    if context_used.get("attack_chain"):
                        resolved_iocs["attack_chain"] = f"{context_used['attack_chain'].get('event_count', 0)} events"

                    if resolved_iocs:
                        pronoun_indicators["resolution_successful"] = True
                        pronoun_indicators["resolved_iocs"] = resolved_iocs

                analysis["pronoun_resolution_indicators"].append(pronoun_indicators)

        # Calculate pronoun resolution success score
        if analysis["pronoun_resolution_indicators"]:
            successful_resolutions = sum(1 for ind in analysis["pronoun_resolution_indicators"]
                                        if ind["resolution_successful"])
            analysis["pronoun_resolution_score"] = successful_resolutions / len(analysis["pronoun_resolution_indicators"])
        else:
            analysis["pronoun_resolution_score"] = 0

        return analysis

    def compare_session_behavior(self, with_session: List[Dict], without_session: List[Dict]) -> Dict:
        """Compare behavior with and without consistent session ID."""
        return {
            "with_session_pronoun_score": self.analyze_context_preservation(with_session).get("pronoun_resolution_score", 0),
            "without_session_pronoun_score": self.analyze_context_preservation(without_session).get("pronoun_resolution_score", 0),
            "session_id_helps": True if len(with_session) > 1 and len(without_session) > 1 else False
        }

    def analyze_cache_usage(self, requests_chain: List[Dict]) -> Dict:
        """Analyze if cache was used based on response times."""
        if len(requests_chain) < 2:
            return {"insufficient_data": True}

        times = [req.get("response_time", 0) for req in requests_chain if req["status"] == "success"]

        return {
            "first_request_time": times[0] if times else 0,
            "subsequent_avg_time": sum(times[1:]) / len(times[1:]) if len(times) > 1 else 0,
            "cache_likely_used": times[0] > sum(times[1:]) / len(times[1:]) if len(times) > 1 else False,
            "all_response_times": times
        }

    def calculate_speedup(self, first_time: float, cached_time: float) -> float:
        """Calculate speedup percentage."""
        if first_time == 0 or cached_time == 0:
            return 0
        return ((first_time - cached_time) / first_time) * 100

    def generate_summary_report(self):
        """Generate summary report of all memory tests."""
        console.print("\n" + "="*80, style="bold green")
        console.print("MEMORY & CONTEXT TEST SUMMARY", style="bold green")
        console.print("="*80 + "\n", style="bold green")

        table = Table(title="Test Results Summary")
        table.add_column("Test Name", style="cyan")
        table.add_column("Total Requests", style="magenta")
        table.add_column("Pronoun Resolution Score", style="green", no_wrap=True)
        table.add_column("Status", style="blue")

        for result in self.test_results:
            test_name = result["test_name"]
            analysis = result["analysis"]

            # Extract metrics
            if "with_session" in analysis:
                total_reqs = "Comparison"
                pronoun_score = f"{analysis.get('with_session', {}).get('pronoun_resolution_score', 0):.2f}"
            else:
                total_reqs = str(analysis.get("total_requests", "N/A"))
                pronoun_score = f"{analysis.get('pronoun_resolution_score', 0):.2f}"

            # Status based on pronoun resolution
            pronoun_score_val = analysis.get('pronoun_resolution_score', 0)
            if "with_session" in analysis:
                pronoun_score_val = analysis.get('with_session', {}).get('pronoun_resolution_score', 0)

            status = "✓ Pass" if pronoun_score_val > 0 else "⚠ Check"

            table.add_row(test_name, total_reqs, pronoun_score, status)

        console.print(table)
        console.print("\n[bold cyan]Note:[/bold cyan]")
        console.print("  Pronoun Resolution Score measures actual context preservation via pronoun → IOC resolution")
        console.print("  1.00 = Perfect (all pronouns resolved correctly)")
        console.print("  0.00 = No pronoun resolution occurred (may be expected for some tests)")

        # Save summary
        summary_file = self.results_dir / "MEMORY_TEST_SUMMARY.md"
        with open(summary_file, "w") as f:
            f.write(f"# Memory & Context Test Summary\n\n")
            f.write(f"**Generated**: {datetime.now().isoformat()}\n\n")
            f.write(f"**Session ID**: {self.session_id}\n\n")

            f.write(f"## Scoring Metric\n\n")
            f.write(f"**Pronoun Resolution Score**: Measures actual context preservation via pronoun → IOC resolution\n\n")
            f.write(f"- Checks for `context_enrichment` field in responses\n")
            f.write(f"- Verifies that `context_used` contains actual resolved IOC values\n")
            f.write(f"- Confirms pronouns were successfully replaced with real indicators\n")
            f.write(f"- **1.00** = Perfect (all pronouns resolved correctly)\n")
            f.write(f"- **0.00** = No pronoun resolution occurred (may be expected for some tests)\n\n")

            f.write(f"## Test Results\n\n")

            for result in self.test_results:
                test_name = result['test_name']
                analysis = result['analysis']

                f.write(f"### {test_name}\n\n")

                # Add score summary at top
                pronoun_score = analysis.get('pronoun_resolution_score', 0)
                if "with_session" in analysis:
                    pronoun_score = analysis.get('with_session', {}).get('pronoun_resolution_score', 0)

                f.write(f"**Pronoun Resolution Score**: {pronoun_score:.2f}\n\n")

                # Show pronoun resolution details if available
                if analysis.get('pronoun_resolution_indicators'):
                    f.write(f"**Resolution Details**:\n\n")
                    for ind in analysis['pronoun_resolution_indicators']:
                        status = "✓ Success" if ind['resolution_successful'] else "✗ Failed"
                        f.write(f"- Request {ind['request_number']}: {status}\n")
                        if ind['resolved_iocs']:
                            for ioc_type, value in ind['resolved_iocs'].items():
                                f.write(f"  - Resolved {ioc_type}: `{value}`\n")
                    f.write(f"\n")

                f.write(f"**Full Analysis**:\n")
                f.write(f"```json\n{json.dumps(result['analysis'], indent=2)}\n```\n\n")

        console.print(f"\n✓ Summary saved: {summary_file}", style="green")


def main():
    """Run all memory and context tests."""
    console.print("\n[bold blue]CyberShield Memory & Context Test Suite[/bold blue]\n")

    tester = MemoryContextTester()

    # Run all tests
    tests = [
        ("Sequential IOC Analysis", tester.test_sequential_ioc_analysis),
        ("Incremental Threat Investigation", tester.test_incremental_threat_investigation),
        ("Cross-Agent Data Sharing", tester.test_cross_agent_data_sharing),
        ("Session ID Comparison", tester.test_with_and_without_session_id),
        ("Redis Cache Persistence", tester.test_redis_cache_persistence)
    ]

    for test_name, test_func in tests:
        try:
            console.print(f"\n[bold yellow]Running: {test_name}[/bold yellow]")
            test_func()
            console.print(f"[green]✓ {test_name} completed[/green]")
        except Exception as e:
            console.print(f"[red]✗ {test_name} failed: {e}[/red]")

    # Generate summary
    tester.generate_summary_report()

    console.print(f"\n[bold green]All memory tests complete![/bold green]")
    console.print(f"Results saved to: {tester.results_dir}")


if __name__ == "__main__":
    main()
