#!/usr/bin/env python3
"""
Demonstration script for context preservation across sequential requests.

This script demonstrates:
1. Session-based context with consistent session_id
2. Pronoun resolution ("same IP" → actual IP)
3. IOC storage and retrieval from Redis
4. Attack chain correlation
"""

import requests
import json
import uuid
import time
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

console = Console()

BASE_URL = "http://localhost:8000"


def print_request(num: int, text: str, session_id: str):
    """Print request details."""
    console.print(f"\n[bold cyan]{'='*80}[/bold cyan]")
    console.print(f"[bold cyan]Request {num}[/bold cyan]")
    console.print(f"[bold cyan]{'='*80}[/bold cyan]")
    console.print(f"\n[yellow]Input Text:[/yellow] {text}")
    console.print(f"[dim]Session ID: {session_id}[/dim]")


def print_response(response: dict, request_num: int):
    """Print response highlights."""
    if response.get("status") == "success":
        result = response.get("result", {})

        # Show context enrichment if present
        if "context_enrichment" in result:
            enrichment = result["context_enrichment"]
            if enrichment and enrichment.get("enriched"):
                console.print("\n[bold green]✓ Context Enrichment Detected![/bold green]")
                console.print(Panel(
                    f"Original: {enrichment.get('original_text', 'N/A')}\n"
                    f"Enriched: {enrichment.get('enriched_text', 'N/A')}\n"
                    f"Method: {enrichment.get('resolution_method', 'N/A')}\n"
                    f"Context Used: {json.dumps(enrichment.get('context_used', {}), indent=2)}",
                    title="Context Resolution",
                    border_style="green"
                ))

        # Show extracted IOCs
        ioc_analysis = result.get("ioc_analysis", {})
        extracted_iocs = ioc_analysis.get("extracted_iocs", {})

        if extracted_iocs:
            ioc_summary = []
            for ioc_type, values in extracted_iocs.items():
                if values:
                    ioc_summary.append(f"  • {ioc_type}: {values}")

            if ioc_summary:
                console.print("\n[bold blue]📋 Extracted IOCs:[/bold blue]")
                for line in ioc_summary:
                    console.print(line)

        # Show threat analysis summary
        threat_analysis = result.get("threat_analysis", {})
        if threat_analysis:
            high_risk = threat_analysis.get("high_risk_count", 0)
            medium_risk = threat_analysis.get("medium_risk_count", 0)
            low_risk = threat_analysis.get("low_risk_count", 0)

            console.print(f"\n[bold magenta]⚠️ Threat Analysis:[/bold magenta]")
            console.print(f"  • High Risk: {high_risk}")
            console.print(f"  • Medium Risk: {medium_risk}")
            console.print(f"  • Low Risk: {low_risk}")

        # Show processing method
        processing_method = result.get("processing_method", "unknown")
        console.print(f"\n[dim]Processing Method: {processing_method}[/dim]")

        # Show recommendations
        recommendations = result.get("recommendations", [])
        if recommendations:
            console.print(f"\n[bold green]💡 Recommendations:[/bold green]")
            for rec in recommendations[:3]:  # Show first 3
                console.print(f"  {rec}")
    else:
        console.print(f"\n[bold red]✗ Request failed[/bold red]")
        console.print(response.get("error", "Unknown error"))


def make_request(text: str, session_id: str) -> dict:
    """Make analysis request."""
    start_time = time.time()

    try:
        response = requests.post(
            f"{BASE_URL}/analyze",
            json={
                "text": text,
                "session_id": session_id,
                "use_react_workflow": True
            },
            timeout=30
        )

        elapsed = time.time() - start_time
        console.print(f"\n[dim]Response Time: {elapsed:.2f}s[/dim]")

        if response.status_code == 200:
            return response.json()
        else:
            return {
                "status": "error",
                "error": f"HTTP {response.status_code}: {response.text}"
            }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


def demo_scenario_1():
    """Scenario 1: Progressive threat investigation with pronoun resolution."""
    console.print("\n[bold blue]" + "="*80 + "[/bold blue]")
    console.print("[bold blue]SCENARIO 1: Progressive Threat Investigation[/bold blue]")
    console.print("[bold blue]" + "="*80 + "[/bold blue]")
    console.print("\nThis demonstrates pronoun resolution and context preservation.\n")

    session_id = str(uuid.uuid4())
    console.print(f"[bold]Session ID:[/bold] {session_id}\n")

    # Request 1: Initial detection
    print_request(1, "Suspicious login attempt from IP 192.168.1.100", session_id)
    response1 = make_request("Suspicious login attempt from IP 192.168.1.100", session_id)
    print_response(response1, 1)

    time.sleep(2)

    # Request 2: Use pronoun "same IP"
    print_request(2, "The same IP is now scanning ports 22, 23, 3389", session_id)
    console.print("\n[yellow]Note: 'same IP' should resolve to 192.168.1.100[/yellow]")
    response2 = make_request("The same IP is now scanning ports 22, 23, 3389", session_id)
    print_response(response2, 2)

    time.sleep(2)

    # Request 3: Use pronoun "that IP"
    print_request(3, "Successful SSH connection from that IP", session_id)
    console.print("\n[yellow]Note: 'that IP' should resolve to 192.168.1.100[/yellow]")
    response3 = make_request("Successful SSH connection from that IP", session_id)
    print_response(response3, 3)

    time.sleep(2)

    # Request 4: Ask for summary
    print_request(4, "Summarize the entire attack chain", session_id)
    console.print("\n[yellow]Note: Should retrieve all events from this session[/yellow]")
    response4 = make_request("Summarize the entire attack chain", session_id)
    print_response(response4, 4)


def demo_scenario_2():
    """Scenario 2: Multiple IOC types with context."""
    console.print("\n\n[bold blue]" + "="*80 + "[/bold blue]")
    console.print("[bold blue]SCENARIO 2: Multiple IOC Types[/bold blue]")
    console.print("[bold blue]" + "="*80 + "[/bold blue]")
    console.print("\nThis demonstrates tracking multiple IOC types in one session.\n")

    session_id = str(uuid.uuid4())
    console.print(f"[bold]Session ID:[/bold] {session_id}\n")

    # Request 1: Initial analysis with multiple IOCs
    text1 = ("Security incident: Traffic from 203.0.113.50 to malicious-c2.example.com. "
             "File hash detected: d41d8cd98f00b204e9800998ecf8427e")
    print_request(1, text1, session_id)
    response1 = make_request(text1, session_id)
    print_response(response1, 1)

    time.sleep(2)

    # Request 2: Ask about domain
    print_request(2, "Is that domain known to be malicious?", session_id)
    console.print("\n[yellow]Note: 'that domain' should resolve to malicious-c2.example.com[/yellow]")
    response2 = make_request("Is that domain known to be malicious?", session_id)
    print_response(response2, 2)

    time.sleep(2)

    # Request 3: Ask about hash
    print_request(3, "Check the file hash we detected", session_id)
    console.print("\n[yellow]Note: Should resolve to d41d8cd98f00b204e9800998ecf8427e[/yellow]")
    response3 = make_request("Check the file hash we detected", session_id)
    print_response(response3, 3)


def demo_scenario_3():
    """Scenario 3: Compare with and without session context."""
    console.print("\n\n[bold blue]" + "="*80 + "[/bold blue]")
    console.print("[bold blue]SCENARIO 3: With vs Without Session Context[/bold blue]")
    console.print("[bold blue]" + "="*80 + "[/bold blue]")
    console.print("\nThis compares behavior with consistent vs. changing session IDs.\n")

    # Part A: With consistent session
    session_a = str(uuid.uuid4())
    console.print(f"\n[bold green]Part A: Consistent Session[/bold green]")
    console.print(f"Session ID: {session_a}\n")

    print_request(1, "Analyze IP 8.8.8.8", session_a)
    response_a1 = make_request("Analyze IP 8.8.8.8", session_a)
    print_response(response_a1, 1)

    time.sleep(1)

    print_request(2, "What was the IP we just analyzed?", session_a)
    console.print("\n[yellow]Note: Should have context from request 1[/yellow]")
    response_a2 = make_request("What was the IP we just analyzed?", session_a)
    print_response(response_a2, 2)

    # Part B: With different sessions
    console.print(f"\n[bold yellow]Part B: Different Sessions (No Context)[/bold yellow]")

    session_b1 = str(uuid.uuid4())
    console.print(f"\nSession ID: {session_b1}\n")
    print_request(1, "Analyze IP 8.8.8.8", session_b1)
    response_b1 = make_request("Analyze IP 8.8.8.8", session_b1)
    print_response(response_b1, 1)

    time.sleep(1)

    session_b2 = str(uuid.uuid4())  # Different session!
    console.print(f"\nSession ID: {session_b2} [bold red](DIFFERENT!)[/bold red]\n")
    print_request(2, "What was the IP we just analyzed?", session_b2)
    console.print("\n[yellow]Note: Should NOT have context (different session)[/yellow]")
    response_b2 = make_request("What was the IP we just analyzed?", session_b2)
    print_response(response_b2, 2)


def main():
    """Run all demonstration scenarios."""
    console.print("\n[bold green]" + "="*80 + "[/bold green]")
    console.print("[bold green]CyberShield Context Preservation Demonstration[/bold green]")
    console.print("[bold green]" + "="*80 + "[/bold green]")

    console.print("\nThis script demonstrates the context preservation features:")
    console.print("  • Session-based memory using Redis")
    console.print("  • Pronoun resolution ('same IP', 'that domain', etc.)")
    console.print("  • Attack chain correlation across multiple requests")
    console.print("  • Cross-request IOC tracking")

    console.print(f"\n[dim]Backend URL: {BASE_URL}[/dim]")
    console.print(f"[dim]Make sure the CyberShield backend is running![/dim]\n")

    input("Press Enter to start Scenario 1...")
    demo_scenario_1()

    input("\n\nPress Enter to start Scenario 2...")
    demo_scenario_2()

    input("\n\nPress Enter to start Scenario 3...")
    demo_scenario_3()

    console.print("\n\n[bold green]" + "="*80 + "[/bold green]")
    console.print("[bold green]Demonstration Complete![/bold green]")
    console.print("[bold green]" + "="*80 + "[/bold green]")
    console.print("\n[bold]Key Observations:[/bold]")
    console.print("  1. Check if 'Context Enrichment Detected' panels appeared")
    console.print("  2. Verify pronouns were resolved to actual IOC values")
    console.print("  3. Compare behavior with consistent vs. different session IDs")
    console.print("  4. Notice faster response times for cached requests\n")


if __name__ == "__main__":
    main()
