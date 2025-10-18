"""
Analyze memory test results to understand context preservation behavior.
"""

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.tree import Tree

console = Console()

RESULTS_DIR = Path(__file__).parent / "results" / "memory_tests"


def analyze_incremental_threat():
    """Analyze the incremental threat investigation results."""

    console.print("\n" + "=" * 80, style="bold cyan")
    console.print("INCREMENTAL THREAT INVESTIGATION ANALYSIS", style="bold cyan")
    console.print("=" * 80 + "\n", style="bold cyan")

    file_path = RESULTS_DIR / "incremental_threat_investigation.json"
    with open(file_path) as f:
        data = json.load(f)

    console.print(f"[yellow]Session ID:[/yellow] {data['session_id']}")
    console.print(f"[yellow]Total Requests:[/yellow] {len(data['requests_chain'])}\n")

    # Create table showing the flow
    table = Table(title="Request Flow and Context Preservation")
    table.add_column("Step", style="cyan", width=5)
    table.add_column("User Request", style="yellow", width=35)
    table.add_column("IOCs Extracted", style="green", width=15)
    table.add_column("Context Maintained?", style="magenta", width=20)

    for i, req in enumerate(data["requests_chain"], 1):
        user_text = req["request"]["text"]
        iocs = req["response"]["result"]["ioc_analysis"]["extracted_iocs"]

        # Check what IOCs were found
        ioc_summary = []
        if iocs.get("ips"):
            ioc_summary.append(f"IPs: {len(iocs['ips'])}")
        if iocs.get("domains"):
            ioc_summary.append(f"Domains: {len(iocs['domains'])}")
        if iocs.get("hashes"):
            ioc_summary.append(f"Hashes: {len(iocs['hashes'])}")

        ioc_str = ", ".join(ioc_summary) if ioc_summary else "❌ None"

        # Check if context was maintained
        response_text = str(req["response"]["result"])
        has_context_refs = any(
            word in user_text.lower()
            for word in ["same", "that", "this", "the", "entire", "we"]
        )

        if i == 1:
            context_status = "N/A (first request)"
        elif has_context_refs and not iocs.get("ips"):
            context_status = "❌ FAILED - No reference"
        elif has_context_refs and iocs.get("ips"):
            context_status = "✅ SUCCESS"
        else:
            context_status = "⚠️  UNCLEAR"

        table.add_row(
            str(i),
            user_text[:32] + "..." if len(user_text) > 32 else user_text,
            ioc_str,
            context_status,
        )

    console.print(table)

    # Show the problem
    console.print("\n[bold red]PROBLEM IDENTIFIED:[/bold red]")
    console.print(
        "When user says 'the same IP' or 'that IP', "
        "the system should retrieve IP 198.51.100.25 from Redis STM."
    )
    console.print(
        "Instead, it's treating each request independently and finding NO IOCs.\n"
    )

    # Show what should happen
    tree = Tree("[bold green]Expected Behavior[/bold green]")
    step1 = tree.add(
        "[cyan]Step 1:[/cyan] Analyze '198.51.100.25' → Store in Redis with session_id"
    )
    step1.add("✅ Extract IP: 198.51.100.25")
    step1.add("✅ Store in Redis: session:00da04ef:iocs = {ips: ['198.51.100.25']}")

    step2 = tree.add("[cyan]Step 2:[/cyan] 'The same IP is scanning ports...'")
    step2.add("✅ Detect pronoun reference: 'same IP'")
    step2.add("✅ Query Redis: session:00da04ef:iocs")
    step2.add("✅ Retrieve: 198.51.100.25")
    step2.add("✅ Analyze ports 22, 23, 3389 for IP 198.51.100.25")

    step3 = tree.add("[cyan]Step 3:[/cyan] 'SSH connection from that IP'")
    step3.add("✅ Detect pronoun reference: 'that IP'")
    step3.add("✅ Query Redis: session:00da04ef:iocs")
    step3.add("✅ Retrieve: 198.51.100.25")
    step3.add("✅ Correlate SSH with previous port scan")

    step4 = tree.add("[cyan]Step 4:[/cyan] 'Summarize entire attack chain'")
    step4.add("✅ Query Redis: session:00da04ef:all_events")
    step4.add("✅ Retrieve all 3 previous analyses")
    step4.add("✅ Generate comprehensive timeline")

    console.print(tree)

    # Show actual behavior
    tree2 = Tree("[bold red]Actual Behavior[/bold red]")
    actual1 = tree2.add("[cyan]Step 1:[/cyan] Analyze '198.51.100.25'")
    actual1.add("✅ Extract IP: 198.51.100.25")
    actual1.add("❌ Store in Redis: NOT IMPLEMENTED")

    actual2 = tree2.add("[cyan]Step 2:[/cyan] 'The same IP is scanning ports...'")
    actual2.add("❌ No pronoun resolution")
    actual2.add("❌ No Redis query")
    actual2.add("❌ Result: 0 IOCs extracted")

    actual3 = tree2.add("[cyan]Step 3:[/cyan] 'SSH connection from that IP'")
    actual3.add("❌ No pronoun resolution")
    actual3.add("❌ No Redis query")
    actual3.add("❌ Result: 0 IOCs extracted")

    actual4 = tree2.add("[cyan]Step 4:[/cyan] 'Summarize entire attack chain'")
    actual4.add("❌ No historical query")
    actual4.add("❌ No context retrieval")
    actual4.add("❌ Result: Empty summary")

    console.print("\n")
    console.print(tree2)

    return data


def analyze_session_comparison():
    """Analyze the session ID comparison test."""

    console.print("\n" + "=" * 80, style="bold cyan")
    console.print("SESSION ID COMPARISON ANALYSIS", style="bold cyan")
    console.print("=" * 80 + "\n", style="bold cyan")

    file_path = RESULTS_DIR / "session_id_comparison.json"
    with open(file_path) as f:
        data = json.load(f)

    # Show both scenarios
    with_session = data["requests_chain"]["with_session"]
    without_session = data["requests_chain"]["without_session"]

    console.print("[bold green]Scenario A: WITH Consistent Session ID[/bold green]")
    table1 = Table()
    table1.add_column("Request", style="cyan")
    table1.add_column("Session ID", style="yellow", width=20)
    table1.add_column("Response", style="green")

    for req in with_session:
        session_id = req["request"]["session_id"][:20] + "..."
        response_preview = str(req["response"]["result"])[:50]
        table1.add_row(req["description"], session_id, response_preview + "...")

    console.print(table1)

    console.print(
        "\n[bold yellow]Scenario B: WITHOUT Consistent Session ID[/bold yellow]"
    )
    table2 = Table()
    table2.add_column("Request", style="cyan")
    table2.add_column("Session ID", style="yellow", width=20)
    table2.add_column("Response", style="green")

    for req in without_session:
        session_id = req["request"]["session_id"][:20] + "..."
        response_preview = str(req["response"]["result"])[:50]
        table2.add_row(req["description"], session_id, response_preview + "...")

    console.print(table2)

    # Show comparison
    analysis = data["analysis"]
    console.print("\n[bold]Comparison Results:[/bold]")
    console.print(
        f"  With Session Context Score: {analysis['comparison']['with_session_context_score']}"
    )
    console.print(
        f"  Without Session Context Score: {analysis['comparison']['without_session_context_score']}"
    )
    console.print(f"  Session ID Helps: {analysis['comparison']['session_id_helps']}")

    console.print("\n[bold red]Observation:[/bold red]")
    console.print(
        "Both scenarios have context score of 0.0 - meaning session IDs are NOT being utilized!"
    )


def show_recommendations():
    """Show recommendations for implementing context preservation."""

    console.print("\n" + "=" * 80, style="bold green")
    console.print(
        "RECOMMENDATIONS TO IMPLEMENT CONTEXT PRESERVATION", style="bold green"
    )
    console.print("=" * 80 + "\n", style="bold green")

    recommendations = [
        {
            "title": "1. Store IOCs in Redis STM on First Analysis",
            "details": [
                "When IOCs are extracted, store them with session_id as key",
                "Key format: cybershield:session:{session_id}:iocs",
                "TTL: 30 minutes (1800 seconds)",
                "Value: JSON with {ips: [], domains: [], hashes: [], emails: []}",
            ],
        },
        {
            "title": "2. Implement Pronoun Resolution in LogParser",
            "details": [
                "Detect references: 'same IP', 'that IP', 'this domain', 'the hash'",
                "Query Redis for previous IOCs when pronouns detected",
                "Replace pronouns with actual values from context",
                "Example: 'same IP' → '198.51.100.25'",
            ],
        },
        {
            "title": "3. Store Analysis History in Redis",
            "details": [
                "Store each analysis result with timestamp",
                "Key format: cybershield:session:{session_id}:history",
                "Use Redis LIST data structure for ordered history",
                "Enable 'summarize attack chain' queries",
            ],
        },
        {
            "title": "4. Implement Context-Aware Routing in Supervisor",
            "details": [
                "Check Redis for session history before routing",
                "If pronouns detected, fetch previous context",
                "Enrich current request with historical data",
                "Pass enriched context to agents",
            ],
        },
        {
            "title": "5. Add LLM-Based Context Resolution",
            "details": [
                "Use OpenAI to understand context references",
                "Prompt: 'Given previous: [history], resolve: [current]'",
                "LLM can intelligently map pronouns to entities",
                "Fallback to regex patterns if LLM unavailable",
            ],
        },
    ]

    for rec in recommendations:
        console.print(f"\n[bold cyan]{rec['title']}[/bold cyan]")
        for detail in rec["details"]:
            console.print(f"  • {detail}")

    # Show code example
    console.print("\n[bold yellow]Code Example:[/bold yellow]")
    code_example = '''
# In supervisor.py or log_parser.py
async def resolve_context_references(self, text: str, session_id: str) -> str:
    """Resolve pronoun references using Redis session context."""

    # Check for pronouns
    pronouns = ['same', 'that', 'this', 'the']
    has_pronoun = any(p in text.lower() for p in pronouns)

    if not has_pronoun or not session_id:
        return text

    # Fetch previous IOCs from Redis
    cache_key = f"cybershield:session:{session_id}:iocs"
    previous_iocs = await self.memory.get(cache_key)

    if not previous_iocs:
        return text

    # Replace pronouns with actual values
    enriched_text = text
    if previous_iocs.get('ips') and ('same ip' in text.lower() or 'that ip' in text.lower()):
        last_ip = previous_iocs['ips'][-1]
        enriched_text = enriched_text.replace('same IP', last_ip)
        enriched_text = enriched_text.replace('that IP', last_ip)

    return enriched_text
'''

    console.print(f"[dim]{code_example}[/dim]")


def main():
    """Run all analyses."""

    console.print("\n[bold blue]CyberShield Memory Test Analysis[/bold blue]\n")

    # Analyze key test results
    analyze_incremental_threat()
    analyze_session_comparison()
    show_recommendations()

    console.print("\n[bold green]Analysis Complete![/bold green]")
    console.print(f"Review detailed results at: {RESULTS_DIR}\n")


if __name__ == "__main__":
    main()
