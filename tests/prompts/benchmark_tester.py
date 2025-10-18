#!/usr/bin/env python3
"""Benchmark and caching effectiveness tester for CyberShield.

This script performs comprehensive benchmarking:
- Response time measurements
- Caching effectiveness analysis
- Performance regression detection
- API call optimization validation
"""

import json
import statistics
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
from rich.console import Console
from rich.progress import track
from rich.table import Table

BASE_URL = "http://localhost:8000"
TIMEOUT = 60

console = Console()


class BenchmarkTester:
    """Automated benchmark testing tool."""

    def __init__(self):
        """Initialize the benchmark tester."""
        self.results_dir = Path(__file__).parent / "results"
        self.results_dir.mkdir(exist_ok=True)

        self.test_prompts = [
            "Test IP 8.8.8.8 with hash d41d8cd98f00b204e9800998ecf8427e",
            "Failed login from 203.0.113.42 for user admin",
            "Firewall blocked 185.220.101.42:443",
            "User John Doe (SSN: 123-45-6789) accessed system",
            "Malware hash: a665a45920422f9d417e4867efdc4fb8",
        ]

    def check_server(self) -> bool:
        """Check if the server is running."""
        try:
            response = requests.get(f"{BASE_URL}/health", timeout=5)
            return response.status_code == 200
        except requests.exceptions.ConnectionError:
            console.print(f"[red]Error: Server not running at {BASE_URL}[/red]")
            return False

    def call_api(self, text: str) -> tuple[bool, float]:
        """Call the API and measure response time."""
        start_time = time.time()

        try:
            response = requests.post(
                f"{BASE_URL}/analyze", json={"text": text}, timeout=TIMEOUT
            )
            elapsed_time = time.time() - start_time

            if response.status_code == 200:
                return True, elapsed_time
            else:
                return False, elapsed_time

        except requests.exceptions.RequestException:
            elapsed_time = time.time() - start_time
            return False, elapsed_time

    def test_single_request(self, prompt: str, iterations: int = 3) -> dict[str, Any]:
        """Test a single prompt multiple times to measure caching."""
        console.print(f"\n[cyan]Testing prompt:[/cyan] [dim]{prompt[:60]}...[/dim]")

        times = []
        success_count = 0

        for i in track(range(iterations), description="Running tests..."):
            success, elapsed_time = self.call_api(prompt)

            if success:
                success_count += 1
                times.append(elapsed_time)

            # Small delay between requests
            if i < iterations - 1:
                time.sleep(0.5)

        if not times:
            return {
                "prompt": prompt,
                "success": False,
                "error": "All requests failed",
            }

        # Calculate statistics
        first_request = times[0]
        cached_times = times[1:] if len(times) > 1 else []

        result = {
            "prompt": prompt,
            "success": True,
            "iterations": iterations,
            "success_count": success_count,
            "first_request_time": first_request,
            "times": times,
        }

        if cached_times:
            avg_cached = statistics.mean(cached_times)
            min_cached = min(cached_times)
            speedup = ((first_request - avg_cached) / first_request) * 100

            result.update(
                {
                    "avg_cached_time": avg_cached,
                    "min_cached_time": min_cached,
                    "cache_speedup_percent": speedup,
                }
            )

            console.print(f"  First request: {first_request:.3f}s")
            console.print(f"  Avg cached: {avg_cached:.3f}s")
            console.print(f"  [green]Speedup: {speedup:.1f}%[/green]")
        else:
            console.print(f"  Single request: {first_request:.3f}s")

        return result

    def run_comprehensive_benchmark(self, iterations: int = 3) -> list[dict[str, Any]]:
        """Run benchmark tests on all test prompts."""
        console.print("[bold cyan]Running Comprehensive Benchmark Tests[/bold cyan]\n")
        console.print(f"Test prompts: {len(self.test_prompts)}")
        console.print(f"Iterations per prompt: {iterations}\n")

        results = []

        for prompt in self.test_prompts:
            result = self.test_single_request(prompt, iterations)
            results.append(result)

        return results

    def display_summary(self, results: list[dict[str, Any]]):
        """Display benchmark summary."""
        console.print("\n[bold green]Benchmark Summary[/bold green]\n")

        # Create summary table
        table = Table(show_header=True, title="Performance Results")
        table.add_column("Test", style="cyan", no_wrap=False, max_width=40)
        table.add_column("First (s)", style="yellow", justify="right")
        table.add_column("Cached (s)", style="yellow", justify="right")
        table.add_column("Speedup", style="green", justify="right")

        for result in results:
            if not result.get("success"):
                continue

            prompt_preview = (
                result["prompt"][:37] + "..."
                if len(result["prompt"]) > 40
                else result["prompt"]
            )
            first = f"{result['first_request_time']:.3f}"

            if "avg_cached_time" in result:
                cached = f"{result['avg_cached_time']:.3f}"
                speedup = f"{result['cache_speedup_percent']:.1f}%"
            else:
                cached = "-"
                speedup = "-"

            table.add_row(prompt_preview, first, cached, speedup)

        console.print(table)

        # Overall statistics
        console.print("\n[bold]Overall Statistics:[/bold]")

        all_first_times = [r["first_request_time"] for r in results if r.get("success")]
        all_cached_times = []
        all_speedups = []

        for r in results:
            if r.get("success") and "avg_cached_time" in r:
                all_cached_times.append(r["avg_cached_time"])
                all_speedups.append(r["cache_speedup_percent"])

        stats_table = Table(show_header=False, box=None, padding=(0, 2))
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="yellow")

        if all_first_times:
            stats_table.add_row(
                "Avg First Request", f"{statistics.mean(all_first_times):.3f}s"
            )

        if all_cached_times:
            stats_table.add_row(
                "Avg Cached Request", f"{statistics.mean(all_cached_times):.3f}s"
            )
            stats_table.add_row(
                "Avg Cache Speedup", f"{statistics.mean(all_speedups):.1f}%"
            )
            stats_table.add_row("Best Speedup", f"{max(all_speedups):.1f}%")

        console.print(stats_table)

    def save_results(self, results: list[dict[str, Any]]):
        """Save benchmark results to file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"benchmark_results_{timestamp}.json"
        filepath = self.results_dir / filename

        data = {
            "timestamp": datetime.now().isoformat(),
            "base_url": BASE_URL,
            "results": results,
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

        console.print(f"\n[green]✓ Results saved to {filepath}[/green]")

    def compare_with_baseline(self, results: list[dict[str, Any]]):
        """Compare current results with baseline (if exists)."""
        baseline_file = self.results_dir / "benchmark_baseline.json"

        if not baseline_file.exists():
            # Create baseline
            console.print(
                "\n[yellow]No baseline found. Creating baseline from current results...[/yellow]"
            )

            data = {
                "timestamp": datetime.now().isoformat(),
                "results": results,
            }

            with open(baseline_file, "w") as f:
                json.dump(data, f, indent=2)

            console.print(f"[green]✓ Baseline created at {baseline_file}[/green]")
            return

        # Load baseline and compare
        with open(baseline_file) as f:
            baseline_data = json.load(f)

        baseline_results = baseline_data["results"]

        console.print("\n[bold]Comparison with Baseline[/bold]")
        console.print(f"[dim]Baseline from: {baseline_data['timestamp']}[/dim]\n")

        comparison_table = Table(show_header=True, title="Performance Comparison")
        comparison_table.add_column("Test", style="cyan", max_width=40)
        comparison_table.add_column("Current", style="yellow", justify="right")
        comparison_table.add_column("Baseline", style="yellow", justify="right")
        comparison_table.add_column("Change", style="magenta", justify="right")

        for i, current in enumerate(results):
            if not current.get("success"):
                continue

            if i >= len(baseline_results):
                continue

            baseline = baseline_results[i]
            if not baseline.get("success"):
                continue

            prompt_preview = current["prompt"][:37] + "..."
            current_time = current["first_request_time"]
            baseline_time = baseline["first_request_time"]

            change = ((current_time - baseline_time) / baseline_time) * 100
            change_str = f"{change:+.1f}%"

            # Color code the change
            if change < -10:
                change_str = f"[green]{change_str}[/green]"
            elif change > 10:
                change_str = f"[red]{change_str}[/red]"

            comparison_table.add_row(
                prompt_preview,
                f"{current_time:.3f}s",
                f"{baseline_time:.3f}s",
                change_str,
            )

        console.print(comparison_table)

    def run(self):
        """Run the benchmark suite."""
        if not self.check_server():
            return

        console.print("[bold cyan]CyberShield Benchmark & Caching Tests[/bold cyan]\n")

        # Ask for number of iterations
        iterations = 3
        console.print(f"Running {iterations} iterations per test\n")

        # Run benchmarks
        results = self.run_comprehensive_benchmark(iterations)

        # Display summary
        self.display_summary(results)

        # Save results
        self.save_results(results)

        # Compare with baseline
        self.compare_with_baseline(results)

        console.print("\n[bold green]✓ Benchmark complete![/bold green]")


def main():
    """Main entry point."""
    try:
        tester = BenchmarkTester()
        tester.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


if __name__ == "__main__":
    main()
