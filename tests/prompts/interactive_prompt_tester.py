#!/usr/bin/env python3
"""Interactive CLI tester for CyberShield sample prompts.

Features:
- CLI menu to select different prompt categories
- Real-time API response visualization
- Ability to modify prompts on-the-fly
- Save test results to files
- Response time benchmarks
- Caching effectiveness testing
- Multi-modal analysis (text + image)
"""

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, Prompt
from rich.syntax import Syntax
from rich.table import Table


BASE_URL = "http://localhost:8000"
TIMEOUT = 60

console = Console()


class PromptTester:
    """Interactive prompt testing tool."""

    def __init__(self):
        """Initialize the tester."""
        self.prompts_file = Path(__file__).parent / "test_data" / "prompts.json"
        self.images_dir = Path(__file__).parent / "test_images"
        self.results_dir = Path(__file__).parent / "results"
        self.results_dir.mkdir(exist_ok=True)

        self.prompts_data: Dict[str, Any] = {}
        self.load_prompts()

        self.benchmark_history: List[Dict[str, Any]] = []

    def load_prompts(self):
        """Load prompts from JSON file."""
        if not self.prompts_file.exists():
            console.print(
                f"[red]Error: Prompts file not found at {self.prompts_file}[/red]"
            )
            sys.exit(1)

        with open(self.prompts_file) as f:
            self.prompts_data = json.load(f)

        console.print(f"[green]✓ Loaded prompts from {self.prompts_file}[/green]")

    def check_server(self) -> bool:
        """Check if the FastAPI server is running."""
        try:
            response = requests.get(f"{BASE_URL}/health", timeout=5)
            if response.status_code == 200:
                console.print(
                    f"[green]✓ Server is running at {BASE_URL}[/green]"
                )
                return True
        except requests.exceptions.ConnectionError:
            console.print(
                f"[red]✗ Server is not running at {BASE_URL}[/red]"
            )
            console.print("[yellow]Please start the server with: cybershield[/yellow]")
            return False

        return False

    def display_main_menu(self):
        """Display the main menu."""
        console.clear()
        console.print(
            Panel.fit(
                "[bold cyan]CyberShield Interactive Prompt Tester[/bold cyan]\n"
                "[dim]Test sample prompts with real-time analysis[/dim]",
                border_style="cyan",
            )
        )

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Option", style="bold yellow")
        table.add_column("Description")

        table.add_row("1", "Basic Security Analysis")
        table.add_row("2", "PII Detection")
        table.add_row("3", "Network Security Events")
        table.add_row("4", "Advanced Persistent Threats")
        table.add_row("5", "Error Handling Tests")
        table.add_row("6", "Image Analysis")
        table.add_row("7", "Multi-modal Analysis (Text + Image)")
        table.add_row("8", "Custom Prompt")
        table.add_row("9", "Benchmark & Caching Tests")
        table.add_row("10", "View Benchmark History")
        table.add_row("11", "Run All Tests")
        table.add_row("0", "Exit")

        console.print(table)

    def select_prompt_from_category(self, category_key: str) -> Optional[Dict[str, Any]]:
        """Select a specific prompt from a category."""
        if category_key not in self.prompts_data:
            console.print(f"[red]Category {category_key} not found[/red]")
            return None

        prompts = self.prompts_data[category_key]

        console.print(f"\n[bold]Available prompts in {category_key}:[/bold]")
        for i, prompt in enumerate(prompts, 1):
            console.print(f"{i}. {prompt['name']}")

        choice = Prompt.ask(
            "Select a prompt", choices=[str(i) for i in range(1, len(prompts) + 1)]
        )

        return prompts[int(choice) - 1]

    def call_analyze_endpoint(
        self, text: str, measure_time: bool = True
    ) -> tuple[Optional[Dict[str, Any]], float]:
        """Call the /analyze endpoint and return response with timing."""
        start_time = time.time()

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                progress.add_task("Analyzing...", total=None)

                response = requests.post(
                    f"{BASE_URL}/analyze", json={"text": text}, timeout=TIMEOUT
                )

            elapsed_time = time.time() - start_time

            if response.status_code == 200:
                return response.json(), elapsed_time
            else:
                console.print(
                    f"[red]API Error: {response.status_code} - {response.text}[/red]"
                )
                return None, elapsed_time

        except requests.exceptions.RequestException as e:
            elapsed_time = time.time() - start_time
            console.print(f"[red]Request failed: {e}[/red]")
            return None, elapsed_time

    def call_image_analysis_endpoint(
        self, image_path: Path, text: Optional[str] = None
    ) -> tuple[Optional[Dict[str, Any]], float]:
        """Call image analysis endpoint."""
        start_time = time.time()

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                progress.add_task("Analyzing image...", total=None)

                with open(image_path, "rb") as f:
                    if text:
                        # Multi-modal analysis
                        files = {"image": (image_path.name, f, "image/png")}
                        data = {"text": text}
                        response = requests.post(
                            f"{BASE_URL}/analyze-with-image",
                            files=files,
                            data=data,
                            timeout=TIMEOUT,
                        )
                    else:
                        # Image-only analysis
                        files = {"file": (image_path.name, f, "image/png")}
                        response = requests.post(
                            f"{BASE_URL}/upload-image", files=files, timeout=TIMEOUT
                        )

            elapsed_time = time.time() - start_time

            if response.status_code == 200:
                return response.json(), elapsed_time
            else:
                console.print(
                    f"[red]API Error: {response.status_code} - {response.text}[/red]"
                )
                return None, elapsed_time

        except requests.exceptions.RequestException as e:
            elapsed_time = time.time() - start_time
            console.print(f"[red]Request failed: {e}[/red]")
            return None, elapsed_time

    def display_result(
        self,
        result: Dict[str, Any],
        elapsed_time: float,
        prompt_name: str = "Analysis",
    ):
        """Display analysis result with rich formatting."""
        console.print("\n" + "=" * 80)
        console.print(f"[bold green]✓ {prompt_name} Complete[/bold green]")
        console.print(f"[dim]Response time: {elapsed_time:.3f} seconds[/dim]")
        console.print("=" * 80 + "\n")

        # Display result as formatted JSON
        syntax = Syntax(
            json.dumps(result, indent=2), "json", theme="monokai", line_numbers=True
        )
        console.print(Panel(syntax, title="Analysis Result", border_style="green"))

        # Extract key insights
        self.display_key_insights(result)

    def display_key_insights(self, result: Dict[str, Any]):
        """Extract and display key insights from the result."""
        insights_table = Table(title="Key Insights", show_header=True)
        insights_table.add_column("Category", style="cyan")
        insights_table.add_column("Finding", style="yellow")

        result_str = json.dumps(result).lower()

        # Check for common patterns
        if "threat" in result_str or "malware" in result_str:
            insights_table.add_row("Threat Detection", "⚠ Threats detected in input")

        if "pii" in result_str or "sensitive" in result_str:
            insights_table.add_row("PII Detection", "🔒 Sensitive data identified")

        if "ip" in result_str or "domain" in result_str:
            insights_table.add_row("IOC Extraction", "🔍 Indicators of Compromise found")

        if "bitcoin" in result_str or "wallet" in result_str:
            insights_table.add_row(
                "Cryptocurrency", "₿ Cryptocurrency addresses detected"
            )

        if insights_table.row_count > 0:
            console.print(insights_table)

    def save_result(
        self,
        prompt_name: str,
        prompt_text: str,
        result: Dict[str, Any],
        elapsed_time: float,
    ):
        """Save test result to file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"test_result_{timestamp}_{prompt_name.replace(' ', '_')}.json"
        filepath = self.results_dir / filename

        data = {
            "timestamp": datetime.now().isoformat(),
            "prompt_name": prompt_name,
            "prompt_text": prompt_text,
            "elapsed_time": elapsed_time,
            "result": result,
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

        console.print(f"[green]✓ Result saved to {filepath}[/green]")

    def run_category_tests(self, category_key: str):
        """Run tests for a specific category."""
        prompt_data = self.select_prompt_from_category(category_key)
        if not prompt_data:
            return

        console.print(f"\n[bold cyan]Testing: {prompt_data['name']}[/bold cyan]")
        console.print(f"[dim]Prompt: {prompt_data['prompt']}[/dim]\n")

        # Allow modification
        if Confirm.ask("Would you like to modify the prompt?"):
            new_prompt = Prompt.ask("Enter modified prompt")
            prompt_data["prompt"] = new_prompt

        # Run analysis
        result, elapsed_time = self.call_analyze_endpoint(prompt_data["prompt"])

        if result:
            self.display_result(result, elapsed_time, prompt_data["name"])

            # Save result
            if Confirm.ask("Save this result?"):
                self.save_result(
                    prompt_data["name"], prompt_data["prompt"], result, elapsed_time
                )

            # Record benchmark
            self.benchmark_history.append(
                {
                    "name": prompt_data["name"],
                    "category": category_key,
                    "time": elapsed_time,
                    "timestamp": datetime.now().isoformat(),
                }
            )

    def run_custom_prompt(self):
        """Run a custom user-provided prompt."""
        console.print("\n[bold cyan]Custom Prompt Test[/bold cyan]")
        prompt_text = Prompt.ask("Enter your custom prompt")

        result, elapsed_time = self.call_analyze_endpoint(prompt_text)

        if result:
            self.display_result(result, elapsed_time, "Custom Prompt")

            if Confirm.ask("Save this result?"):
                self.save_result("custom_prompt", prompt_text, result, elapsed_time)

            self.benchmark_history.append(
                {
                    "name": "Custom Prompt",
                    "category": "custom",
                    "time": elapsed_time,
                    "timestamp": datetime.now().isoformat(),
                }
            )

    def run_image_analysis(self):
        """Run image analysis tests."""
        console.print("\n[bold cyan]Image Analysis Tests[/bold cyan]")

        # List available images
        images = list(self.images_dir.glob("*.png"))
        if not images:
            console.print("[red]No test images found![/red]")
            return

        console.print("[bold]Available test images:[/bold]")
        for i, img in enumerate(images, 1):
            console.print(f"{i}. {img.name}")

        choice = Prompt.ask(
            "Select an image", choices=[str(i) for i in range(1, len(images) + 1)]
        )
        selected_image = images[int(choice) - 1]

        result, elapsed_time = self.call_image_analysis_endpoint(selected_image)

        if result:
            self.display_result(result, elapsed_time, f"Image: {selected_image.name}")

            if Confirm.ask("Save this result?"):
                self.save_result(
                    f"image_{selected_image.stem}", str(selected_image), result, elapsed_time
                )

    def run_multimodal_analysis(self):
        """Run multi-modal analysis (text + image)."""
        console.print("\n[bold cyan]Multi-modal Analysis (Text + Image)[/bold cyan]")

        # Select image
        images = list(self.images_dir.glob("*.png"))
        if not images:
            console.print("[red]No test images found![/red]")
            return

        console.print("[bold]Available test images:[/bold]")
        for i, img in enumerate(images, 1):
            console.print(f"{i}. {img.name}")

        img_choice = Prompt.ask(
            "Select an image", choices=[str(i) for i in range(1, len(images) + 1)]
        )
        selected_image = images[int(img_choice) - 1]

        # Get text prompt
        text_prompt = Prompt.ask("Enter text prompt to analyze with the image")

        result, elapsed_time = self.call_image_analysis_endpoint(
            selected_image, text_prompt
        )

        if result:
            self.display_result(
                result, elapsed_time, f"Multimodal: {selected_image.name}"
            )

            if Confirm.ask("Save this result?"):
                self.save_result(
                    f"multimodal_{selected_image.stem}",
                    f"Image: {selected_image}\nText: {text_prompt}",
                    result,
                    elapsed_time,
                )

    def run_benchmark_tests(self):
        """Run benchmark and caching effectiveness tests."""
        console.print("\n[bold cyan]Benchmark & Caching Tests[/bold cyan]")

        # Select a prompt to test
        prompt_text = "Test IP 8.8.8.8 with hash d41d8cd98f00b204e9800998ecf8427e"
        if Confirm.ask("Use default test prompt?"):
            console.print(f"[dim]Using: {prompt_text}[/dim]")
        else:
            prompt_text = Prompt.ask("Enter test prompt")

        num_runs = int(Prompt.ask("Number of test runs", default="3"))

        console.print(f"\n[bold]Running {num_runs} tests to measure caching...[/bold]\n")

        times = []
        for i in range(num_runs):
            console.print(f"[cyan]Run {i + 1}/{num_runs}...[/cyan]")
            result, elapsed_time = self.call_analyze_endpoint(prompt_text)

            if result:
                times.append(elapsed_time)
                console.print(f"  ⏱ Time: {elapsed_time:.3f}s")

                if i == 0:
                    console.print("  [dim](First request - no cache)[/dim]")
                else:
                    improvement = ((times[0] - elapsed_time) / times[0]) * 100
                    console.print(
                        f"  [green]Cache speedup: {improvement:.1f}%[/green]"
                    )

        # Display benchmark summary
        if times:
            console.print("\n[bold]Benchmark Summary:[/bold]")
            summary_table = Table(show_header=True)
            summary_table.add_column("Metric", style="cyan")
            summary_table.add_column("Value", style="yellow")

            summary_table.add_row("First Request", f"{times[0]:.3f}s")
            if len(times) > 1:
                summary_table.add_row("Avg Cached", f"{sum(times[1:]) / len(times[1:]):.3f}s")
                speedup = ((times[0] - min(times[1:])) / times[0]) * 100
                summary_table.add_row("Cache Speedup", f"{speedup:.1f}%")

            console.print(summary_table)

    def view_benchmark_history(self):
        """View benchmark history."""
        if not self.benchmark_history:
            console.print("[yellow]No benchmark history available[/yellow]")
            return

        console.print("\n[bold cyan]Benchmark History[/bold cyan]")

        table = Table(show_header=True)
        table.add_column("Test Name", style="cyan")
        table.add_column("Category", style="magenta")
        table.add_column("Time", style="yellow")
        table.add_column("Timestamp", style="dim")

        for entry in self.benchmark_history:
            table.add_row(
                entry["name"],
                entry["category"],
                f"{entry['time']:.3f}s",
                entry["timestamp"],
            )

        console.print(table)

        # Calculate statistics
        times = [e["time"] for e in self.benchmark_history]
        console.print(f"\n[bold]Statistics:[/bold]")
        console.print(f"  Total tests: {len(times)}")
        console.print(f"  Avg time: {sum(times) / len(times):.3f}s")
        console.print(f"  Min time: {min(times):.3f}s")
        console.print(f"  Max time: {max(times):.3f}s")

    def run_all_tests(self):
        """Run all available tests."""
        console.print("\n[bold cyan]Running All Tests[/bold cyan]")

        if not Confirm.ask("This will run all test categories. Continue?"):
            return

        categories = [
            ("basic_security_analysis", "Basic Security Analysis"),
            ("pii_detection", "PII Detection"),
            ("network_security_events", "Network Security Events"),
            ("advanced_persistent_threats", "Advanced Persistent Threats"),
            ("error_handling", "Error Handling"),
        ]

        results = []

        for category_key, category_name in categories:
            console.print(f"\n[bold]Testing: {category_name}[/bold]")

            if category_key not in self.prompts_data:
                continue

            for prompt_data in self.prompts_data[category_key]:
                console.print(f"  → {prompt_data['name']}")

                result, elapsed_time = self.call_analyze_endpoint(prompt_data["prompt"])

                if result:
                    results.append(
                        {
                            "category": category_name,
                            "name": prompt_data["name"],
                            "time": elapsed_time,
                            "success": True,
                        }
                    )
                else:
                    results.append(
                        {
                            "category": category_name,
                            "name": prompt_data["name"],
                            "time": elapsed_time,
                            "success": False,
                        }
                    )

        # Display summary
        console.print("\n[bold green]All Tests Complete[/bold green]")

        summary_table = Table(show_header=True, title="Test Summary")
        summary_table.add_column("Category", style="cyan")
        summary_table.add_column("Test", style="yellow")
        summary_table.add_column("Time", style="magenta")
        summary_table.add_column("Status", style="green")

        for r in results:
            status = "✓" if r["success"] else "✗"
            summary_table.add_row(r["category"], r["name"], f"{r['time']:.3f}s", status)

        console.print(summary_table)

        # Save summary
        if Confirm.ask("Save test summary?"):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"test_summary_{timestamp}.json"
            filepath = self.results_dir / filename

            with open(filepath, "w") as f:
                json.dump(results, f, indent=2)

            console.print(f"[green]✓ Summary saved to {filepath}[/green]")

    def run(self):
        """Run the interactive tester."""
        if not self.check_server():
            return

        while True:
            self.display_main_menu()
            choice = Prompt.ask("\nSelect an option", default="0")

            if choice == "0":
                console.print("[yellow]Goodbye![/yellow]")
                break
            elif choice == "1":
                self.run_category_tests("basic_security_analysis")
            elif choice == "2":
                self.run_category_tests("pii_detection")
            elif choice == "3":
                self.run_category_tests("network_security_events")
            elif choice == "4":
                self.run_category_tests("advanced_persistent_threats")
            elif choice == "5":
                self.run_category_tests("error_handling")
            elif choice == "6":
                self.run_image_analysis()
            elif choice == "7":
                self.run_multimodal_analysis()
            elif choice == "8":
                self.run_custom_prompt()
            elif choice == "9":
                self.run_benchmark_tests()
            elif choice == "10":
                self.view_benchmark_history()
            elif choice == "11":
                self.run_all_tests()
            else:
                console.print("[red]Invalid choice![/red]")

            if choice != "0":
                Prompt.ask("\n[dim]Press Enter to continue...[/dim]")


def main():
    """Main entry point."""
    try:
        tester = PromptTester()
        tester.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
