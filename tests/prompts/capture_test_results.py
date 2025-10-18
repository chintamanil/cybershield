#!/usr/bin/env python3
"""Capture and save detailed test results for review.

This script runs all sample prompt tests and saves the complete API responses
to organized files for manual review.
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
from rich.console import Console

BASE_URL = "http://localhost:8000"
TIMEOUT = 60

console = Console()


class ResultCapture:
    """Capture and save test results."""

    def __init__(self):
        """Initialize result capture."""
        self.results_base = Path(__file__).parent / "results"
        self.prompts_file = Path(__file__).parent / "test_data" / "prompts.json"
        self.images_dir = Path(__file__).parent / "test_images"

        # Use results directory directly (no timestamped subdirectory)
        self.run_dir = self.results_base
        self.run_dir.mkdir(parents=True, exist_ok=True)

        # Create subdirectories
        (self.run_dir / "text_analysis").mkdir(exist_ok=True)
        (self.run_dir / "image_analysis").mkdir(exist_ok=True)
        (self.run_dir / "multimodal").mkdir(exist_ok=True)
        (self.run_dir / "batch").mkdir(exist_ok=True)
        (self.run_dir / "tools").mkdir(exist_ok=True)

        self.prompts_data = self.load_prompts()
        self.all_results = []

        # Store timestamp for metadata
        self.run_timestamp = datetime.now().isoformat()

    def load_prompts(self) -> dict[str, Any]:
        """Load prompts from JSON file."""
        with open(self.prompts_file) as f:
            return json.load(f)

    def check_server(self) -> bool:
        """Check if server is running."""
        try:
            response = requests.get(f"{BASE_URL}/health", timeout=10)
            return response.status_code in [200, 503]  # Accept degraded status
        except requests.exceptions.ConnectionError:
            return False
        except requests.exceptions.ReadTimeout:
            console.print(
                "[yellow]Server health check timed out, but continuing...[/yellow]"
            )
            return True  # Continue anyway

    def save_result(
        self,
        category: str,
        test_name: str,
        result: dict[str, Any],
        metadata: dict[str, Any],
    ):
        """Save a single test result to file."""
        # Clean test name for filename
        safe_name = test_name.replace(" ", "_").replace("/", "_").lower()
        filename = f"{safe_name}.json"

        # Determine subdirectory
        if "image" in category.lower():
            subdir = "image_analysis"
        elif "multimodal" in category.lower():
            subdir = "multimodal"
        elif "batch" in category.lower():
            subdir = "batch"
        elif "tool" in category.lower():
            subdir = "tools"
        else:
            subdir = "text_analysis"

        filepath = self.run_dir / subdir / filename

        # Prepare complete result with metadata
        complete_result = {
            "timestamp": datetime.now().isoformat(),
            "category": category,
            "test_name": test_name,
            "metadata": metadata,
            "api_response": result,
        }

        # Save to file
        with open(filepath, "w") as f:
            json.dump(complete_result, f, indent=2)

        console.print(f"[dim]  Saved: {filepath.name}[/dim]")

    def test_text_analysis(self):
        """Test all text analysis prompts and save results."""
        console.print("\n[bold cyan]Testing Text Analysis Prompts[/bold cyan]")

        categories = [
            ("basic_security_analysis", "Basic Security"),
            ("pii_detection", "PII Detection"),
            ("network_security_events", "Network Security"),
            ("advanced_persistent_threats", "Advanced Threats"),
            ("error_handling", "Error Handling"),
        ]

        for category_key, category_name in categories:
            if category_key not in self.prompts_data:
                continue

            console.print(f"\n[yellow]Category: {category_name}[/yellow]")

            for prompt_data in self.prompts_data[category_key]:
                test_name = prompt_data["name"]
                console.print(f"  Testing: {test_name}")

                start_time = time.time()

                try:
                    response = requests.post(
                        f"{BASE_URL}/analyze",
                        json={"text": prompt_data["prompt"]},
                        timeout=TIMEOUT,
                    )

                    elapsed_time = time.time() - start_time

                    if response.status_code == 200:
                        result = response.json()

                        metadata = {
                            "prompt": prompt_data["prompt"],
                            "expected_iocs": prompt_data.get("expected_iocs", {}),
                            "expected_pii": prompt_data.get("expected_pii", {}),
                            "response_time": elapsed_time,
                            "status_code": response.status_code,
                        }

                        self.save_result(category_name, test_name, result, metadata)

                        self.all_results.append(
                            {
                                "category": category_name,
                                "test": test_name,
                                "status": "success",
                                "time": elapsed_time,
                            }
                        )
                    else:
                        console.print(f"    [red]Failed: {response.status_code}[/red]")
                        self.all_results.append(
                            {
                                "category": category_name,
                                "test": test_name,
                                "status": "failed",
                                "error": response.text,
                            }
                        )

                except Exception as e:
                    console.print(f"    [red]Error: {e}[/red]")
                    self.all_results.append(
                        {
                            "category": category_name,
                            "test": test_name,
                            "status": "error",
                            "error": str(e),
                        }
                    )

    def test_image_analysis(self):
        """Test image analysis and save results."""
        console.print("\n[bold cyan]Testing Image Analysis[/bold cyan]")

        images = [
            ("security_logs_screenshot.png", "Security Logs Screenshot"),
            ("email_with_pii.png", "Email with PII"),
            ("security_dashboard.png", "Security Dashboard"),
        ]

        for image_filename, test_name in images:
            image_path = self.images_dir / image_filename

            if not image_path.exists():
                console.print(
                    f"  [yellow]Skipping {test_name}: image not found[/yellow]"
                )
                continue

            console.print(f"  Testing: {test_name}")

            start_time = time.time()

            try:
                with open(image_path, "rb") as f:
                    files = {"image": (image_filename, f, "image/png")}
                    response = requests.post(
                        f"{BASE_URL}/upload-image", files=files, timeout=TIMEOUT
                    )

                elapsed_time = time.time() - start_time

                if response.status_code == 200:
                    result = response.json()

                    metadata = {
                        "image_file": image_filename,
                        "image_size": image_path.stat().st_size,
                        "response_time": elapsed_time,
                        "status_code": response.status_code,
                    }

                    self.save_result("Image Analysis", test_name, result, metadata)

                    self.all_results.append(
                        {
                            "category": "Image Analysis",
                            "test": test_name,
                            "status": "success",
                            "time": elapsed_time,
                        }
                    )
                else:
                    console.print(f"    [red]Failed: {response.status_code}[/red]")

            except Exception as e:
                console.print(f"    [red]Error: {e}[/red]")

    def test_multimodal_analysis(self):
        """Test multimodal (text + image) analysis."""
        console.print("\n[bold cyan]Testing Multimodal Analysis[/bold cyan]")

        test_cases = [
            (
                "security_logs_screenshot.png",
                "Analyze this security log image for threats",
                "Security Logs + Text",
            ),
            (
                "email_with_pii.png",
                "Extract PII from this email screenshot",
                "Email PII + Text",
            ),
        ]

        for image_filename, text_prompt, test_name in test_cases:
            image_path = self.images_dir / image_filename

            if not image_path.exists():
                console.print(
                    f"  [yellow]Skipping {test_name}: image not found[/yellow]"
                )
                continue

            console.print(f"  Testing: {test_name}")

            start_time = time.time()

            try:
                with open(image_path, "rb") as f:
                    files = {"image": (image_filename, f, "image/png")}
                    data = {"text": text_prompt}

                    response = requests.post(
                        f"{BASE_URL}/analyze-with-image",
                        files=files,
                        data=data,
                        timeout=TIMEOUT,
                    )

                elapsed_time = time.time() - start_time

                if response.status_code == 200:
                    result = response.json()

                    metadata = {
                        "image_file": image_filename,
                        "text_prompt": text_prompt,
                        "response_time": elapsed_time,
                        "status_code": response.status_code,
                    }

                    self.save_result("Multimodal", test_name, result, metadata)

                    self.all_results.append(
                        {
                            "category": "Multimodal",
                            "test": test_name,
                            "status": "success",
                            "time": elapsed_time,
                        }
                    )
                else:
                    console.print(f"    [red]Failed: {response.status_code}[/red]")

            except Exception as e:
                console.print(f"    [red]Error: {e}[/red]")

    def test_batch_analysis(self):
        """Test batch analysis."""
        console.print("\n[bold cyan]Testing Batch Analysis[/bold cyan]")

        # Create a batch of different prompts
        batch_prompts = [
            self.prompts_data["basic_security_analysis"][0]["prompt"],
            self.prompts_data["pii_detection"][0]["prompt"],
            self.prompts_data["network_security_events"][0]["prompt"],
        ]

        test_name = "Mixed Batch Analysis"
        console.print(f"  Testing: {test_name}")

        start_time = time.time()

        try:
            response = requests.post(
                f"{BASE_URL}/batch-analyze",
                json={"inputs": batch_prompts},
                timeout=TIMEOUT * 2,
            )

            elapsed_time = time.time() - start_time

            if response.status_code == 200:
                result = response.json()

                metadata = {
                    "batch_size": len(batch_prompts),
                    "prompts": batch_prompts,
                    "response_time": elapsed_time,
                    "status_code": response.status_code,
                }

                self.save_result("Batch", test_name, result, metadata)

                self.all_results.append(
                    {
                        "category": "Batch",
                        "test": test_name,
                        "status": "success",
                        "time": elapsed_time,
                    }
                )
            else:
                console.print(f"    [red]Failed: {response.status_code}[/red]")

        except Exception as e:
            console.print(f"    [red]Error: {e}[/red]")

    def test_tool_endpoints(self):
        """Test individual tool endpoints."""
        console.print("\n[bold cyan]Testing Tool Endpoints[/bold cyan]")

        # Regex extraction
        console.print("  Testing: Regex IOC Extraction")
        test_text = (
            "Suspicious IP 203.0.113.42 with hash d41d8cd98f00b204e9800998ecf8427e"
        )

        try:
            response = requests.post(
                f"{BASE_URL}/tools/regex/extract",
                params={"text": test_text},
                timeout=10,
            )

            if response.status_code == 200:
                result = response.json()

                metadata = {
                    "test_text": test_text,
                    "endpoint": "/tools/regex/extract",
                }

                self.save_result("Tools", "Regex IOC Extraction", result, metadata)
        except Exception as e:
            console.print(f"    [red]Error: {e}[/red]")

        # Regex validation
        console.print("  Testing: Regex Pattern Validation")

        try:
            response = requests.post(
                f"{BASE_URL}/tools/regex/validate",
                params={"text": "8.8.8.8", "pattern_type": "ip"},
                timeout=10,
            )

            if response.status_code == 200:
                result = response.json()

                metadata = {
                    "test_text": "8.8.8.8",
                    "pattern_type": "ip",
                    "endpoint": "/tools/regex/validate",
                }

                self.save_result("Tools", "Regex Pattern Validation", result, metadata)
        except Exception as e:
            console.print(f"    [red]Error: {e}[/red]")

    def generate_summary_report(self):
        """Generate a comprehensive summary report."""
        console.print("\n[bold cyan]Generating Summary Report[/bold cyan]")

        # Count results by status
        total = len(self.all_results)
        success = sum(1 for r in self.all_results if r.get("status") == "success")
        failed = sum(1 for r in self.all_results if r.get("status") == "failed")
        errors = sum(1 for r in self.all_results if r.get("status") == "error")

        # Calculate average times
        times = [r["time"] for r in self.all_results if "time" in r]
        avg_time = sum(times) / len(times) if times else 0

        # Group by category
        by_category = {}
        for r in self.all_results:
            cat = r["category"]
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(r)

        # Create summary report
        summary = {
            "timestamp": self.run_timestamp,
            "run_directory": str(self.run_dir),
            "summary": {
                "total_tests": total,
                "successful": success,
                "failed": failed,
                "errors": errors,
                "success_rate": f"{(success / total * 100):.1f}%"
                if total > 0
                else "0%",
                "average_response_time": f"{avg_time:.3f}s",
            },
            "by_category": {},
            "detailed_results": self.all_results,
        }

        # Add category breakdowns
        for cat, results in by_category.items():
            cat_success = sum(1 for r in results if r.get("status") == "success")
            summary["by_category"][cat] = {
                "total": len(results),
                "successful": cat_success,
                "success_rate": f"{(cat_success / len(results) * 100):.1f}%",
            }

        # Save summary
        summary_file = self.run_dir / "summary.json"
        with open(summary_file, "w") as f:
            json.dump(summary, f, indent=2)

        # Create markdown report
        md_report = self.create_markdown_report(summary)
        md_file = self.run_dir / "REPORT.md"
        with open(md_file, "w") as f:
            f.write(md_report)

        console.print(f"[green]✓ Summary saved to {summary_file}[/green]")
        console.print(f"[green]✓ Markdown report saved to {md_file}[/green]")

    def create_markdown_report(self, summary: dict[str, Any]) -> str:
        """Create a markdown formatted report."""
        md = f"""# CyberShield Test Results Report

**Run Date:** {summary["timestamp"]}
**Results Directory:** `tests/prompts/results/`

## Summary

| Metric | Value |
|--------|-------|
| Total Tests | {summary["summary"]["total_tests"]} |
| Successful | {summary["summary"]["successful"]} ✅ |
| Failed | {summary["summary"]["failed"]} ❌ |
| Errors | {summary["summary"]["errors"]} ⚠️ |
| Success Rate | {summary["summary"]["success_rate"]} |
| Avg Response Time | {summary["summary"]["average_response_time"]} |

## Results by Category

"""

        for cat, stats in summary["by_category"].items():
            md += f"""### {cat}
- Total: {stats["total"]}
- Successful: {stats["successful"]}
- Success Rate: {stats["success_rate"]}

"""

        md += """## Detailed Results

| Category | Test | Status | Response Time |
|----------|------|--------|---------------|
"""

        for r in summary["detailed_results"]:
            status_icon = "✅" if r.get("status") == "success" else "❌"
            time_str = f"{r['time']:.3f}s" if "time" in r else "N/A"
            md += f"| {r['category']} | {r['test']} | {status_icon} {r['status']} | {time_str} |\n"

        md += f"""
## Review Instructions

### View Detailed Results

Each test result is saved in a separate JSON file for detailed review:

1. **Text Analysis**: `{summary["run_directory"]}/text_analysis/`
2. **Image Analysis**: `{summary["run_directory"]}/image_analysis/`
3. **Multimodal**: `{summary["run_directory"]}/multimodal/`
4. **Batch**: `{summary["run_directory"]}/batch/`
5. **Tools**: `{summary["run_directory"]}/tools/`

### Example: View Image Test Results

```bash
# View what the security logs screenshot test returned
cat {summary["run_directory"]}/image_analysis/security_logs_screenshot.json | jq .

# View what the email PII test returned
cat {summary["run_directory"]}/image_analysis/email_with_pii.json | jq .

# View multimodal analysis results
cat {summary["run_directory"]}/multimodal/security_logs_+_text.json | jq .
```

### Result File Structure

Each result file contains:
- `timestamp`: When the test was run
- `category`: Test category
- `test_name`: Name of the test
- `metadata`: Test inputs and configuration
- `api_response`: Complete API response for review

---

**Generated by CyberShield Test Suite**
"""

        return md

    def run_all_tests(self):
        """Run all tests and save results."""
        console.print(
            "[bold cyan]CyberShield Comprehensive Test Result Capture[/bold cyan]\n"
        )

        if not self.check_server():
            console.print("[red]Error: Server not running at {BASE_URL}[/red]")
            console.print("[yellow]Start server with: cybershield[/yellow]")
            return

        console.print("[green]✓ Server is running[/green]")
        console.print(f"[cyan]Results will be saved to: {self.run_dir}[/cyan]\n")

        # Run all test categories
        self.test_text_analysis()
        self.test_image_analysis()
        self.test_multimodal_analysis()
        self.test_batch_analysis()
        self.test_tool_endpoints()

        # Generate summary
        self.generate_summary_report()

        console.print("\n[bold green]✓ All tests complete![/bold green]")
        console.print(f"[cyan]Review results at: {self.run_dir}[/cyan]")


def main():
    """Main entry point."""
    try:
        capture = ResultCapture()
        capture.run_all_tests()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


if __name__ == "__main__":
    main()
