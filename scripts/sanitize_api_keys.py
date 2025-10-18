#!/usr/bin/env python3
"""
Script to sanitize exposed API keys from test result files.
This removes sensitive API keys that may have been logged in error messages.
"""

import json
import re
from pathlib import Path
from typing import Any


def sanitize_api_key_in_url(url: str) -> str:
    """Replace API keys in URLs with [REDACTED]"""
    # Pattern to match API keys in query parameters
    patterns = [
        r"(key=)([A-Za-z0-9]{20,})",  # ?key=XXXXX
        r"(apikey=)([A-Za-z0-9]{20,})",  # ?apikey=XXXXX
        r"(api_key=)([A-Za-z0-9]{20,})",  # ?api_key=XXXXX
        r"(token=)([A-Za-z0-9]{20,})",  # ?token=XXXXX
    ]

    sanitized_url = url
    for pattern in patterns:
        sanitized_url = re.sub(pattern, r"\1[REDACTED]", sanitized_url)

    return sanitized_url


def sanitize_dict(data: Any) -> Any:
    """Recursively sanitize API keys in dictionary/list structures"""
    if isinstance(data, dict):
        return {key: sanitize_dict(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [sanitize_dict(item) for item in data]
    elif isinstance(data, str):
        # Check if string contains URLs with API keys
        if (
            "api.shodan.io" in data
            or "virustotal.com" in data
            or "abuseipdb.com" in data
        ):
            return sanitize_api_key_in_url(data)
        return data
    else:
        return data


def sanitize_json_file(file_path: Path) -> bool:
    """Sanitize a single JSON file"""
    try:
        print(f"🔍 Processing: {file_path}")

        # Read the file
        with open(file_path, encoding="utf-8") as f:
            data = json.load(f)

        # Sanitize the data
        sanitized_data = sanitize_dict(data)

        # Write back the sanitized data
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(sanitized_data, f, indent=2, ensure_ascii=False)

        print(f"✅ Sanitized: {file_path}")
        return True

    except Exception as e:
        print(f"❌ Error processing {file_path}: {e}")
        return False


def main():
    """Main function to sanitize all test result files"""
    print("🛡️ CyberShield API Key Sanitization Tool")
    print("=" * 60)
    print("\n⚠️  This will remove exposed API keys from test result files")
    print()

    # Files to sanitize
    test_results_dir = Path(__file__).parent.parent / "tests" / "prompts" / "results"

    files_to_sanitize = [
        test_results_dir / "memory_tests" / "incremental_threat_investigation.json",
        test_results_dir / "memory_tests" / "sequential_ioc_analysis.json",
        test_results_dir / "batch" / "mixed_batch_analysis.json",
        test_results_dir / "text_analysis" / "rate_limiting_test.json",
        test_results_dir / "text_analysis" / "firewall_block_with_dns_query.json",
        test_results_dir / "text_analysis" / "ssh_connection_attempt.json",
        test_results_dir / "text_analysis" / "failed_login_with_hash_and_domain.json",
    ]

    # Process each file
    success_count = 0
    for file_path in files_to_sanitize:
        if file_path.exists():
            if sanitize_json_file(file_path):
                success_count += 1
        else:
            print(f"⚠️  File not found: {file_path}")

    print()
    print("=" * 60)
    print(f"✅ Successfully sanitized {success_count}/{len(files_to_sanitize)} files")
    print()
    print("⚠️  IMPORTANT SECURITY STEPS:")
    print("1. Regenerate your Shodan API key at https://account.shodan.io/")
    print("2. Update your .env file with the new key")
    print("3. Commit these sanitized files")
    print("4. Consider adding 'tests/prompts/results/**/*.json' to .gitignore")


if __name__ == "__main__":
    main()
