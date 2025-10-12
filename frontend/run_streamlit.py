#!/usr/bin/env python3
"""
CyberShield Streamlit Application Runner
"""

import os
import sys
import subprocess
import time
import requests
from pathlib import Path


def check_fastapi_backend(
    url: str = "http://localhost:8000", timeout: int = 30
) -> bool:
    """Check if FastAPI backend is running"""
    print(f"🔍 Checking FastAPI backend at {url}...")

    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = requests.get(f"{url}/health", timeout=5)
            if response.status_code == 200:
                print("✅ FastAPI backend is running")
                return True
        except requests.exceptions.RequestException:
            pass

        print("⏳ Waiting for FastAPI backend...")
        time.sleep(2)

    print("❌ FastAPI backend not found")
    return False


def install_requirements():
    """Install required packages"""
    requirements_file = Path(__file__).parent / "requirements.txt"

    if requirements_file.exists():
        print("📦 Installing Streamlit requirements...")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "-r", str(requirements_file)],
                check=True,
            )
            print("✅ Requirements installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install requirements: {e}")
            return False
    else:
        print("⚠️ requirements.txt not found, skipping installation")

    return True


def run_streamlit():
    """Run the Streamlit application"""
    # Check if user wants original backup version
    use_original = "--original" in sys.argv

    if use_original:
        app_file = Path(__file__).parent / "streamlit_app_original_backup.py"
        if not app_file.exists():
            print("❌ Original backup not found. Using current version.")
            app_file = Path(__file__).parent / "streamlit_app.py"
        else:
            print("ℹ️ Using original backup version")
    else:
        app_file = Path(__file__).parent / "streamlit_app.py"

    if not app_file.exists():
        print(f"❌ Streamlit app file not found: {app_file}")
        return False

    print(f"🚀 Starting CyberShield Streamlit Frontend...")

    # Set environment variables
    os.environ["STREAMLIT_SERVER_PORT"] = "8501"
    os.environ["STREAMLIT_SERVER_ENABLE_CORS"] = "false"

    try:
        subprocess.run(
            [
                "streamlit",
                "run",
                str(app_file),
                "--server.port",
                "8501",
                "--server.address",
                "0.0.0.0",
                "--browser.gatherUsageStats",
                "false",
                "--server.maxUploadSize",
                "200",
            ],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to start Streamlit: {e}")
        return False
    except KeyboardInterrupt:
        print("\n👋 Streamlit application stopped")
        return True

    return True


def main():
    """Main function"""
    print("🛡️ CyberShield Streamlit Frontend Launcher")
    print("=" * 50)

    # Show help if requested
    if "--help" in sys.argv or "-h" in sys.argv:
        print("""
Usage: python run_streamlit.py [OPTIONS]

Options:
  --install              Install requirements before running
  --setup                Same as --install
  --no-backend-check     Skip FastAPI backend connectivity check
  --original             Use original streamlit_app.py (default: refactored)
  --help, -h             Show this help message

Examples:
  python run_streamlit.py                    # Run refactored version
  python run_streamlit.py --original         # Run original version
  python run_streamlit.py --install          # Install deps and run
  python run_streamlit.py --no-backend-check # Skip backend check
        """)
        sys.exit(0)

    # Check if we should install requirements
    if "--install" in sys.argv or "--setup" in sys.argv:
        if not install_requirements():
            sys.exit(1)

    # Check if we should skip backend check
    skip_backend_check = "--no-backend-check" in sys.argv

    if not skip_backend_check:
        # Check FastAPI backend
        if not check_fastapi_backend():
            print("❌ FastAPI backend is required. Please start it first:")
            print("   cd /path/to/cybershield")
            print("   python server/main.py")
            print("\nOr use --no-backend-check to skip this check")
            sys.exit(1)

    # Run Streamlit
    if not run_streamlit():
        sys.exit(1)


if __name__ == "__main__":
    main()
