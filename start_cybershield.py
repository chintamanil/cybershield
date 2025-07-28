#!/usr/bin/env python3
"""
CyberShield System Launcher
Starts both FastAPI backend and Streamlit frontend
"""

import os
import sys
import subprocess
import time
import signal
import threading
from pathlib import Path

class CyberShieldLauncher:
    """Launcher for CyberShield components"""
    
    def __init__(self):
        self.backend_process = None
        self.frontend_process = None
        self.shutdown_event = threading.Event()
    
    def start_backend(self):
        """Start FastAPI backend server"""
        print("🚀 Starting FastAPI backend...")
        
        backend_script = Path(__file__).parent / "server" / "main.py"
        
        if not backend_script.exists():
            print(f"❌ Backend script not found: {backend_script}")
            return False
        
        try:
            self.backend_process = subprocess.Popen([
                sys.executable, str(backend_script)
            ], cwd=str(Path(__file__).parent))
            
            print("✅ FastAPI backend started (PID: {})".format(self.backend_process.pid))
            return True
            
        except Exception as e:
            print(f"❌ Failed to start backend: {e}")
            return False
    
    def start_frontend(self):
        """Start Streamlit frontend"""
        print("🎨 Starting Streamlit frontend...")
        
        frontend_script = Path(__file__).parent / "frontend" / "streamlit_app.py"
        
        if not frontend_script.exists():
            print(f"❌ Frontend script not found: {frontend_script}")
            return False
        
        try:
            self.frontend_process = subprocess.Popen([
                "streamlit", "run", str(frontend_script),
                "--server.port", "8501",
                "--server.address", "0.0.0.0",
                "--browser.gatherUsageStats", "false",
                "--server.maxUploadSize", "200"
            ], cwd=str(Path(__file__).parent))
            
            print("✅ Streamlit frontend started (PID: {})".format(self.frontend_process.pid))
            return True
            
        except Exception as e:
            print(f"❌ Failed to start frontend: {e}")
            return False
    
    def wait_for_backend(self, timeout=30):
        """Wait for backend to be ready"""
        import requests
        
        print("⏳ Waiting for backend to be ready...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                response = requests.get("http://localhost:8000/health", timeout=2)
                if response.status_code == 200:
                    print("✅ Backend is ready!")
                    return True
            except requests.exceptions.RequestException:
                pass
            
            time.sleep(1)
        
        print("❌ Backend startup timeout")
        return False
    
    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            print(f"\n🛑 Received signal {signum}, shutting down...")
            self.shutdown()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def shutdown(self):
        """Shutdown all processes"""
        print("🛑 Shutting down CyberShield...")
        
        self.shutdown_event.set()
        
        if self.frontend_process:
            print("⏹️ Stopping Streamlit frontend...")
            self.frontend_process.terminate()
            try:
                self.frontend_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.frontend_process.kill()
            print("✅ Frontend stopped")
        
        if self.backend_process:
            print("⏹️ Stopping FastAPI backend...")
            self.backend_process.terminate()
            try:
                self.backend_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.backend_process.kill()
            print("✅ Backend stopped")
        
        print("👋 CyberShield shutdown complete")
    
    def check_dependencies(self):
        """Check if required dependencies are available"""
        print("🔍 Checking dependencies...")
        
        # Check Python version
        if sys.version_info < (3, 8):
            print("❌ Python 3.8+ required")
            return False
        
        # Check required packages
        required_packages = {
            "fastapi": "FastAPI backend framework",
            "streamlit": "Streamlit frontend framework", 
            "uvicorn": "ASGI server for FastAPI",
            "requests": "HTTP client library"
        }
        
        missing_packages = []
        
        for package, description in required_packages.items():
            try:
                __import__(package)
                print(f"✅ {package} - {description}")
            except ImportError:
                print(f"❌ {package} - {description} (MISSING)")
                missing_packages.append(package)
        
        if missing_packages:
            print(f"\n❌ Missing packages: {', '.join(missing_packages)}")
            print("Install with: pip install " + " ".join(missing_packages))
            return False
        
        print("✅ All dependencies satisfied")
        return True
    
    def display_info(self):
        """Display startup information"""
        print("🛡️ CyberShield AI Security System")
        print("=" * 50)
        print("🌐 Backend API: http://localhost:8000")
        print("🎨 Frontend UI: http://localhost:8501")
        print("📚 API Docs: http://localhost:8000/docs")
        print("=" * 50)
        print("Press Ctrl+C to stop all services")
        print()
    
    def run(self):
        """Main run method"""
        print("🛡️ CyberShield System Launcher")
        print("=" * 40)
        
        # Check dependencies
        if not self.check_dependencies():
            sys.exit(1)
        
        # Setup signal handlers
        self.setup_signal_handlers()
        
        try:
            # Start backend
            if not self.start_backend():
                sys.exit(1)
            
            # Wait for backend to be ready
            if not self.wait_for_backend():
                self.shutdown()
                sys.exit(1)
            
            # Start frontend
            if not self.start_frontend():
                self.shutdown()
                sys.exit(1)
            
            # Display information
            self.display_info()
            
            # Wait for shutdown signal
            while not self.shutdown_event.is_set():
                # Check if processes are still running
                if self.backend_process and self.backend_process.poll() is not None:
                    print("❌ Backend process died unexpectedly")
                    break
                
                if self.frontend_process and self.frontend_process.poll() is not None:
                    print("❌ Frontend process died unexpectedly")
                    break
                
                time.sleep(1)
        
        except KeyboardInterrupt:
            print("\n🛑 Keyboard interrupt received")
        
        finally:
            self.shutdown()

def main():
    """Main entry point"""
    launcher = CyberShieldLauncher()
    
    # Check command line arguments
    if "--backend-only" in sys.argv:
        print("🚀 Starting backend only...")
        launcher.start_backend()
        launcher.wait_for_backend()
        input("Press Enter to stop...")
        launcher.shutdown()
    elif "--frontend-only" in sys.argv:
        print("🎨 Starting frontend only...")
        launcher.start_frontend()
        input("Press Enter to stop...")
        launcher.shutdown()
    else:
        # Start both services
        launcher.run()

if __name__ == "__main__":
    main()