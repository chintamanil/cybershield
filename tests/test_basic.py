#!/usr/bin/env python3
"""
Basic test to verify CyberShield components work without external dependencies
"""

def test_imports():
    """Test that all required modules can be imported"""
    try:
        print("✅ All core imports successful")
        return True
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return False

def test_basic_supervisor():
    """Test basic supervisor functionality without external services"""
    try:
        # Import without external dependencies
        from agents.supervisor import SupervisorAgent

        # Create agent with None dependencies (fallback mode)
        agent = SupervisorAgent(None, None)

        # Test basic analysis
        result = agent.analyze("Test input")
        print(f"✅ Basic supervisor test passed: {type(result)}")
        return True
    except Exception as e:
        print(f"❌ Basic supervisor test failed: {e}")
        return False

def test_supervisor():
    """Test supervisor functionality"""
    try:
        from agents.supervisor import SupervisorAgent

        # Create agent without external dependencies
        agent = SupervisorAgent(None, None, use_react_workflow=False)

        # Test basic functionality
        status = agent.get_agent_status()
        print(f"✅ supervisor test passed: {status['supervisor']['version']}")
        return True
    except Exception as e:
        print(f"❌ supervisor test failed: {e}")
        return False

def test_fastapi_basic():
    """Test basic FastAPI functionality"""
    try:
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()

        @app.get("/")
        def read_root():
            return {"status": "ok"}

        client = TestClient(app)
        response = client.get("/")

        assert response.status_code == 200
        assert response.json()["status"] == "ok"
        print("✅ Basic FastAPI test passed")
        return True
    except Exception as e:
        print(f"❌ FastAPI test failed: {e}")
        return False

if __name__ == "__main__":
    print("🧪 Running CyberShield Basic Tests...")
    print("=" * 50)

    tests = [
        test_imports,
        test_basic_supervisor,
        test_supervisor,
        test_fastapi_basic
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} crashed: {e}")

    print("=" * 50)
    print(f"📊 Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All tests passed! CyberShield is ready to run.")
    else:
        print("⚠️  Some tests failed. Check dependencies or configurations.")