#!/usr/bin/env python3
# Setup script for configuring CyberShield environment

import os
import sys
import shutil
from pathlib import Path

def setup_local_environment():
    """Setup local development environment"""
    print("🔧 Setting up local development environment...")
    
    # Copy .env.local to .env if .env doesn't exist
    if not os.path.exists('.env'):
        if os.path.exists('.env.local'):
            shutil.copy('.env.local', '.env')
            print("✅ Created .env from .env.local")
        else:
            print("❌ .env.local not found. Please create it first.")
            return False
    
    # Set environment variable
    os.environ['CYBERSHIELD_ENV'] = 'local'
    
    print("✅ Local environment configured")
    print("📋 Next steps:")
    print("   1. Update .env with your API keys")
    print("   2. Start Docker services: docker-compose up -d")
    print("   3. Run the application: python server/main.py")
    
    return True

def setup_aws_environment():
    """Setup AWS production environment"""
    print("🚀 Setting up AWS production environment...")
    
    # Copy .env.aws to .env if .env doesn't exist
    if not os.path.exists('.env'):
        if os.path.exists('.env.aws'):
            shutil.copy('.env.aws', '.env')
            print("✅ Created .env from .env.aws")
        else:
            print("❌ .env.aws not found. Please create it first.")
            return False
    
    # Set environment variable
    os.environ['CYBERSHIELD_ENV'] = 'aws'
    
    print("✅ AWS environment configured")
    print("📋 Next steps:")
    print("   1. Configure AWS credentials: aws configure")
    print("   2. Update .env.aws with your AWS resource endpoints")
    print("   3. Deploy AWS infrastructure using CDK/CloudFormation")
    print("   4. Store API keys in AWS Secrets Manager")
    
    return True

def check_dependencies():
    """Check if required dependencies are installed"""
    print("🔍 Checking dependencies...")
    
    try:
        import boto3
        print("✅ boto3 installed")
    except ImportError:
        print("❌ boto3 not installed. Run: pip install boto3")
        return False
    
    try:
        import redis
        print("✅ redis installed")
    except ImportError:
        print("❌ redis not installed. Run: pip install redis")
        return False
    
    try:
        import psycopg2
        print("✅ psycopg2 installed")
    except ImportError:
        print("❌ psycopg2 not installed. Run: pip install psycopg2-binary")
        return False
    
    return True

def test_environment():
    """Test environment configuration"""
    print("🧪 Testing environment configuration...")
    
    try:
        from utils.environment_config import config
        from utils.service_factory import services
        
        print(f"✅ Environment detected: {config.detector.environment}")
        print(f"✅ LLM Provider: {config.llm.provider}")
        print(f"✅ Vector Store: {config.vector_store.provider}")
        print(f"✅ Database: {config.database.host}")
        print(f"✅ Redis: {config.redis.host}")
        
        return True
        
    except Exception as e:
        print(f"❌ Environment test failed: {e}")
        return False

def main():
    """Main setup function"""
    if len(sys.argv) < 2:
        print("Usage: python setup_environment.py [local|aws|test]")
        print("Commands:")
        print("  local - Setup for local development")
        print("  aws   - Setup for AWS deployment")
        print("  test  - Test current configuration")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    print("🛡️ CyberShield Environment Setup")
    print("=" * 40)
    
    if command == "local":
        if check_dependencies() and setup_local_environment():
            test_environment()
    elif command == "aws":
        if check_dependencies() and setup_aws_environment():
            test_environment()
    elif command == "test":
        test_environment()
    else:
        print(f"❌ Unknown command: {command}")
        sys.exit(1)

if __name__ == "__main__":
    main()