#!/bin/bash
# AWS Setup Script for CyberShield

set -e

echo "🚀 CyberShield AWS Setup Script"
echo "================================"

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo "❌ AWS CLI not found. Installing..."
    
    # Detect OS and install AWS CLI
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"
        sudo installer -pkg AWSCLIV2.pkg -target /
        rm AWSCLIV2.pkg
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
        unzip awscliv2.zip
        sudo ./aws/install
        rm -rf aws awscliv2.zip
    else
        echo "❌ Unsupported OS. Please install AWS CLI manually:"
        echo "https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
        exit 1
    fi
else
    echo "✅ AWS CLI found: $(aws --version)"
fi

# Check if CDK is installed
if ! command -v cdk &> /dev/null; then
    echo "📦 Installing AWS CDK..."
    npm install -g aws-cdk
else
    echo "✅ AWS CDK found: $(cdk --version)"
fi

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker:"
    echo "https://docs.docker.com/get-docker/"
    exit 1
else
    echo "✅ Docker found: $(docker --version)"
fi

echo ""
echo "🔧 AWS Configuration Setup"
echo "=========================="

# Configure AWS CLI if not already configured
if ! aws sts get-caller-identity &> /dev/null; then
    echo "🔑 Please configure AWS CLI with your credentials:"
    echo ""
    echo "You'll need:"
    echo "- AWS Access Key ID"
    echo "- AWS Secret Access Key" 
    echo "- Default region (e.g., us-east-1)"
    echo "- Default output format (json)"
    echo ""
    
    aws configure
else
    echo "✅ AWS CLI already configured"
    aws sts get-caller-identity
fi

echo ""
echo "📋 Account Information"
echo "====================="

# Get AWS account info
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region)

echo "Account ID: $ACCOUNT_ID"
echo "Region: $REGION"

# Update CDK stack with actual account ID and region
echo ""
echo "🔧 Updating CDK configuration..."

# Update the account ID and region in the CDK stack
sed -i.bak "s/account=\"123456789012\"/account=\"$ACCOUNT_ID\"/" infrastructure/aws_cdk_stack.py
sed -i.bak "s/region=\"us-east-1\"/region=\"$REGION\"/" infrastructure/aws_cdk_stack.py

echo "✅ CDK configuration updated with Account ID: $ACCOUNT_ID, Region: $REGION"

echo ""
echo "🚀 Ready for AWS Deployment!"
echo "==========================="
echo ""
echo "Next steps:"
echo "1. Run: python scripts/deploy_aws.py"
echo "2. Configure API keys in AWS Secrets Manager"
echo "3. Test your deployment"