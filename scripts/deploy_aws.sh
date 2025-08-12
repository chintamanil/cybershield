#!/bin/bash
# AWS Deployment Script for CyberShield

set -e

echo "🚀 CyberShield AWS Deployment"
echo "============================"

# Check if we're in the right directory
if [ ! -f "infrastructure/aws_cdk_stack.py" ]; then
    echo "❌ Please run this script from the CyberShield root directory"
    exit 1
fi

# Install Python dependencies for CDK
echo "📦 Installing CDK dependencies..."
pip install aws-cdk-lib constructs

# Bootstrap CDK (only needed once per account/region)
echo "🔧 Bootstrapping CDK..."
cdk bootstrap

# Synthesize the CloudFormation template
echo "🏗️ Synthesizing CDK template..."
cd infrastructure
cdk synth

# Deploy the infrastructure
echo "🚀 Deploying infrastructure..."
echo "This will create:"
echo "- VPC with public/private subnets"
echo "- RDS PostgreSQL database"
echo "- ElastiCache Redis cluster"
echo "- OpenSearch domain"
echo "- ECS Fargate service"
echo "- Application Load Balancer"
echo "- CloudFront distribution"
echo "- WAF security rules"
echo "- KMS encryption keys"
echo "- Secrets Manager secrets"
echo ""

read -p "Continue with deployment? (y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled"
    exit 1
fi

# Deploy the stack
cdk deploy --require-approval never

echo ""
echo "✅ Infrastructure deployment completed!"
echo ""

# Get stack outputs
echo "📋 Stack Outputs:"
echo "================="

aws cloudformation describe-stacks \
    --stack-name CyberShieldStack \
    --query 'Stacks[0].Outputs[*].[OutputKey,OutputValue]' \
    --output table

echo ""
echo "🔑 Next Steps:"
echo "=============="
echo ""
echo "1. Configure API keys in AWS Secrets Manager:"
echo "   - Go to AWS Console → Secrets Manager"
echo "   - Find 'CyberShieldAPIKeys' secret"
echo "   - Update with your actual API keys:"
echo "     * VirusTotal API Key"
echo "     * Shodan API Key" 
echo "     * AbuseIPDB API Key"
echo ""
echo "2. Wait for ECS service to be healthy (5-10 minutes)"
echo ""
echo "3. Test your deployment:"
echo "   - Load Balancer URL (from outputs above)"
echo "   - CloudFront URL (from outputs above)"
echo ""
echo "4. Configure your domain (optional):"
echo "   - Point your domain to CloudFront distribution"
echo "   - Set up SSL certificate in ACM"
echo ""

# Return to root directory
cd ..

echo "🎉 CyberShield is now deployed on AWS!"