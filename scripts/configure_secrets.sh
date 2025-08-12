#!/bin/bash
# Script to configure AWS Secrets Manager with API keys

set -e

echo "🔑 CyberShield API Keys Configuration"
echo "===================================="

# Check if AWS CLI is configured
if ! aws sts get-caller-identity &> /dev/null; then
    echo "❌ AWS CLI not configured. Please run aws configure first."
    exit 1
fi

# Get the secret ARN
SECRET_NAME="CyberShieldAPIKeys"
echo "🔍 Finding Secrets Manager secret..."

SECRET_ARN=$(aws secretsmanager list-secrets \
    --query "SecretList[?Name=='$SECRET_NAME'].ARN | [0]" \
    --output text)

if [ "$SECRET_ARN" == "None" ] || [ -z "$SECRET_ARN" ]; then
    echo "❌ Secret '$SECRET_NAME' not found. Please deploy the infrastructure first."
    exit 1
fi

echo "✅ Found secret: $SECRET_ARN"
echo ""

# Prompt for API keys
echo "📝 Please enter your API keys:"
echo "============================="

read -p "VirusTotal API Key: " VIRUSTOTAL_KEY
read -p "Shodan API Key: " SHODAN_KEY  
read -p "AbuseIPDB API Key: " ABUSEIPDB_KEY

# Validate keys are not empty
if [ -z "$VIRUSTOTAL_KEY" ] || [ -z "$SHODAN_KEY" ] || [ -z "$ABUSEIPDB_KEY" ]; then
    echo "❌ All API keys are required. Please try again."
    exit 1
fi

# Create JSON with API keys
API_KEYS_JSON=$(cat << EOF
{
  "virustotal": "$VIRUSTOTAL_KEY",
  "shodan": "$SHODAN_KEY", 
  "abuseipdb": "$ABUSEIPDB_KEY"
}
EOF
)

echo ""
echo "🔄 Updating Secrets Manager..."

# Update the secret
aws secretsmanager update-secret \
    --secret-id "$SECRET_ARN" \
    --secret-string "$API_KEYS_JSON"

echo "✅ API keys successfully configured in AWS Secrets Manager!"
echo ""

# Test the secret retrieval
echo "🧪 Testing secret retrieval..."
aws secretsmanager get-secret-value \
    --secret-id "$SECRET_ARN" \
    --query SecretString \
    --output text | jq .

echo ""
echo "🔄 Restarting ECS service to pick up new secrets..."

# Get ECS cluster and service names
CLUSTER_NAME=$(aws ecs list-clusters --query 'clusterArns[0]' --output text | cut -d'/' -f2)
SERVICE_NAME=$(aws ecs list-services --cluster "$CLUSTER_NAME" --query 'serviceArns[0]' --output text | cut -d'/' -f3)

if [ "$CLUSTER_NAME" != "None" ] && [ "$SERVICE_NAME" != "None" ]; then
    aws ecs update-service \
        --cluster "$CLUSTER_NAME" \
        --service "$SERVICE_NAME" \
        --force-new-deployment > /dev/null
    
    echo "✅ ECS service restart initiated"
    echo "⏳ New deployment will take 5-10 minutes to complete"
else
    echo "⚠️ Could not find ECS service. Please restart manually in AWS Console."
fi

echo ""
echo "🎉 Configuration complete!"
echo ""
echo "Next steps:"
echo "1. Wait for ECS service to redeploy (5-10 minutes)"
echo "2. Test your application endpoints"
echo "3. Monitor CloudWatch logs for any issues"