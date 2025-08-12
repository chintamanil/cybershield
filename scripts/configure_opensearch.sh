#!/bin/bash
# Configure OpenSearch integration for CyberShield

set -e

echo "🔍 Configuring OpenSearch Integration"
echo "====================================="

# Wait for OpenSearch domain to be ready
echo "Checking OpenSearch domain status..."
DOMAIN_NAME="cybershield-vectorstore"

while true; do
    STATUS=$(aws opensearch describe-domain --domain-name $DOMAIN_NAME --query 'DomainStatus.Processing' --output text)
    if [ "$STATUS" = "False" ]; then
        echo "✅ OpenSearch domain is ready!"
        break
    fi
    echo "⏳ OpenSearch domain still creating... waiting 30s"
    sleep 30
done

# Get OpenSearch endpoint
OPENSEARCH_ENDPOINT=$(aws opensearch describe-domain --domain-name $DOMAIN_NAME --query 'DomainStatus.Endpoint' --output text)
echo "🔗 OpenSearch Endpoint: $OPENSEARCH_ENDPOINT"

# Update environment configuration
if [ -f "../.env.aws" ]; then
    ENV_FILE="../.env.aws"
elif [ -f ".env.aws" ]; then
    ENV_FILE=".env.aws"
else
    echo "❌ Error: .env.aws file not found"
    exit 1
fi

# Add OpenSearch configuration to .env.aws
echo "" >> "$ENV_FILE"
echo "# OpenSearch Configuration" >> "$ENV_FILE"
echo "OPENSEARCH_ENDPOINT=$OPENSEARCH_ENDPOINT" >> "$ENV_FILE"
echo "OPENSEARCH_PORT=443" >> "$ENV_FILE"
echo "OPENSEARCH_SSL=true" >> "$ENV_FILE"

echo "✅ Environment file updated with OpenSearch configuration"

# Create new task definition with OpenSearch environment variables
echo "Creating updated task definition with OpenSearch..."
cd /Users/manil/Projects/IK/Project-up/CyberShield/cybershield/scripts

# Load environment variables
source "$ENV_FILE"

# Create task definition with OpenSearch environment variables
cat > task-definition-opensearch.json << EOF
{
  "family": "cybershield-task",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "executionRoleArn": "arn:aws:iam::$AWS_ACCOUNT_ID:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::$AWS_ACCOUNT_ID:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "cybershield",
      "image": "$ECR_URI",
      "cpu": 1024,
      "memory": 2048,
      "essential": true,
      "portMappings": [
        {
          "containerPort": 8000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "CYBERSHIELD_ENV",
          "value": "aws"
        },
        {
          "name": "AWS_DEFAULT_REGION",
          "value": "$AWS_REGION"
        },
        {
          "name": "RDS_ENDPOINT",
          "value": "$RDS_ENDPOINT"
        },
        {
          "name": "RDS_PORT",
          "value": "$RDS_PORT"
        },
        {
          "name": "RDS_DATABASE",
          "value": "$RDS_DATABASE"
        },
        {
          "name": "RDS_USERNAME",
          "value": "$RDS_USERNAME"
        },
        {
          "name": "RDS_PASSWORD",
          "value": "$RDS_PASSWORD"
        },
        {
          "name": "REDIS_ENDPOINT",
          "value": "$REDIS_ENDPOINT"
        },
        {
          "name": "REDIS_PORT",
          "value": "$REDIS_PORT"
        },
        {
          "name": "POSTGRES_HOST",
          "value": "$RDS_ENDPOINT"
        },
        {
          "name": "POSTGRES_PORT",
          "value": "$RDS_PORT"
        },
        {
          "name": "POSTGRES_DB",
          "value": "$RDS_DATABASE"
        },
        {
          "name": "POSTGRES_USER",
          "value": "$RDS_USERNAME"
        },
        {
          "name": "POSTGRES_PASSWORD",
          "value": "$RDS_PASSWORD"
        },
        {
          "name": "REDIS_HOST",
          "value": "$REDIS_ENDPOINT"
        },
        {
          "name": "OPENSEARCH_ENDPOINT",
          "value": "$OPENSEARCH_ENDPOINT"
        },
        {
          "name": "OPENSEARCH_PORT",
          "value": "443"
        },
        {
          "name": "OPENSEARCH_SSL",
          "value": "true"
        },
        {
          "name": "OPENAI_API_KEY",
          "value": "$OPENAI_API_KEY"
        },
        {
          "name": "VIRUSTOTAL_API_KEY",
          "value": "$VIRUSTOTAL_API_KEY"
        },
        {
          "name": "SHODAN_API_KEY",
          "value": "$SHODAN_API_KEY"
        },
        {
          "name": "ABUSEIPDB_API_KEY",
          "value": "$ABUSEIPDB_API_KEY"
        },
        {
          "name": "DEBUG",
          "value": "$DEBUG"
        },
        {
          "name": "LOG_LEVEL",
          "value": "$LOG_LEVEL"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/cybershield",
          "awslogs-region": "$AWS_REGION",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": [
          "CMD-SHELL",
          "curl -f http://localhost:8000/health || exit 1"
        ],
        "interval": 30,
        "timeout": 10,
        "retries": 3,
        "startPeriod": 60
      }
    }
  ]
}
EOF

# Register new task definition
echo "Registering task definition with OpenSearch support..."
TASK_DEF_ARN=$(aws ecs register-task-definition \
    --cli-input-json file://task-definition-opensearch.json \
    --query 'taskDefinition.taskDefinitionArn' \
    --output text)

echo "✅ Task definition registered: $TASK_DEF_ARN"

# Update ECS service to use new task definition
echo "Updating ECS service with OpenSearch configuration..."
aws ecs update-service \
    --cluster cybershield-cluster \
    --service cybershield-service \
    --task-definition "$TASK_DEF_ARN" \
    --force-new-deployment

echo "✅ ECS service updated with OpenSearch integration"

# Clean up temporary files
rm task-definition-opensearch.json

echo ""
echo "🎉 OpenSearch Integration Complete!"
echo "========================================="
echo "OpenSearch Endpoint: $OPENSEARCH_ENDPOINT"
echo "ECS Service: cybershield-service (updating)"
echo ""
echo "Next steps:"
echo "1. Wait for ECS service to stabilize"
echo "2. Test vector search functionality"
echo "3. Run data migration if needed"