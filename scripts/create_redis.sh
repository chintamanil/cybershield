#!/bin/bash
# Create ElastiCache Redis Cluster for CyberShield

set -e

echo "🔴 Creating ElastiCache Redis Cluster"
echo "====================================="

# Load environment variables from the correct path
if [ -f "../.env.aws" ]; then
    source ../.env.aws
elif [ -f ".env.aws" ]; then
    source .env.aws
else
    echo "❌ Error: .env.aws file not found"
    exit 1
fi

echo "Creating Redis subnet group..."
REDIS_SUBNET_GROUP_NAME="${PROJECT_NAME:-cybershield}-redis-subnet-group"

# Check if Redis subnet group already exists
if aws elasticache describe-cache-subnet-groups --cache-subnet-group-name "$REDIS_SUBNET_GROUP_NAME" >/dev/null 2>&1; then
    echo "✅ Redis subnet group already exists: $REDIS_SUBNET_GROUP_NAME"
else
    # Create Redis subnet group using private subnets
    aws elasticache create-cache-subnet-group \
        --cache-subnet-group-name "$REDIS_SUBNET_GROUP_NAME" \
        --cache-subnet-group-description "Redis subnet group for CyberShield" \
        --subnet-ids "$PRIVATE_SUBNET_1" "$PRIVATE_SUBNET_2"
    
    echo "✅ Redis subnet group created: $REDIS_SUBNET_GROUP_NAME"
fi

echo "Creating Redis cluster..."
REDIS_CLUSTER_ID="${PROJECT_NAME:-cybershield}-redis"

# Check if Redis cluster already exists
if aws elasticache describe-cache-clusters --cache-cluster-id "$REDIS_CLUSTER_ID" >/dev/null 2>&1; then
    echo "✅ Redis cluster already exists: $REDIS_CLUSTER_ID"
else
    # Create Redis cluster
    aws elasticache create-cache-cluster \
        --cache-cluster-id "$REDIS_CLUSTER_ID" \
        --engine "redis" \
        --cache-node-type "cache.t3.micro" \
        --num-cache-nodes 1 \
        --cache-subnet-group-name "$REDIS_SUBNET_GROUP_NAME" \
        --security-group-ids "$REDIS_SECURITY_GROUP" \
        --tags Key=Name,Value="$REDIS_CLUSTER_ID" \
               Key=Project,Value=cybershield \
               Key=Environment,Value=production

    echo "✅ Redis cluster creation initiated: $REDIS_CLUSTER_ID"
fi

echo "⏳ Waiting for Redis cluster to be available (this may take 3-5 minutes)..."

# Wait for Redis cluster to be available
aws elasticache wait cache-cluster-available --cache-cluster-id "$REDIS_CLUSTER_ID"

# Get the Redis endpoint
REDIS_ENDPOINT=$(aws elasticache describe-cache-clusters \
    --cache-cluster-id "$REDIS_CLUSTER_ID" \
    --show-cache-node-info \
    --query 'CacheClusters[0].CacheNodes[0].Endpoint.Address' \
    --output text)

REDIS_PORT=$(aws elasticache describe-cache-clusters \
    --cache-cluster-id "$REDIS_CLUSTER_ID" \
    --show-cache-node-info \
    --query 'CacheClusters[0].CacheNodes[0].Endpoint.Port' \
    --output text)

echo "✅ Redis cluster is now available!"
echo "📋 Redis Details:"
echo "   Cluster ID: $REDIS_CLUSTER_ID"
echo "   Endpoint: $REDIS_ENDPOINT"
echo "   Port: $REDIS_PORT"

# Update .env.aws with Redis information
echo ""
echo "💾 Updating .env.aws with Redis configuration..."

# Add Redis configuration to .env.aws
if [ -f "../.env.aws" ]; then
    ENV_FILE="../.env.aws"
elif [ -f ".env.aws" ]; then
    ENV_FILE=".env.aws"
else
    echo "❌ Error: .env.aws file not found for updating"
    exit 1
fi

cat >> "$ENV_FILE" << EOF

# ElastiCache Redis Configuration
REDIS_ENDPOINT=$REDIS_ENDPOINT
REDIS_PORT=$REDIS_PORT
REDIS_CLUSTER_ID=$REDIS_CLUSTER_ID
REDIS_SUBNET_GROUP=$REDIS_SUBNET_GROUP_NAME
EOF

echo "✅ Configuration updated in .env.aws"
echo ""
echo "🔄 Next Steps:"
echo "1. Create ECS cluster: ./scripts/create_ecs.sh"
echo "2. Deploy application: ./scripts/deploy_app.sh"
echo "3. Test deployment: ./scripts/test_deployment.sh"