#!/bin/bash
# Create ECS Cluster and Application Load Balancer for CyberShield

set -e

echo "🚀 Creating ECS Cluster and Load Balancer"
echo "=========================================="

# Load environment variables from the correct path
if [ -f "../.env.aws" ]; then
    source ../.env.aws
elif [ -f ".env.aws" ]; then
    source .env.aws
else
    echo "❌ Error: .env.aws file not found"
    exit 1
fi

PROJECT_NAME="${PROJECT_NAME:-cybershield}"

echo "Creating ECS cluster..."
ECS_CLUSTER_NAME="${PROJECT_NAME}-cluster"

# Check if ECS cluster already exists
if aws ecs describe-clusters --clusters "$ECS_CLUSTER_NAME" --query 'clusters[0].clusterName' --output text 2>/dev/null | grep -q "$ECS_CLUSTER_NAME"; then
    echo "✅ ECS cluster already exists: $ECS_CLUSTER_NAME"
else
    # Try to create ECS cluster
    if aws ecs create-cluster \
        --cluster-name "$ECS_CLUSTER_NAME" \
        --capacity-providers FARGATE \
        --default-capacity-provider-strategy capacityProvider=FARGATE,weight=1 \
        --tags key=Name,value="$ECS_CLUSTER_NAME" \
               key=Project,value=cybershield \
               key=Environment,value=production >/dev/null 2>&1; then
        echo "✅ ECS cluster created: $ECS_CLUSTER_NAME"
    else
        echo "⚠️  ECS cluster creation failed - missing ECS permissions"
        echo "   Please create ECS policy with: ecs:*, application-autoscaling:*, iam:PassRole"
        echo "   Continuing with load balancer setup..."
    fi
fi

echo "Creating Application Load Balancer..."
ALB_NAME="${PROJECT_NAME}-alb"

# Check if ALB already exists
if aws elbv2 describe-load-balancers --names "$ALB_NAME" >/dev/null 2>&1; then
    echo "✅ Application Load Balancer already exists: $ALB_NAME"
    ALB_ARN=$(aws elbv2 describe-load-balancers --names "$ALB_NAME" --query 'LoadBalancers[0].LoadBalancerArn' --output text)
else
    # Create Application Load Balancer
    ALB_ARN=$(aws elbv2 create-load-balancer \
        --name "$ALB_NAME" \
        --subnets "$PUBLIC_SUBNET_1" "$PUBLIC_SUBNET_2" \
        --security-groups "$ALB_SECURITY_GROUP" \
        --scheme internet-facing \
        --type application \
        --ip-address-type ipv4 \
        --tags Key=Name,Value="$ALB_NAME" \
               Key=Project,Value=cybershield \
               Key=Environment,Value=production \
        --query 'LoadBalancers[0].LoadBalancerArn' --output text)

    echo "✅ Application Load Balancer created: $ALB_NAME"
fi

# Get ALB DNS name
ALB_DNS=$(aws elbv2 describe-load-balancers --load-balancer-arns "$ALB_ARN" --query 'LoadBalancers[0].DNSName' --output text)

echo "Creating target group..."
TARGET_GROUP_NAME="${PROJECT_NAME}-tg"

# Check if target group already exists
if aws elbv2 describe-target-groups --names "$TARGET_GROUP_NAME" >/dev/null 2>&1; then
    echo "✅ Target group already exists: $TARGET_GROUP_NAME"
    TARGET_GROUP_ARN=$(aws elbv2 describe-target-groups --names "$TARGET_GROUP_NAME" --query 'TargetGroups[0].TargetGroupArn' --output text)
else
    # Create target group for ECS
    TARGET_GROUP_ARN=$(aws elbv2 create-target-group \
        --name "$TARGET_GROUP_NAME" \
        --protocol HTTP \
        --port 8000 \
        --vpc-id "$VPC_ID" \
        --target-type ip \
        --health-check-protocol HTTP \
        --health-check-path "/health" \
        --health-check-interval-seconds 30 \
        --health-check-timeout-seconds 10 \
        --healthy-threshold-count 2 \
        --unhealthy-threshold-count 5 \
        --matcher HttpCode=200 \
        --tags Key=Name,Value="$TARGET_GROUP_NAME" \
               Key=Project,Value=cybershield \
               Key=Environment,Value=production \
        --query 'TargetGroups[0].TargetGroupArn' --output text)

    echo "✅ Target group created: $TARGET_GROUP_NAME"
fi

echo "Creating ALB listener..."
LISTENER_PORT=80

# Check if listener already exists
if aws elbv2 describe-listeners --load-balancer-arn "$ALB_ARN" --query 'Listeners[?Port==`80`]' --output text | grep -q "80"; then
    echo "✅ ALB listener already exists on port $LISTENER_PORT"
else
    # Create listener
    aws elbv2 create-listener \
        --load-balancer-arn "$ALB_ARN" \
        --protocol HTTP \
        --port "$LISTENER_PORT" \
        --default-actions Type=forward,TargetGroupArn="$TARGET_GROUP_ARN" \
        --tags Key=Name,Value="${PROJECT_NAME}-listener" \
               Key=Project,Value=cybershield \
               Key=Environment,Value=production

    echo "✅ ALB listener created on port $LISTENER_PORT"
fi

echo "✅ ECS infrastructure setup complete!"
echo ""
echo "📋 Infrastructure Summary:"
echo "   ECS Cluster: $ECS_CLUSTER_NAME"
echo "   Load Balancer: $ALB_DNS"
echo "   Target Group: $TARGET_GROUP_NAME"
echo ""

# Update .env.aws with ECS information
echo "💾 Updating .env.aws with ECS configuration..."

# Add ECS configuration to .env.aws
if [ -f "../.env.aws" ]; then
    ENV_FILE="../.env.aws"
elif [ -f ".env.aws" ]; then
    ENV_FILE=".env.aws"
else
    echo "❌ Error: .env.aws file not found for updating"
    exit 1
fi

cat >> "$ENV_FILE" << EOF

# ECS Configuration
ECS_CLUSTER_NAME=$ECS_CLUSTER_NAME
ALB_ARN=$ALB_ARN
ALB_DNS=$ALB_DNS
TARGET_GROUP_ARN=$TARGET_GROUP_ARN
TARGET_GROUP_NAME=$TARGET_GROUP_NAME
EOF

echo "✅ Configuration updated in .env.aws"
echo ""
echo "🔄 Next Steps:"
echo "1. Build and push Docker image: docker build -f Dockerfile.aws -t cybershield ."
echo "2. Deploy application: ./scripts/deploy_app.sh"
echo "3. Test deployment: curl http://$ALB_DNS/health"