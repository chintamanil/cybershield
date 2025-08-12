#!/bin/bash
# Test AWS deployment script

set -e

echo "🧪 CyberShield AWS Deployment Test"
echo "=================================="

# Get stack outputs
echo "📋 Retrieving deployment information..."

OUTPUTS=$(aws cloudformation describe-stacks \
    --stack-name CyberShieldStack \
    --query 'Stacks[0].Outputs')

if [ "$OUTPUTS" == "null" ] || [ -z "$OUTPUTS" ]; then
    echo "❌ CyberShieldStack not found. Please deploy first."
    exit 1
fi

# Extract URLs
ALB_URL=$(echo "$OUTPUTS" | jq -r '.[] | select(.OutputKey=="LoadBalancerDNS") | .OutputValue')
CLOUDFRONT_URL=$(echo "$OUTPUTS" | jq -r '.[] | select(.OutputKey=="CloudFrontDomain") | .OutputValue')

echo "🌐 Testing endpoints:"
echo "Load Balancer: https://$ALB_URL"
echo "CloudFront: https://$CLOUDFRONT_URL"
echo ""

# Test health endpoint
echo "🔍 Testing health endpoint..."
for url in "https://$ALB_URL" "https://$CLOUDFRONT_URL"; do
    echo "Testing: $url/health"
    
    if curl -s -o /dev/null -w "%{http_code}" "$url/health" | grep -q "200"; then
        echo "✅ Health check passed: $url"
    else
        echo "❌ Health check failed: $url"
    fi
done

echo ""

# Test status endpoint
echo "🔍 Testing status endpoint..."
for url in "https://$ALB_URL" "https://$CLOUDFRONT_URL"; do
    echo "Testing: $url/status"
    
    response=$(curl -s "$url/status" || echo "failed")
    
    if echo "$response" | jq -e '.status == "online"' > /dev/null 2>&1; then
        echo "✅ Status check passed: $url"
        echo "   Environment: $(echo "$response" | jq -r '.environment.type // "unknown"')"
        echo "   Features: $(echo "$response" | jq -r '.features | length // 0') enabled"
    else
        echo "❌ Status check failed: $url"
        echo "   Response: $response"
    fi
done

echo ""

# Test analyze endpoint with sample data
echo "🔬 Testing analysis endpoint..."

SAMPLE_DATA='{"text": "Failed login attempt from 203.0.113.1 for user admin", "use_react_workflow": true}'

for url in "https://$ALB_URL" "https://$CLOUDFRONT_URL"; do
    echo "Testing: $url/analyze"
    
    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "$SAMPLE_DATA" \
        "$url/analyze" || echo "failed")
    
    if echo "$response" | jq -e '.status == "success"' > /dev/null 2>&1; then
        echo "✅ Analysis test passed: $url"
        echo "   Processing method: $(echo "$response" | jq -r '.result.processing_method // "unknown"')"
        echo "   Processing time: $(echo "$response" | jq -r '.processing_time // "unknown"')s"
    else
        echo "❌ Analysis test failed: $url"
        echo "   Response: $(echo "$response" | head -c 200)..."
    fi
done

echo ""

# Check ECS service status
echo "🏃 Checking ECS service status..."

CLUSTER_NAME=$(aws ecs list-clusters --query 'clusterArns[0]' --output text | cut -d'/' -f2)
SERVICE_NAME=$(aws ecs list-services --cluster "$CLUSTER_NAME" --query 'serviceArns[0]' --output text | cut -d'/' -f3)

if [ "$CLUSTER_NAME" != "None" ] && [ "$SERVICE_NAME" != "None" ]; then
    SERVICE_STATUS=$(aws ecs describe-services \
        --cluster "$CLUSTER_NAME" \
        --services "$SERVICE_NAME" \
        --query 'services[0].status' --output text)
    
    RUNNING_COUNT=$(aws ecs describe-services \
        --cluster "$CLUSTER_NAME" \
        --services "$SERVICE_NAME" \
        --query 'services[0].runningCount' --output text)
    
    DESIRED_COUNT=$(aws ecs describe-services \
        --cluster "$CLUSTER_NAME" \
        --services "$SERVICE_NAME" \
        --query 'services[0].desiredCount' --output text)
    
    echo "Service Status: $SERVICE_STATUS"
    echo "Running Tasks: $RUNNING_COUNT/$DESIRED_COUNT"
    
    if [ "$RUNNING_COUNT" == "$DESIRED_COUNT" ] && [ "$SERVICE_STATUS" == "ACTIVE" ]; then
        echo "✅ ECS service is healthy"
    else
        echo "⚠️ ECS service may be starting up or having issues"
    fi
else
    echo "❌ Could not find ECS service"
fi

echo ""

# Check CloudWatch logs
echo "📊 Recent CloudWatch logs (last 10 lines):"
LOG_GROUP="/aws/cybershield/application"

if aws logs describe-log-groups --log-group-name-prefix "$LOG_GROUP" > /dev/null 2>&1; then
    aws logs tail "$LOG_GROUP" --since 10m | tail -10 || echo "No recent logs found"
else
    echo "❌ Log group not found: $LOG_GROUP"
fi

echo ""
echo "🎯 Deployment Test Summary"
echo "========================="
echo "ALB URL: https://$ALB_URL"
echo "CloudFront URL: https://$CLOUDFRONT_URL"
echo ""
echo "📱 Access your CyberShield application at:"
echo "🌐 https://$CLOUDFRONT_URL"
echo ""
echo "📊 Monitor your application:"
echo "- CloudWatch Logs: AWS Console → CloudWatch → Log groups → $LOG_GROUP"
echo "- ECS Service: AWS Console → ECS → Clusters → $CLUSTER_NAME"
echo "- Load Balancer: AWS Console → EC2 → Load Balancers"
echo ""
echo "🔧 Troubleshooting:"
echo "- Check ECS service events in AWS Console"
echo "- Review CloudWatch logs for errors"
echo "- Verify API keys in Secrets Manager"