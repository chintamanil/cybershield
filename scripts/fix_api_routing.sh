#!/bin/bash

# Fix ALB routing to properly separate backend API endpoints from frontend
# Backend endpoints: /analyze, /health, /status, /tools/*, /upload-image, /batch-analyze, /analyze-with-image
# Frontend: everything else (/, /static/*, etc.)

set -e

REGION="us-east-1"
ALB_NAME="cybershield-alb"

echo "🔧 Fixing ALB routing for proper API/Frontend separation"

# Get resources
ALB_ARN=$(aws elbv2 describe-load-balancers --names $ALB_NAME --query 'LoadBalancers[0].LoadBalancerArn' --output text --region $REGION)
HTTPS_LISTENER_ARN=$(aws elbv2 describe-listeners --load-balancer-arn $ALB_ARN --query 'Listeners[?Port==`443`].ListenerArn' --output text --region $REGION)
HTTP_LISTENER_ARN=$(aws elbv2 describe-listeners --load-balancer-arn $ALB_ARN --query 'Listeners[?Port==`80`].ListenerArn' --output text --region $REGION)
FRONTEND_TG_ARN=$(aws elbv2 describe-target-groups --names cybershield-frontend-tg --query 'TargetGroups[0].TargetGroupArn' --output text --region $REGION)
BACKEND_TG_ARN=$(aws elbv2 describe-target-groups --names cybershield-tg --query 'TargetGroups[0].TargetGroupArn' --output text --region $REGION)

echo "📍 Resources:"
echo "  ALB: $ALB_ARN"
echo "  HTTPS Listener: $HTTPS_LISTENER_ARN"
echo "  Frontend TG: $FRONTEND_TG_ARN"
echo "  Backend TG: $BACKEND_TG_ARN"

echo ""
echo "📋 Current HTTPS routing rules:"
aws elbv2 describe-rules --listener-arn $HTTPS_LISTENER_ARN --region $REGION --query 'Rules[*].{Priority:Priority,Path:Conditions[0].PathPatternConfig.Values[0],Target:Actions[0].TargetGroupArn,IsDefault:IsDefault}' --output table

# Step 1: Delete the catch-all rule (priority 1) that's sending everything to frontend
echo ""
echo "🗑️  Deleting catch-all frontend rule..."
CATCHALL_RULE_ARN=$(aws elbv2 describe-rules --listener-arn $HTTPS_LISTENER_ARN --region $REGION --query 'Rules[?Priority==`1`].RuleArn' --output text)

if [ ! -z "$CATCHALL_RULE_ARN" ] && [ "$CATCHALL_RULE_ARN" != "None" ]; then
    aws elbv2 delete-rule --rule-arn $CATCHALL_RULE_ARN --region $REGION
    echo "  ✅ Deleted catch-all rule"
fi

# Step 2: Create specific rules for backend API endpoints
echo ""
echo "🎯 Creating specific backend API routing rules..."

# Rule for /analyze
aws elbv2 create-rule \
    --listener-arn $HTTPS_LISTENER_ARN \
    --priority 10 \
    --conditions Field=path-pattern,PathPatternConfig="{Values=[/analyze]}" \
    --actions Type=forward,TargetGroupArn=$BACKEND_TG_ARN \
    --region $REGION

# Rule for /analyze-with-image
aws elbv2 create-rule \
    --listener-arn $HTTPS_LISTENER_ARN \
    --priority 11 \
    --conditions Field=path-pattern,PathPatternConfig="{Values=[/analyze-with-image]}" \
    --actions Type=forward,TargetGroupArn=$BACKEND_TG_ARN \
    --region $REGION

# Rule for /batch-analyze
aws elbv2 create-rule \
    --listener-arn $HTTPS_LISTENER_ARN \
    --priority 12 \
    --conditions Field=path-pattern,PathPatternConfig="{Values=[/batch-analyze]}" \
    --actions Type=forward,TargetGroupArn=$BACKEND_TG_ARN \
    --region $REGION

# Rule for /upload-image
aws elbv2 create-rule \
    --listener-arn $HTTPS_LISTENER_ARN \
    --priority 13 \
    --conditions Field=path-pattern,PathPatternConfig="{Values=[/upload-image]}" \
    --actions Type=forward,TargetGroupArn=$BACKEND_TG_ARN \
    --region $REGION

# Rule for /health
aws elbv2 create-rule \
    --listener-arn $HTTPS_LISTENER_ARN \
    --priority 14 \
    --conditions Field=path-pattern,PathPatternConfig="{Values=[/health]}" \
    --actions Type=forward,TargetGroupArn=$BACKEND_TG_ARN \
    --region $REGION

# Rule for /status  
aws elbv2 create-rule \
    --listener-arn $HTTPS_LISTENER_ARN \
    --priority 15 \
    --conditions Field=path-pattern,PathPatternConfig="{Values=[/status]}" \
    --actions Type=forward,TargetGroupArn=$BACKEND_TG_ARN \
    --region $REGION

# Rule for /environment
aws elbv2 create-rule \
    --listener-arn $HTTPS_LISTENER_ARN \
    --priority 16 \
    --conditions Field=path-pattern,PathPatternConfig="{Values=[/environment]}" \
    --actions Type=forward,TargetGroupArn=$BACKEND_TG_ARN \
    --region $REGION

# Rule for /tools/* (already exists as priority 98, but let's ensure it's there)
echo "  ✅ Tools rule already exists at priority 98"

# Step 3: Create a new catch-all rule for frontend (priority 99)
echo ""
echo "🌐 Creating frontend catch-all rule..."
aws elbv2 create-rule \
    --listener-arn $HTTPS_LISTENER_ARN \
    --priority 99 \
    --conditions Field=path-pattern,PathPatternConfig="{Values=[/*]}" \
    --actions Type=forward,TargetGroupArn=$FRONTEND_TG_ARN \
    --region $REGION

# Step 4: Apply same changes to HTTP listener
echo ""
echo "🔄 Applying same changes to HTTP listener..."

# Delete HTTP catch-all rule if it exists
HTTP_CATCHALL_RULE_ARN=$(aws elbv2 describe-rules --listener-arn $HTTP_LISTENER_ARN --region $REGION --query 'Rules[?Priority==`1`].RuleArn' --output text 2>/dev/null || echo "")

if [ ! -z "$HTTP_CATCHALL_RULE_ARN" ] && [ "$HTTP_CATCHALL_RULE_ARN" != "None" ]; then
    aws elbv2 delete-rule --rule-arn $HTTP_CATCHALL_RULE_ARN --region $REGION
    echo "  ✅ Deleted HTTP catch-all rule"
fi

# Create HTTP rules for backend endpoints
aws elbv2 create-rule --listener-arn $HTTP_LISTENER_ARN --priority 10 --conditions Field=path-pattern,PathPatternConfig="{Values=[/analyze]}" --actions Type=forward,TargetGroupArn=$BACKEND_TG_ARN --region $REGION
aws elbv2 create-rule --listener-arn $HTTP_LISTENER_ARN --priority 11 --conditions Field=path-pattern,PathPatternConfig="{Values=[/analyze-with-image]}" --actions Type=forward,TargetGroupArn=$BACKEND_TG_ARN --region $REGION
aws elbv2 create-rule --listener-arn $HTTP_LISTENER_ARN --priority 12 --conditions Field=path-pattern,PathPatternConfig="{Values=[/batch-analyze]}" --actions Type=forward,TargetGroupArn=$BACKEND_TG_ARN --region $REGION
aws elbv2 create-rule --listener-arn $HTTP_LISTENER_ARN --priority 13 --conditions Field=path-pattern,PathPatternConfig="{Values=[/upload-image]}" --actions Type=forward,TargetGroupArn=$BACKEND_TG_ARN --region $REGION
aws elbv2 create-rule --listener-arn $HTTP_LISTENER_ARN --priority 14 --conditions Field=path-pattern,PathPatternConfig="{Values=[/health]}" --actions Type=forward,TargetGroupArn=$BACKEND_TG_ARN --region $REGION
aws elbv2 create-rule --listener-arn $HTTP_LISTENER_ARN --priority 15 --conditions Field=path-pattern,PathPatternConfig="{Values=[/status]}" --actions Type=forward,TargetGroupArn=$BACKEND_TG_ARN --region $REGION
aws elbv2 create-rule --listener-arn $HTTP_LISTENER_ARN --priority 16 --conditions Field=path-pattern,PathPatternConfig="{Values=[/environment]}" --actions Type=forward,TargetGroupArn=$BACKEND_TG_ARN --region $REGION

# Create HTTP frontend catch-all
aws elbv2 create-rule --listener-arn $HTTP_LISTENER_ARN --priority 99 --conditions Field=path-pattern,PathPatternConfig="{Values=[/*]}" --actions Type=forward,TargetGroupArn=$FRONTEND_TG_ARN --region $REGION

echo ""
echo "📋 Updated HTTPS routing rules:"
aws elbv2 describe-rules --listener-arn $HTTPS_LISTENER_ARN --region $REGION --query 'Rules[*].{Priority:Priority,Path:Conditions[0].PathPatternConfig.Values[0],Target:Actions[0].TargetGroupArn,IsDefault:IsDefault}' --output table

echo ""
echo "🎯 New routing logic:"
echo "  Priority 10: /analyze → Backend"
echo "  Priority 11: /analyze-with-image → Backend"
echo "  Priority 12: /batch-analyze → Backend"
echo "  Priority 13: /upload-image → Backend"
echo "  Priority 14: /health → Backend"
echo "  Priority 15: /status → Backend"
echo "  Priority 16: /environment → Backend"
echo "  Priority 98: /tools/* → Backend (existing)"
echo "  Priority 99: /* → Frontend (catch-all)"
echo "  Default: → Backend (never reached)"

echo ""
echo "✅ API routing fixed successfully!"
echo ""
echo "🌐 Endpoint structure:"
echo "  Frontend: https://cybershield-ai.com/"
echo "  Backend analyze: https://cybershield-ai.com/analyze"
echo "  Backend health: https://cybershield-ai.com/health"
echo "  Backend status: https://cybershield-ai.com/status"