#!/bin/bash

# Update ALB with SSL certificate for cybershield-ai.com
# Run this AFTER certificate validation completes

set -e

CERT_ARN=${1}
REGION="us-east-1"
ALB_NAME="cybershield-alb"

if [ -z "$CERT_ARN" ]; then
    if [ -f "cert_arn.txt" ]; then
        CERT_ARN=$(cat cert_arn.txt)
        echo "📜 Using certificate ARN from file: $CERT_ARN"
    else
        echo "❌ Error: Certificate ARN required"
        echo "Usage: $0 <certificate-arn>"
        echo "Or ensure cert_arn.txt exists"
        exit 1
    fi
fi

echo "🔒 Updating ALB certificate for cybershield-ai.com"
echo "Certificate ARN: $CERT_ARN"

# Get ALB and listener details
ALB_ARN=$(aws elbv2 describe-load-balancers --names $ALB_NAME --query 'LoadBalancers[0].LoadBalancerArn' --output text --region $REGION)
HTTPS_LISTENER_ARN=$(aws elbv2 describe-listeners --load-balancer-arn $ALB_ARN --query 'Listeners[?Port==`443`].ListenerArn' --output text --region $REGION)

echo "📍 Resources:"
echo "  ALB: $ALB_ARN"
echo "  HTTPS Listener: $HTTPS_LISTENER_ARN"

# Check certificate status
echo ""
echo "🔍 Checking certificate status..."
CERT_STATUS=$(aws acm describe-certificate --certificate-arn $CERT_ARN --query 'Certificate.Status' --output text --region $REGION)

if [ "$CERT_STATUS" != "ISSUED" ]; then
    echo "⚠️  Certificate status: $CERT_STATUS"
    echo "❌ Certificate must be ISSUED before updating ALB"
    echo "📋 To check status: aws acm describe-certificate --certificate-arn $CERT_ARN --region $REGION"
    exit 1
fi

echo "✅ Certificate status: $CERT_STATUS"

# Update HTTPS listener with new certificate
echo ""
echo "🔄 Updating HTTPS listener with certificate..."
aws elbv2 modify-listener \
    --listener-arn $HTTPS_LISTENER_ARN \
    --certificates CertificateArn=$CERT_ARN \
    --region $REGION

echo ""
echo "🔍 Verifying certificate update..."
CURRENT_CERT=$(aws elbv2 describe-listeners --listener-arn $HTTPS_LISTENER_ARN --query 'Listeners[0].Certificates[0].CertificateArn' --output text --region $REGION)

if [ "$CURRENT_CERT" = "$CERT_ARN" ]; then
    echo "✅ Certificate successfully updated on ALB!"
else
    echo "❌ Certificate update failed. Current: $CURRENT_CERT"
    exit 1
fi

echo ""
echo "🎉 SSL Setup Complete!"
echo ""
echo "🌐 Your CyberShield platform is now available at:"
echo "  Frontend: https://cybershield-ai.com/"
echo "  Backend API: https://cybershield-ai.com/api/health"
echo "  Status: https://cybershield-ai.com/api/status"
echo ""
echo "📋 DNS propagation may take 5-60 minutes worldwide"
echo "🔒 SSL certificate automatically renews via AWS Certificate Manager"