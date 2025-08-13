#!/bin/bash

# SSL Certificate Setup for cybershield-ai.com
# This script only handles the SSL certificate part

set -e

DOMAIN_NAME="cybershield-ai.com"
REGION="us-east-1"

echo "🔒 Setting up SSL certificate for: $DOMAIN_NAME"

# Request SSL certificate from ACM
echo "📜 Requesting SSL certificate from AWS Certificate Manager..."
CERT_ARN=$(aws acm request-certificate \
    --domain-name $DOMAIN_NAME \
    --subject-alternative-names "www.$DOMAIN_NAME" \
    --validation-method DNS \
    --query 'CertificateArn' \
    --output text \
    --region $REGION)

echo "✅ Certificate ARN: $CERT_ARN"

# Wait for validation records to be generated
echo "⏳ Waiting for DNS validation records..."
sleep 30

echo ""
echo "🎯 NEXT STEPS:"
echo "1. Go to your domain registrar (where you bought cybershield-ai.com)"
echo "2. Add these DNS validation records to your domain's DNS settings:"
echo ""

# Get and display DNS validation records
aws acm describe-certificate \
    --certificate-arn $CERT_ARN \
    --query 'Certificate.DomainValidationOptions[*].ResourceRecord.{Name:Name,Type:Type,Value:Value}' \
    --output table \
    --region $REGION

echo ""
echo "3. Also add these DNS records to point your domain to the load balancer:"
echo ""
echo "   Record Type: A"
echo "   Name: @ (or leave blank for root domain)"
echo "   Value: cybershield-alb-1386398593.us-east-1.elb.amazonaws.com"
echo ""
echo "   Record Type: CNAME"  
echo "   Name: www"
echo "   Value: cybershield-ai.com"
echo ""
echo "4. Wait 5-30 minutes for certificate validation"
echo "5. Run: ./update_alb_certificate.sh $CERT_ARN"
echo ""
echo "💾 Certificate ARN saved for next step: $CERT_ARN"
echo "$CERT_ARN" > cert_arn.txt

echo "✅ SSL certificate request completed!"
echo "📋 Next: Add the DNS records above to your domain registrar"