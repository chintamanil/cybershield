#!/bin/bash
# Check OpenSearch domain status and provide integration update

echo "🔍 OpenSearch Domain Status Check"
echo "=================================="

DOMAIN_NAME="cybershield-vectorstore"

# Get domain status
STATUS_JSON=$(aws opensearch describe-domain --domain-name $DOMAIN_NAME)
PROCESSING=$(echo $STATUS_JSON | jq -r '.DomainStatus.Processing')
ENDPOINT=$(echo $STATUS_JSON | jq -r '.DomainStatus.Endpoint')
DOMAIN_STATUS=$(echo $STATUS_JSON | jq -r '.DomainStatus.DomainProcessingStatus')
CLUSTER_CONFIG=$(echo $STATUS_JSON | jq -r '.DomainStatus.ClusterConfig')

echo "📊 Current Status:"
echo "  Domain: $DOMAIN_NAME"
echo "  Processing: $PROCESSING"
echo "  Status: $DOMAIN_STATUS"
echo "  Endpoint: $ENDPOINT"

if [ "$PROCESSING" = "false" ] && [ "$ENDPOINT" != "null" ]; then
    echo ""
    echo "✅ OpenSearch Domain is READY!"
    echo "🔗 Endpoint: https://$ENDPOINT"
    
    # Show cluster configuration
    echo ""
    echo "⚙️ Cluster Configuration:"
    echo $CLUSTER_CONFIG | jq '.'
    
    echo ""
    echo "🚀 Ready to run OpenSearch integration:"
    echo "  ./configure_opensearch.sh"
    
elif [ "$PROCESSING" = "true" ]; then
    echo ""
    echo "⏳ Domain is still being created..."
    echo "💡 This typically takes 10-15 minutes for new domains"
    
    # Show progress details if available
    CHANGE_DETAILS=$(echo $STATUS_JSON | jq -r '.DomainStatus.ChangeProgressDetails // empty')
    if [ ! -z "$CHANGE_DETAILS" ]; then
        echo ""
        echo "📈 Progress Details:"
        echo $STATUS_JSON | jq '.DomainStatus.ChangeProgressDetails'
    fi
    
    echo ""
    echo "🔄 Check again in 5 minutes with:"
    echo "  ./check_opensearch_status.sh"
    
else
    echo ""
    echo "❌ Unexpected domain status"
    echo "Raw status:"
    echo $STATUS_JSON | jq '.'
fi

echo ""
echo "💰 Estimated Monthly Cost: ~$25-50 USD (t3.small.search)"
echo "⚡ Next Steps After Ready:"
echo "  1. Run ./configure_opensearch.sh"
echo "  2. Update ECS task definition"  
echo "  3. Test vector search functionality"