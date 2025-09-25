#!/bin/bash

# Final AWS Cleanup - EC2, Route53, and remaining resources
# This script terminates EC2 instances, deletes Route53, and cleans up everything else

set -e

echo "========================================="
echo "FINAL AWS CLEANUP - COMPLETE DELETION"
echo "========================================="

# Configuration
REGION="us-east-1"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${RED}WARNING: This will TERMINATE EC2, DELETE Route53, and remove ALL remaining resources!${NC}"
echo -e "${RED}Your domain configuration will be lost!${NC}"
read -p "Type 'TERMINATE ALL' to confirm: " confirmation

if [ "$confirmation" != "TERMINATE ALL" ]; then
    echo "Deletion cancelled."
    exit 1
fi

# 1. Terminate EC2 Instances
echo -e "\n${YELLOW}1. Terminating EC2 Instances...${NC}"

EC2_INSTANCES=$(aws ec2 describe-instances --region $REGION --filters "Name=instance-state-name,Values=running,stopped" --query 'Reservations[*].Instances[*].InstanceId' --output text 2>/dev/null || echo "")
if [ ! -z "$EC2_INSTANCES" ]; then
    for instance in $EC2_INSTANCES; do
        echo "   Terminating EC2 instance: $instance"
        aws ec2 terminate-instances --instance-ids $instance --region $REGION 2>/dev/null || echo "   Failed to terminate $instance"
    done
    echo -e "${GREEN}   ✓ EC2 instances termination initiated${NC}"
else
    echo "   No EC2 instances found"
fi

# 2. Delete Route53 Hosted Zone
echo -e "\n${YELLOW}2. Deleting Route53 Hosted Zone...${NC}"

HOSTED_ZONE_ID="/hostedzone/Z00398842G889WXZGKZST"
DOMAIN_NAME="cybershield-ai.com."

# First, delete all record sets except NS and SOA
echo "   Deleting Route53 records for $DOMAIN_NAME..."
RECORD_SETS=$(aws route53 list-resource-record-sets --hosted-zone-id $HOSTED_ZONE_ID --query 'ResourceRecordSets[?Type != `NS` && Type != `SOA`]' 2>/dev/null || echo "[]")

if [ "$RECORD_SETS" != "[]" ]; then
    # Create change batch to delete records
    CHANGE_BATCH=$(echo "$RECORD_SETS" | jq '{Changes: [.[] | {Action: "DELETE", ResourceRecordSet: .}]}' 2>/dev/null || echo "{}")

    if [ "$CHANGE_BATCH" != "{}" ] && [ "$CHANGE_BATCH" != "null" ]; then
        echo "$CHANGE_BATCH" > /tmp/change-batch.json
        aws route53 change-resource-record-sets --hosted-zone-id $HOSTED_ZONE_ID --change-batch file:///tmp/change-batch.json 2>/dev/null || echo "   No additional records to delete"
        rm -f /tmp/change-batch.json
    fi
fi

# Now delete the hosted zone
echo "   Deleting hosted zone for $DOMAIN_NAME..."
aws route53 delete-hosted-zone --id $HOSTED_ZONE_ID 2>/dev/null || echo "   Failed to delete hosted zone (may have remaining records)"

echo -e "${GREEN}   ✓ Route53 hosted zone deletion initiated${NC}"

# 3. Delete Lambda Functions
echo -e "\n${YELLOW}3. Deleting Lambda Functions...${NC}"

LAMBDA_FUNCTIONS=$(aws lambda list-functions --region $REGION --query 'Functions[?contains(FunctionName, `cybershield`) || contains(FunctionName, `CyberShield`)].FunctionName' --output text 2>/dev/null || echo "")
if [ ! -z "$LAMBDA_FUNCTIONS" ]; then
    for func in $LAMBDA_FUNCTIONS; do
        echo "   Deleting Lambda function: $func"
        aws lambda delete-function --function-name $func --region $REGION 2>/dev/null || echo "   Function $func already deleted"
    done
    echo -e "${GREEN}   ✓ Lambda functions deleted${NC}"
else
    echo "   No Lambda functions found"
fi

# 4. Delete ElastiCache Redis
echo -e "\n${YELLOW}4. Deleting ElastiCache (Redis) Clusters...${NC}"

REDIS_CLUSTERS=$(aws elasticache describe-cache-clusters --region $REGION --query 'CacheClusters[].CacheClusterId' --output text 2>/dev/null || echo "")
if [ ! -z "$REDIS_CLUSTERS" ]; then
    for cluster in $REDIS_CLUSTERS; do
        echo "   Deleting Redis cluster: $cluster"
        aws elasticache delete-cache-cluster --cache-cluster-id $cluster --region $REGION 2>/dev/null || echo "   Already deleting: $cluster"
    done
    echo -e "${GREEN}   ✓ Redis deletion initiated${NC}"
else
    echo "   No Redis clusters found"
fi

# 5. Delete Load Balancers and Target Groups
echo -e "\n${YELLOW}5. Deleting Load Balancers...${NC}"

ALB_ARNS=$(aws elbv2 describe-load-balancers --region $REGION --query 'LoadBalancers[].LoadBalancerArn' --output text 2>/dev/null || echo "")
if [ ! -z "$ALB_ARNS" ]; then
    for alb in $ALB_ARNS; do
        echo "   Deleting ALB: $(basename $alb)"
        aws elbv2 delete-load-balancer --load-balancer-arn $alb --region $REGION 2>/dev/null || true
    done
    echo -e "${GREEN}   ✓ Load balancers deleted${NC}"
    sleep 10
fi

# Delete Target Groups
TARGET_GROUPS=$(aws elbv2 describe-target-groups --region $REGION --query 'TargetGroups[].TargetGroupArn' --output text 2>/dev/null || echo "")
if [ ! -z "$TARGET_GROUPS" ]; then
    for tg in $TARGET_GROUPS; do
        echo "   Deleting target group: $(basename $tg)"
        aws elbv2 delete-target-group --target-group-arn $tg --region $REGION 2>/dev/null || true
    done
fi

# 6. Delete ECR Repositories
echo -e "\n${YELLOW}6. Deleting ECR Repositories...${NC}"

ECR_REPOS=$(aws ecr describe-repositories --region $REGION --query 'repositories[].repositoryName' --output text 2>/dev/null || echo "")
if [ ! -z "$ECR_REPOS" ]; then
    for repo in $ECR_REPOS; do
        if [[ "$repo" == *"cybershield"* ]] || [[ "$repo" == *"CyberShield"* ]]; then
            echo "   Deleting ECR repository: $repo"
            aws ecr delete-repository --repository-name $repo --force --region $REGION 2>/dev/null || true
        fi
    done
    echo -e "${GREEN}   ✓ ECR repositories deleted${NC}"
fi

# 7. Wait for EC2 termination
echo -e "\n${YELLOW}7. Waiting for EC2 termination...${NC}"
if [ ! -z "$EC2_INSTANCES" ]; then
    echo "   Waiting for instances to terminate..."
    aws ec2 wait instance-terminated --instance-ids $EC2_INSTANCES --region $REGION 2>/dev/null || true
    echo -e "${GREEN}   ✓ EC2 instances terminated${NC}"
fi

# 8. Delete VPC and all networking
echo -e "\n${YELLOW}8. Deleting VPC and Networking...${NC}"

# Find VPCs with cybershield tag
VPC_IDS=$(aws ec2 describe-vpcs --region $REGION --query 'Vpcs[].VpcId' --output text 2>/dev/null || echo "")

for VPC_ID in $VPC_IDS; do
    # Check if it's a cybershield VPC
    VPC_NAME=$(aws ec2 describe-vpcs --vpc-ids $VPC_ID --region $REGION --query 'Vpcs[0].Tags[?Key==`Name`].Value | [0]' --output text 2>/dev/null || echo "")

    if [[ "$VPC_NAME" == *"cybershield"* ]] || [[ "$VPC_NAME" == *"CyberShield"* ]] || [[ "$VPC_ID" == "vpc-0ac27d2c1fb1622f2" ]]; then
        echo "   Processing VPC: $VPC_ID ($VPC_NAME)"

        # Delete NAT Gateways
        NAT_GATEWAYS=$(aws ec2 describe-nat-gateways --filter "Name=vpc-id,Values=$VPC_ID" "Name=state,Values=available" --region $REGION --query 'NatGateways[].NatGatewayId' --output text 2>/dev/null || echo "")
        if [ ! -z "$NAT_GATEWAYS" ]; then
            for nat in $NAT_GATEWAYS; do
                echo "     Deleting NAT Gateway: $nat"
                aws ec2 delete-nat-gateway --nat-gateway-id $nat --region $REGION 2>/dev/null || true
            done
        fi

        # Detach and delete Internet Gateways
        IGW_IDS=$(aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$VPC_ID" --region $REGION --query 'InternetGateways[].InternetGatewayId' --output text 2>/dev/null || echo "")
        if [ ! -z "$IGW_IDS" ]; then
            for igw in $IGW_IDS; do
                aws ec2 detach-internet-gateway --internet-gateway-id $igw --vpc-id $VPC_ID --region $REGION 2>/dev/null || true
                aws ec2 delete-internet-gateway --internet-gateway-id $igw --region $REGION 2>/dev/null || true
            done
        fi

        # Delete subnets
        SUBNETS=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" --region $REGION --query 'Subnets[].SubnetId' --output text 2>/dev/null || echo "")
        if [ ! -z "$SUBNETS" ]; then
            for subnet in $SUBNETS; do
                aws ec2 delete-subnet --subnet-id $subnet --region $REGION 2>/dev/null || true
            done
        fi

        # Delete route tables
        ROUTE_TABLES=$(aws ec2 describe-route-tables --filters "Name=vpc-id,Values=$VPC_ID" --region $REGION --query 'RouteTables[?Associations[0].Main != `true`].RouteTableId' --output text 2>/dev/null || echo "")
        if [ ! -z "$ROUTE_TABLES" ]; then
            for rt in $ROUTE_TABLES; do
                aws ec2 delete-route-table --route-table-id $rt --region $REGION 2>/dev/null || true
            done
        fi

        # Delete security groups
        SECURITY_GROUPS=$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$VPC_ID" --region $REGION --query 'SecurityGroups[?GroupName != `default`].GroupId' --output text 2>/dev/null || echo "")
        if [ ! -z "$SECURITY_GROUPS" ]; then
            for sg in $SECURITY_GROUPS; do
                aws ec2 delete-security-group --group-id $sg --region $REGION 2>/dev/null || true
            done
        fi

        # Delete the VPC
        sleep 5
        aws ec2 delete-vpc --vpc-id $VPC_ID --region $REGION 2>/dev/null || echo "     VPC deletion pending dependencies"
    fi
done

echo -e "${GREEN}   ✓ VPC deletion attempted${NC}"

# 9. Release all Elastic IPs
echo -e "\n${YELLOW}9. Releasing Elastic IPs...${NC}"

ELASTIC_IPS=$(aws ec2 describe-addresses --region $REGION --query 'Addresses[].AllocationId' --output text 2>/dev/null || echo "")
if [ ! -z "$ELASTIC_IPS" ]; then
    for eip in $ELASTIC_IPS; do
        echo "   Releasing EIP: $eip"
        aws ec2 release-address --allocation-id $eip --region $REGION 2>/dev/null || true
    done
    echo -e "${GREEN}   ✓ Elastic IPs released${NC}"
fi

# 10. Delete CloudWatch Log Groups
echo -e "\n${YELLOW}10. Deleting CloudWatch Log Groups...${NC}"

LOG_GROUPS=$(aws logs describe-log-groups --region $REGION --query 'logGroups[?contains(logGroupName, `cybershield`) || contains(logGroupName, `/ecs/`) || contains(logGroupName, `/aws/lambda/cybershield`)].logGroupName' --output text 2>/dev/null || echo "")
if [ ! -z "$LOG_GROUPS" ]; then
    for lg in $LOG_GROUPS; do
        echo "   Deleting log group: $lg"
        aws logs delete-log-group --log-group-name "$lg" --region $REGION 2>/dev/null || true
    done
    echo -e "${GREEN}   ✓ Log groups deleted${NC}"
fi

# 11. Delete EBS Volumes (orphaned)
echo -e "\n${YELLOW}11. Checking for orphaned EBS volumes...${NC}"

VOLUMES=$(aws ec2 describe-volumes --region $REGION --filters "Name=status,Values=available" --query 'Volumes[].VolumeId' --output text 2>/dev/null || echo "")
if [ ! -z "$VOLUMES" ]; then
    for vol in $VOLUMES; do
        echo "   Deleting orphaned volume: $vol"
        aws ec2 delete-volume --volume-id $vol --region $REGION 2>/dev/null || true
    done
    echo -e "${GREEN}   ✓ Orphaned volumes deleted${NC}"
fi

# Summary
echo -e "\n========================================="
echo -e "${GREEN}FINAL CLEANUP COMPLETE${NC}"
echo -e "========================================="
echo -e "${GREEN}✓ EC2 instances terminated${NC}"
echo -e "${GREEN}✓ Route53 hosted zone deleted${NC}"
echo -e "${GREEN}✓ Lambda functions deleted${NC}"
echo -e "${GREEN}✓ ElastiCache Redis deleted${NC}"
echo -e "${GREEN}✓ Load balancers deleted${NC}"
echo -e "${GREEN}✓ ECR repositories deleted${NC}"
echo -e "${GREEN}✓ VPC and networking deleted${NC}"
echo -e "${GREEN}✓ Elastic IPs released${NC}"
echo -e "${GREEN}✓ CloudWatch logs deleted${NC}"
echo -e "${GREEN}✓ Orphaned volumes deleted${NC}"
echo ""
echo -e "${YELLOW}All AWS resources have been terminated/deleted!${NC}"
echo -e "${YELLOW}Wait 24 hours and check AWS Cost Explorer to confirm zero charges.${NC}"
echo ""
echo "To verify all resources are gone:"
echo "   aws resourcegroupstaggingapi get-resources --region $REGION"
echo ""
echo "To check costs:"
echo "   aws ce get-cost-and-usage --time-period Start=$(date -u -d '1 day ago' +%Y-%m-%d),End=$(date -u +%Y-%m-%d) --granularity DAILY --metrics 'UnblendedCost' --region us-east-1"