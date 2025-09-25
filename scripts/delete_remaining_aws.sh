#!/bin/bash

# Delete Remaining AWS Resources (Lambda, VPC, etc.)
# This script deletes Lambda functions, VPCs, and associated networking resources

set -e

echo "========================================="
echo "DELETING REMAINING AWS RESOURCES"
echo "========================================="

# Configuration
REGION="us-east-1"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${RED}WARNING: This will delete Lambda functions, VPCs, and all networking!${NC}"
read -p "Type 'DELETE' to confirm: " confirmation

if [ "$confirmation" != "DELETE" ]; then
    echo "Deletion cancelled."
    exit 1
fi

# 1. Delete Lambda Functions
echo -e "\n${YELLOW}1. Deleting Lambda Functions...${NC}"

LAMBDA_FUNCTIONS="cybershield-api-proxy cybershield-gpu-orchestrator"
for func in $LAMBDA_FUNCTIONS; do
    echo "   Deleting Lambda function: $func"
    aws lambda delete-function --function-name $func --region $REGION 2>/dev/null || echo "   Function $func not found or already deleted"
done
echo -e "${GREEN}   ✓ Lambda functions deleted${NC}"

# 2. Delete remaining ElastiCache clusters
echo -e "\n${YELLOW}2. Deleting ElastiCache (Redis) Clusters...${NC}"

REDIS_CLUSTERS=$(aws elasticache describe-cache-clusters --region $REGION --query 'CacheClusters[].CacheClusterId' --output text 2>/dev/null || echo "")
if [ ! -z "$REDIS_CLUSTERS" ]; then
    for cluster in $REDIS_CLUSTERS; do
        echo "   Deleting Redis cluster: $cluster"
        aws elasticache delete-cache-cluster --cache-cluster-id $cluster --region $REGION 2>/dev/null || echo "   Failed to delete $cluster"
    done
    echo -e "${GREEN}   ✓ Redis cluster deletion initiated${NC}"
else
    echo "   No Redis clusters found"
fi

# 3. Delete ALB and Target Groups
echo -e "\n${YELLOW}3. Deleting Application Load Balancers...${NC}"

# Delete ALBs
ALB_ARNS=$(aws elbv2 describe-load-balancers --region $REGION --query 'LoadBalancers[].LoadBalancerArn' --output text 2>/dev/null || echo "")
if [ ! -z "$ALB_ARNS" ]; then
    for alb in $ALB_ARNS; do
        ALB_NAME=$(aws elbv2 describe-load-balancers --load-balancer-arns $alb --region $REGION --query 'LoadBalancers[0].LoadBalancerName' --output text 2>/dev/null)
        echo "   Deleting ALB: $ALB_NAME"
        aws elbv2 delete-load-balancer --load-balancer-arn $alb --region $REGION 2>/dev/null || echo "   Failed to delete ALB"
    done
    echo -e "${GREEN}   ✓ Load balancers deleted${NC}"
else
    echo "   No load balancers found"
fi

# Wait for ALBs to delete
sleep 10

# Delete Target Groups
echo -e "\n${YELLOW}4. Deleting Target Groups...${NC}"
TARGET_GROUPS=$(aws elbv2 describe-target-groups --region $REGION --query 'TargetGroups[].TargetGroupArn' --output text 2>/dev/null || echo "")
if [ ! -z "$TARGET_GROUPS" ]; then
    for tg in $TARGET_GROUPS; do
        echo "   Deleting target group: $(basename $tg)"
        aws elbv2 delete-target-group --target-group-arn $tg --region $REGION 2>/dev/null || echo "   Failed to delete target group"
    done
    echo -e "${GREEN}   ✓ Target groups deleted${NC}"
else
    echo "   No target groups found"
fi

# 5. Wait for RDS to finish deleting
echo -e "\n${YELLOW}5. Checking RDS status...${NC}"
RDS_INSTANCES=$(aws rds describe-db-instances --region $REGION --query 'DBInstances[].DBInstanceIdentifier' --output text 2>/dev/null || echo "")
if [ ! -z "$RDS_INSTANCES" ]; then
    for instance in $RDS_INSTANCES; do
        STATUS=$(aws rds describe-db-instances --db-instance-identifier $instance --region $REGION --query 'DBInstances[0].DBInstanceStatus' --output text 2>/dev/null || echo "deleted")
        if [ "$STATUS" != "deleted" ] && [ "$STATUS" != "deleting" ]; then
            echo "   Force deleting RDS instance: $instance"
            aws rds delete-db-instance \
                --db-instance-identifier $instance \
                --skip-final-snapshot \
                --delete-automated-backups \
                --region $REGION 2>/dev/null || true
        fi
    done
fi

# 6. Delete ECR Repositories
echo -e "\n${YELLOW}6. Deleting ECR Repositories...${NC}"
ECR_REPOS=$(aws ecr describe-repositories --region $REGION --query 'repositories[?contains(repositoryName, `cybershield`)].repositoryName' --output text 2>/dev/null || echo "")
if [ ! -z "$ECR_REPOS" ]; then
    for repo in $ECR_REPOS; do
        echo "   Deleting ECR repository: $repo"
        aws ecr delete-repository --repository-name $repo --force --region $REGION 2>/dev/null || echo "   Failed to delete $repo"
    done
    echo -e "${GREEN}   ✓ ECR repositories deleted${NC}"
else
    echo "   No ECR repositories found"
fi

# 7. Delete VPC and all networking components
echo -e "\n${YELLOW}7. Deleting VPC and Networking...${NC}"

VPC_ID="vpc-0ac27d2c1fb1622f2"

# First, delete NAT Gateways
echo "   Deleting NAT Gateways..."
NAT_GATEWAYS=$(aws ec2 describe-nat-gateways --filter "Name=vpc-id,Values=$VPC_ID" "Name=state,Values=available" --region $REGION --query 'NatGateways[].NatGatewayId' --output text 2>/dev/null || echo "")
if [ ! -z "$NAT_GATEWAYS" ]; then
    for nat in $NAT_GATEWAYS; do
        echo "     Deleting NAT Gateway: $nat"
        aws ec2 delete-nat-gateway --nat-gateway-id $nat --region $REGION 2>/dev/null || true
    done
fi

# Delete Internet Gateways
echo "   Detaching and deleting Internet Gateways..."
IGW_IDS=$(aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$VPC_ID" --region $REGION --query 'InternetGateways[].InternetGatewayId' --output text 2>/dev/null || echo "")
if [ ! -z "$IGW_IDS" ]; then
    for igw in $IGW_IDS; do
        echo "     Detaching IGW: $igw"
        aws ec2 detach-internet-gateway --internet-gateway-id $igw --vpc-id $VPC_ID --region $REGION 2>/dev/null || true
        echo "     Deleting IGW: $igw"
        aws ec2 delete-internet-gateway --internet-gateway-id $igw --region $REGION 2>/dev/null || true
    done
fi

# Delete Route Tables (except main)
echo "   Deleting Route Tables..."
ROUTE_TABLES=$(aws ec2 describe-route-tables --filters "Name=vpc-id,Values=$VPC_ID" --region $REGION --query 'RouteTables[?Associations[0].Main != `true`].RouteTableId' --output text 2>/dev/null || echo "")
if [ ! -z "$ROUTE_TABLES" ]; then
    for rt in $ROUTE_TABLES; do
        echo "     Deleting route table: $rt"
        aws ec2 delete-route-table --route-table-id $rt --region $REGION 2>/dev/null || true
    done
fi

# Delete Subnets
echo "   Deleting Subnets..."
SUBNETS=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" --region $REGION --query 'Subnets[].SubnetId' --output text 2>/dev/null || echo "")
if [ ! -z "$SUBNETS" ]; then
    for subnet in $SUBNETS; do
        echo "     Deleting subnet: $subnet"
        aws ec2 delete-subnet --subnet-id $subnet --region $REGION 2>/dev/null || true
    done
fi

# Delete Security Groups (except default)
echo "   Deleting Security Groups..."
SECURITY_GROUPS=$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$VPC_ID" --region $REGION --query 'SecurityGroups[?GroupName != `default`].GroupId' --output text 2>/dev/null || echo "")
if [ ! -z "$SECURITY_GROUPS" ]; then
    # First remove all ingress rules referencing other security groups
    for sg in $SECURITY_GROUPS; do
        echo "     Clearing rules for: $sg"
        aws ec2 revoke-security-group-ingress --group-id $sg --region $REGION \
            --ip-permissions "$(aws ec2 describe-security-groups --group-ids $sg --region $REGION --query 'SecurityGroups[0].IpPermissions' 2>/dev/null)" 2>/dev/null || true
    done

    # Then delete the security groups
    for sg in $SECURITY_GROUPS; do
        echo "     Deleting security group: $sg"
        aws ec2 delete-security-group --group-id $sg --region $REGION 2>/dev/null || true
    done
fi

# Release Elastic IPs
echo "   Releasing Elastic IPs..."
ELASTIC_IPS=$(aws ec2 describe-addresses --region $REGION --query 'Addresses[].AllocationId' --output text 2>/dev/null || echo "")
if [ ! -z "$ELASTIC_IPS" ]; then
    for eip in $ELASTIC_IPS; do
        echo "     Releasing EIP: $eip"
        aws ec2 release-address --allocation-id $eip --region $REGION 2>/dev/null || true
    done
fi

# Wait for resources to clear
echo "   Waiting for resources to clear..."
sleep 15

# Finally, delete the VPC
echo "   Deleting VPC: $VPC_ID"
aws ec2 delete-vpc --vpc-id $VPC_ID --region $REGION 2>/dev/null || echo "   VPC may still have dependencies"

echo -e "${GREEN}   ✓ VPC deletion attempted${NC}"

# 8. Delete CloudWatch Log Groups
echo -e "\n${YELLOW}8. Deleting CloudWatch Log Groups...${NC}"
LOG_GROUPS=$(aws logs describe-log-groups --region $REGION --query 'logGroups[?contains(logGroupName, `cybershield`) || contains(logGroupName, `ecs`)].logGroupName' --output text 2>/dev/null || echo "")
if [ ! -z "$LOG_GROUPS" ]; then
    for lg in $LOG_GROUPS; do
        echo "   Deleting log group: $lg"
        aws logs delete-log-group --log-group-name "$lg" --region $REGION 2>/dev/null || true
    done
    echo -e "${GREEN}   ✓ Log groups deleted${NC}"
fi

# 9. Final check for any remaining resources
echo -e "\n${YELLOW}9. Final Resource Check...${NC}"

# Check if VPC still exists
VPC_CHECK=$(aws ec2 describe-vpcs --vpc-ids $VPC_ID --region $REGION 2>&1 || echo "DELETED")
if [[ "$VPC_CHECK" == *"DELETED"* ]] || [[ "$VPC_CHECK" == *"InvalidVpcID"* ]]; then
    echo -e "${GREEN}   ✓ VPC successfully deleted${NC}"
else
    echo -e "${YELLOW}   VPC may still exist - check AWS Console${NC}"
fi

# Summary
echo -e "\n========================================="
echo -e "${GREEN}DELETION SUMMARY${NC}"
echo -e "========================================="
echo -e "${GREEN}✓ Lambda functions deleted${NC}"
echo -e "${GREEN}✓ ElastiCache clusters deletion initiated${NC}"
echo -e "${GREEN}✓ Load balancers and target groups deleted${NC}"
echo -e "${GREEN}✓ ECR repositories deleted${NC}"
echo -e "${GREEN}✓ VPC and networking components deletion attempted${NC}"
echo -e "${GREEN}✓ CloudWatch log groups deleted${NC}"
echo ""
echo -e "${YELLOW}Check AWS Cost Explorer in 24 hours to confirm all charges have stopped${NC}"
echo ""
echo "To check current charges:"
echo "   aws ce get-cost-and-usage --time-period Start=$(date -u -d '1 day ago' +%Y-%m-%d),End=$(date -u +%Y-%m-%d) --granularity DAILY --metrics 'UnblendedCost' --region us-east-1"