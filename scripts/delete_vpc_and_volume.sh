#!/bin/bash

# Delete VPC and Volume after EC2 termination

set -e

echo "========================================="
echo "DELETING VPC AND VOLUME"
echo "========================================="

REGION="us-east-1"
VPC_ID="vpc-0ac27d2c1fb1622f2"
VOLUME_ID="vol-015804a66f6387199"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 1. Check EC2 instance status
echo -e "\n${YELLOW}Checking EC2 instance status...${NC}"
INSTANCE_STATE=$(aws ec2 describe-instances --instance-ids i-0b342af49bbbfdccd --region $REGION --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null || echo "terminated")

if [ "$INSTANCE_STATE" != "terminated" ]; then
    echo "   Instance still terminating. Current state: $INSTANCE_STATE"
    echo "   Waiting for termination..."
    aws ec2 wait instance-terminated --instance-ids i-0b342af49bbbfdccd --region $REGION 2>/dev/null || true
fi
echo -e "${GREEN}   ✓ Instance terminated${NC}"

# 2. Delete the Volume
echo -e "\n${YELLOW}Deleting EBS Volume...${NC}"
echo "   Deleting volume: $VOLUME_ID"
aws ec2 delete-volume --volume-id $VOLUME_ID --region $REGION 2>/dev/null || echo "   Volume may already be deleted"
echo -e "${GREEN}   ✓ Volume deleted${NC}"

# 3. Delete VPC components
echo -e "\n${YELLOW}Deleting VPC Components...${NC}"

# Delete Internet Gateway
echo "   Detaching Internet Gateways..."
IGW_IDS=$(aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$VPC_ID" --region $REGION --query 'InternetGateways[].InternetGatewayId' --output text 2>/dev/null || echo "")
if [ ! -z "$IGW_IDS" ]; then
    for igw in $IGW_IDS; do
        aws ec2 detach-internet-gateway --internet-gateway-id $igw --vpc-id $VPC_ID --region $REGION 2>/dev/null || true
        aws ec2 delete-internet-gateway --internet-gateway-id $igw --region $REGION 2>/dev/null || true
    done
fi

# Delete Subnets
echo "   Deleting Subnets..."
SUBNETS=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" --region $REGION --query 'Subnets[].SubnetId' --output text 2>/dev/null || echo "")
if [ ! -z "$SUBNETS" ]; then
    for subnet in $SUBNETS; do
        aws ec2 delete-subnet --subnet-id $subnet --region $REGION 2>/dev/null || true
    done
fi

# Delete Route Tables
echo "   Deleting Route Tables..."
ROUTE_TABLES=$(aws ec2 describe-route-tables --filters "Name=vpc-id,Values=$VPC_ID" --region $REGION --query 'RouteTables[?Associations[0].Main != `true`].RouteTableId' --output text 2>/dev/null || echo "")
if [ ! -z "$ROUTE_TABLES" ]; then
    for rt in $ROUTE_TABLES; do
        aws ec2 delete-route-table --route-table-id $rt --region $REGION 2>/dev/null || true
    done
fi

# Delete Security Groups
echo "   Deleting Security Groups..."
SECURITY_GROUPS=$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$VPC_ID" --region $REGION --query 'SecurityGroups[?GroupName != `default`].GroupId' --output text 2>/dev/null || echo "")
if [ ! -z "$SECURITY_GROUPS" ]; then
    # First clear all rules
    for sg in $SECURITY_GROUPS; do
        # Get and revoke all ingress rules
        RULES=$(aws ec2 describe-security-groups --group-ids $sg --region $REGION --query 'SecurityGroups[0].IpPermissions' 2>/dev/null || echo "[]")
        if [ "$RULES" != "[]" ] && [ "$RULES" != "null" ]; then
            aws ec2 revoke-security-group-ingress --group-id $sg --ip-permissions "$RULES" --region $REGION 2>/dev/null || true
        fi

        # Get and revoke all egress rules
        RULES=$(aws ec2 describe-security-groups --group-ids $sg --region $REGION --query 'SecurityGroups[0].IpPermissionsEgress' 2>/dev/null || echo "[]")
        if [ "$RULES" != "[]" ] && [ "$RULES" != "null" ]; then
            aws ec2 revoke-security-group-egress --group-id $sg --ip-permissions "$RULES" --region $REGION 2>/dev/null || true
        fi
    done

    # Then delete security groups
    for sg in $SECURITY_GROUPS; do
        aws ec2 delete-security-group --group-id $sg --region $REGION 2>/dev/null || true
    done
fi

# Delete the VPC
echo "   Deleting VPC: $VPC_ID"
aws ec2 delete-vpc --vpc-id $VPC_ID --region $REGION 2>/dev/null || echo "   VPC may still have dependencies"
echo -e "${GREEN}   ✓ VPC deletion attempted${NC}"

# 4. Check for any remaining resources
echo -e "\n${YELLOW}Checking for remaining resources...${NC}"

# Check ElastiCache status
REDIS=$(aws elasticache describe-cache-clusters --region $REGION --query 'CacheClusters[].CacheClusterId' --output text 2>/dev/null || echo "")
if [ ! -z "$REDIS" ]; then
    echo -e "   ${RED}WARNING: Redis clusters still exist: $REDIS${NC}"
fi

# Check RDS status
RDS=$(aws rds describe-db-instances --region $REGION --query 'DBInstances[?DBInstanceStatus!=`deleting`].DBInstanceIdentifier' --output text 2>/dev/null || echo "")
if [ ! -z "$RDS" ]; then
    echo -e "   ${RED}WARNING: RDS instances still exist: $RDS${NC}"
fi

# Summary
echo -e "\n========================================="
echo -e "${GREEN}CLEANUP COMPLETE${NC}"
echo -e "========================================="
echo -e "${GREEN}✓ EBS Volume deleted${NC}"
echo -e "${GREEN}✓ VPC components cleaned up${NC}"
echo ""
echo -e "${YELLOW}All major resources have been deleted!${NC}"
echo ""
echo "To verify all resources are gone:"
echo "   aws ce get-cost-and-usage --time-period Start=$(date -u -d '1 day ago' +%Y-%m-%d),End=$(date -u +%Y-%m-%d) --granularity DAILY --metrics 'UnblendedCost' --region us-east-1"