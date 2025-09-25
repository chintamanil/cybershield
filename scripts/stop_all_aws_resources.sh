#!/bin/bash

# Stop All AWS Resources Script
# This script stops all running AWS resources to avoid charges

set -e

echo "========================================="
echo "STOPPING ALL AWS RESOURCES"
echo "========================================="

# Configuration
REGION="us-east-1"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting resource shutdown process...${NC}"

# 1. Stop ECS Services
echo -e "\n${YELLOW}1. Stopping ECS Services...${NC}"

# Stop cybershield-prod services
echo "   Stopping cybershield-prod-backend service..."
aws ecs update-service \
    --cluster cybershield-prod \
    --service cybershield-prod-backend \
    --desired-count 0 \
    --region $REGION >/dev/null 2>&1 || echo "   Service may not exist or already stopped"

echo "   Stopping cybershield-prod-frontend service..."
aws ecs update-service \
    --cluster cybershield-prod \
    --service cybershield-prod-frontend \
    --desired-count 0 \
    --region $REGION >/dev/null 2>&1 || echo "   Service may not exist or already stopped"

# Stop cybershield-gpu service
echo "   Stopping cybershield-gpu-service..."
aws ecs update-service \
    --cluster cybershield-gpu \
    --service cybershield-gpu-service \
    --desired-count 0 \
    --region $REGION >/dev/null 2>&1 || echo "   Service may not exist or already stopped"

echo -e "${GREEN}   ✓ ECS services set to 0 desired count${NC}"

# 2. Stop all running tasks
echo -e "\n${YELLOW}2. Stopping all running ECS tasks...${NC}"

# Stop tasks in cybershield-prod cluster
echo "   Stopping tasks in cybershield-prod cluster..."
TASKS=$(aws ecs list-tasks --cluster cybershield-prod --region $REGION --query 'taskArns[]' --output text 2>/dev/null)
if [ ! -z "$TASKS" ]; then
    for task in $TASKS; do
        echo "   Stopping task: $(basename $task)"
        aws ecs stop-task --cluster cybershield-prod --task $task --region $REGION >/dev/null 2>&1
    done
else
    echo "   No running tasks found in cybershield-prod"
fi

# Stop tasks in cybershield-gpu cluster
echo "   Stopping tasks in cybershield-gpu cluster..."
TASKS=$(aws ecs list-tasks --cluster cybershield-gpu --region $REGION --query 'taskArns[]' --output text 2>/dev/null)
if [ ! -z "$TASKS" ]; then
    for task in $TASKS; do
        echo "   Stopping task: $(basename $task)"
        aws ecs stop-task --cluster cybershield-gpu --task $task --region $REGION >/dev/null 2>&1
    done
else
    echo "   No running tasks found in cybershield-gpu"
fi

echo -e "${GREEN}   ✓ All ECS tasks stopped${NC}"

# 3. Stop RDS instances
echo -e "\n${YELLOW}3. Stopping RDS instances...${NC}"

# Get all RDS instances
RDS_INSTANCES=$(aws rds describe-db-instances --region $REGION --query 'DBInstances[?DBInstanceStatus==`available`].DBInstanceIdentifier' --output text 2>/dev/null)

if [ ! -z "$RDS_INSTANCES" ]; then
    for instance in $RDS_INSTANCES; do
        echo "   Stopping RDS instance: $instance"
        aws rds stop-db-instance --db-instance-identifier $instance --region $REGION >/dev/null 2>&1 || echo "   Failed to stop $instance (may already be stopped)"
    done
    echo -e "${GREEN}   ✓ RDS stop commands issued${NC}"
else
    echo "   No running RDS instances found"
fi

# 4. Check for ElastiCache clusters (Redis)
echo -e "\n${YELLOW}4. Checking ElastiCache (Redis) clusters...${NC}"
echo "   Note: ElastiCache clusters cannot be stopped, only deleted."
echo "   To delete, run: aws elasticache delete-cache-cluster --cache-cluster-id <cluster-id> --region $REGION"

REDIS_CLUSTERS=$(aws elasticache describe-cache-clusters --region $REGION --query 'CacheClusters[].CacheClusterId' --output text 2>/dev/null)
if [ ! -z "$REDIS_CLUSTERS" ]; then
    echo "   Found Redis clusters: $REDIS_CLUSTERS"
    echo -e "   ${RED}WARNING: Redis clusters are still running and incurring charges!${NC}"
else
    echo "   No Redis clusters found"
fi

# 5. Check for EFS file systems
echo -e "\n${YELLOW}5. Checking EFS file systems...${NC}"
echo "   Note: EFS charges for storage used. Consider deleting if not needed."

EFS_SYSTEMS=$(aws efs describe-file-systems --region $REGION --query 'FileSystems[].FileSystemId' --output text 2>/dev/null)
if [ ! -z "$EFS_SYSTEMS" ]; then
    echo "   Found EFS file systems: $EFS_SYSTEMS"
    echo -e "   ${RED}WARNING: EFS systems are still incurring storage charges!${NC}"
    echo "   To delete, first remove mount targets then delete the file system"
else
    echo "   No EFS file systems found"
fi

# 6. Check for Application Load Balancers
echo -e "\n${YELLOW}6. Checking Application Load Balancers...${NC}"

ALB_ARNS=$(aws elbv2 describe-load-balancers --region $REGION --query 'LoadBalancers[].LoadBalancerArn' --output text 2>/dev/null)
if [ ! -z "$ALB_ARNS" ]; then
    for alb in $ALB_ARNS; do
        ALB_NAME=$(aws elbv2 describe-load-balancers --load-balancer-arns $alb --region $REGION --query 'LoadBalancers[0].LoadBalancerName' --output text 2>/dev/null)
        echo "   Found ALB: $ALB_NAME"
    done
    echo -e "   ${RED}WARNING: Load balancers are still running and incurring charges!${NC}"
    echo "   To delete, run: aws elbv2 delete-load-balancer --load-balancer-arn <arn> --region $REGION"
else
    echo "   No load balancers found"
fi

# 7. Check for NAT Gateways (major cost factor)
echo -e "\n${YELLOW}7. Checking NAT Gateways...${NC}"

NAT_GATEWAYS=$(aws ec2 describe-nat-gateways --region $REGION --filter "Name=state,Values=available" --query 'NatGateways[].NatGatewayId' --output text 2>/dev/null)
if [ ! -z "$NAT_GATEWAYS" ]; then
    for nat in $NAT_GATEWAYS; do
        echo "   Found NAT Gateway: $nat"
    done
    echo -e "   ${RED}WARNING: NAT Gateways cost ~$45/month each and are still running!${NC}"
    echo "   To delete, run: aws ec2 delete-nat-gateway --nat-gateway-id <id> --region $REGION"
else
    echo "   No NAT Gateways found"
fi

# 8. Check for Elastic IPs
echo -e "\n${YELLOW}8. Checking Elastic IPs...${NC}"

ELASTIC_IPS=$(aws ec2 describe-addresses --region $REGION --query 'Addresses[?AssociationId==null].AllocationId' --output text 2>/dev/null)
if [ ! -z "$ELASTIC_IPS" ]; then
    echo "   Found unassociated Elastic IPs (charged when not in use): $ELASTIC_IPS"
    echo -e "   ${RED}WARNING: Unassociated Elastic IPs incur charges!${NC}"
    echo "   To release, run: aws ec2 release-address --allocation-id <id> --region $REGION"
else
    echo "   No unassociated Elastic IPs found"
fi

# 9. Check for Bedrock model invocations
echo -e "\n${YELLOW}9. Bedrock Status...${NC}"
echo "   Note: Bedrock charges per API call. No resources to stop."
echo "   Simply stop making API calls to avoid charges."

# 10. Summary
echo -e "\n========================================="
echo -e "${GREEN}SHUTDOWN SUMMARY${NC}"
echo -e "========================================="
echo -e "${GREEN}✓ ECS services set to 0 desired count${NC}"
echo -e "${GREEN}✓ All ECS tasks stopped${NC}"
echo -e "${GREEN}✓ RDS instances stop initiated (may take a few minutes)${NC}"
echo ""
echo -e "${YELLOW}Resources that need manual deletion to stop charges:${NC}"
echo "1. ElastiCache (Redis) clusters - Cannot be stopped, only deleted"
echo "2. EFS file systems - Charges for storage"
echo "3. Application Load Balancers - Running charges"
echo "4. NAT Gateways - Major cost factor (~$45/month each)"
echo "5. Elastic IPs (if unassociated) - Small hourly charge"
echo ""
echo -e "${YELLOW}To completely stop ALL charges, run:${NC}"
echo "   ./delete_all_aws_resources.sh"
echo ""
echo -e "${RED}WARNING: Deletion is permanent and cannot be undone!${NC}"