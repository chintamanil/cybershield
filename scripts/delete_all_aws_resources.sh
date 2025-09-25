#!/bin/bash

# Delete All AWS Resources Script
# WARNING: This will PERMANENTLY DELETE all AWS resources!

set -e

echo "========================================="
echo "DELETING ALL AWS RESOURCES - PERMANENT!"
echo "========================================="

# Configuration
REGION="us-east-1"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${RED}WARNING: This will PERMANENTLY DELETE all resources!${NC}"
echo -e "${RED}This action cannot be undone!${NC}"
read -p "Are you ABSOLUTELY SURE? Type 'DELETE ALL' to confirm: " confirmation

if [ "$confirmation" != "DELETE ALL" ]; then
    echo "Deletion cancelled."
    exit 1
fi

echo -e "\n${YELLOW}Starting complete resource deletion...${NC}"

# 1. Delete ECS Services
echo -e "\n${YELLOW}1. Deleting ECS Services...${NC}"

# Delete services in cybershield-prod
echo "   Deleting cybershield-prod services..."
aws ecs delete-service --cluster cybershield-prod --service cybershield-prod-backend --force --region $REGION >/dev/null 2>&1 || true
aws ecs delete-service --cluster cybershield-prod --service cybershield-prod-frontend --force --region $REGION >/dev/null 2>&1 || true

# Delete services in cybershield-gpu
echo "   Deleting cybershield-gpu services..."
aws ecs delete-service --cluster cybershield-gpu --service cybershield-gpu-service --force --region $REGION >/dev/null 2>&1 || true

echo -e "${GREEN}   ✓ ECS services deleted${NC}"

# 2. Delete ECS Clusters
echo -e "\n${YELLOW}2. Deleting ECS Clusters...${NC}"

echo "   Deleting cybershield-prod cluster..."
aws ecs delete-cluster --cluster cybershield-prod --region $REGION >/dev/null 2>&1 || true

echo "   Deleting cybershield-gpu cluster..."
aws ecs delete-cluster --cluster cybershield-gpu --region $REGION >/dev/null 2>&1 || true

echo -e "${GREEN}   ✓ ECS clusters deleted${NC}"

# 3. Delete Task Definitions (deregister)
echo -e "\n${YELLOW}3. Deregistering Task Definitions...${NC}"

TASK_DEFINITIONS=$(aws ecs list-task-definitions --region $REGION --query 'taskDefinitionArns[]' --output text 2>/dev/null | grep -E "cybershield|CyberShield" || true)
if [ ! -z "$TASK_DEFINITIONS" ]; then
    for td in $TASK_DEFINITIONS; do
        echo "   Deregistering: $(basename $td)"
        aws ecs deregister-task-definition --task-definition $td --region $REGION >/dev/null 2>&1 || true
    done
fi
echo -e "${GREEN}   ✓ Task definitions deregistered${NC}"

# 4. Delete RDS Instances
echo -e "\n${YELLOW}4. Deleting RDS Instances...${NC}"

RDS_INSTANCES=$(aws rds describe-db-instances --region $REGION --query 'DBInstances[].DBInstanceIdentifier' --output text 2>/dev/null | grep -i cybershield || true)
if [ ! -z "$RDS_INSTANCES" ]; then
    for instance in $RDS_INSTANCES; do
        echo "   Deleting RDS instance: $instance"
        aws rds delete-db-instance \
            --db-instance-identifier $instance \
            --skip-final-snapshot \
            --delete-automated-backups \
            --region $REGION >/dev/null 2>&1 || true
    done
fi
echo -e "${GREEN}   ✓ RDS deletion initiated${NC}"

# 5. Delete ElastiCache Clusters
echo -e "\n${YELLOW}5. Deleting ElastiCache (Redis) Clusters...${NC}"

REDIS_CLUSTERS=$(aws elasticache describe-cache-clusters --region $REGION --query 'CacheClusters[].CacheClusterId' --output text 2>/dev/null | grep -i cybershield || true)
if [ ! -z "$REDIS_CLUSTERS" ]; then
    for cluster in $REDIS_CLUSTERS; do
        echo "   Deleting Redis cluster: $cluster"
        aws elasticache delete-cache-cluster --cache-cluster-id $cluster --region $REGION >/dev/null 2>&1 || true
    done
fi
echo -e "${GREEN}   ✓ Redis clusters deletion initiated${NC}"

# 6. Delete Application Load Balancers
echo -e "\n${YELLOW}6. Deleting Application Load Balancers...${NC}"

ALB_ARNS=$(aws elbv2 describe-load-balancers --region $REGION --query 'LoadBalancers[?contains(LoadBalancerName, `cybershield`) || contains(LoadBalancerName, `CyberShield`)].LoadBalancerArn' --output text 2>/dev/null || true)
if [ ! -z "$ALB_ARNS" ]; then
    for alb in $ALB_ARNS; do
        echo "   Deleting ALB: $(basename $alb)"
        aws elbv2 delete-load-balancer --load-balancer-arn $alb --region $REGION >/dev/null 2>&1 || true
    done
fi
echo -e "${GREEN}   ✓ Load balancers deleted${NC}"

# 7. Delete Target Groups
echo -e "\n${YELLOW}7. Deleting Target Groups...${NC}"

TARGET_GROUPS=$(aws elbv2 describe-target-groups --region $REGION --query 'TargetGroups[?contains(TargetGroupName, `cybershield`) || contains(TargetGroupName, `CyberShield`)].TargetGroupArn' --output text 2>/dev/null || true)
if [ ! -z "$TARGET_GROUPS" ]; then
    for tg in $TARGET_GROUPS; do
        echo "   Deleting target group: $(basename $tg)"
        aws elbv2 delete-target-group --target-group-arn $tg --region $REGION >/dev/null 2>&1 || true
    done
fi
echo -e "${GREEN}   ✓ Target groups deleted${NC}"

# 8. Delete EFS File Systems
echo -e "\n${YELLOW}8. Deleting EFS File Systems...${NC}"

# First, get file systems with cybershield tag or name
EFS_SYSTEMS=$(aws efs describe-file-systems --region $REGION --query 'FileSystems[].FileSystemId' --output text 2>/dev/null || true)
if [ ! -z "$EFS_SYSTEMS" ]; then
    for fs in $EFS_SYSTEMS; do
        # Check if it's a cybershield system
        FS_NAME=$(aws efs describe-file-systems --file-system-id $fs --region $REGION --query 'FileSystems[0].Name' --output text 2>/dev/null || echo "")
        if [[ "$FS_NAME" == *"cybershield"* ]] || [[ "$FS_NAME" == *"CyberShield"* ]]; then
            echo "   Deleting EFS: $fs"

            # First delete mount targets
            MOUNT_TARGETS=$(aws efs describe-mount-targets --file-system-id $fs --region $REGION --query 'MountTargets[].MountTargetId' --output text 2>/dev/null || true)
            if [ ! -z "$MOUNT_TARGETS" ]; then
                for mt in $MOUNT_TARGETS; do
                    aws efs delete-mount-target --mount-target-id $mt --region $REGION >/dev/null 2>&1 || true
                done
            fi

            # Wait a moment for mount targets to delete
            sleep 5

            # Delete the file system
            aws efs delete-file-system --file-system-id $fs --region $REGION >/dev/null 2>&1 || true
        fi
    done
fi
echo -e "${GREEN}   ✓ EFS file systems deleted${NC}"

# 9. Delete NAT Gateways
echo -e "\n${YELLOW}9. Deleting NAT Gateways...${NC}"

NAT_GATEWAYS=$(aws ec2 describe-nat-gateways --region $REGION --filter "Name=state,Values=available,pending,deleting" --query 'NatGateways[].NatGatewayId' --output text 2>/dev/null || true)
if [ ! -z "$NAT_GATEWAYS" ]; then
    for nat in $NAT_GATEWAYS; do
        echo "   Deleting NAT Gateway: $nat"
        aws ec2 delete-nat-gateway --nat-gateway-id $nat --region $REGION >/dev/null 2>&1 || true
    done
fi
echo -e "${GREEN}   ✓ NAT Gateways deletion initiated${NC}"

# 10. Release Elastic IPs
echo -e "\n${YELLOW}10. Releasing Elastic IPs...${NC}"

ELASTIC_IPS=$(aws ec2 describe-addresses --region $REGION --query 'Addresses[].AllocationId' --output text 2>/dev/null || true)
if [ ! -z "$ELASTIC_IPS" ]; then
    for eip in $ELASTIC_IPS; do
        echo "   Releasing Elastic IP: $eip"
        aws ec2 release-address --allocation-id $eip --region $REGION >/dev/null 2>&1 || true
    done
fi
echo -e "${GREEN}   ✓ Elastic IPs released${NC}"

# 11. Delete ECR Repositories (optional - contains your Docker images)
echo -e "\n${YELLOW}11. ECR Repositories...${NC}"
echo "   Note: Skipping ECR deletion to preserve Docker images"
echo "   To delete manually: aws ecr delete-repository --repository-name <name> --force --region $REGION"

# 12. Delete Security Groups (after everything else)
echo -e "\n${YELLOW}12. Cleaning up Security Groups...${NC}"
echo "   Note: Default security groups cannot be deleted"
echo "   Custom security groups will be deleted after dependencies are removed"

# Wait for resources to start deleting
echo -e "\n${YELLOW}Waiting for resources to begin deletion...${NC}"
sleep 10

# Try to delete custom security groups
SECURITY_GROUPS=$(aws ec2 describe-security-groups --region $REGION --query 'SecurityGroups[?contains(GroupName, `cybershield`) || contains(GroupName, `CyberShield`)].GroupId' --output text 2>/dev/null || true)
if [ ! -z "$SECURITY_GROUPS" ]; then
    for sg in $SECURITY_GROUPS; do
        echo "   Attempting to delete security group: $sg"
        aws ec2 delete-security-group --group-id $sg --region $REGION >/dev/null 2>&1 || echo "     (May still have dependencies)"
    done
fi

# 13. Delete VPC (if dedicated)
echo -e "\n${YELLOW}13. VPC Cleanup...${NC}"
echo "   Note: VPC deletion requires all resources to be deleted first"
echo "   This may need to be done manually after all resources are fully deleted"

# Final Summary
echo -e "\n========================================="
echo -e "${GREEN}DELETION SUMMARY${NC}"
echo -e "========================================="
echo -e "${GREEN}✓ ECS services and clusters deleted${NC}"
echo -e "${GREEN}✓ RDS instances deletion initiated${NC}"
echo -e "${GREEN}✓ ElastiCache clusters deletion initiated${NC}"
echo -e "${GREEN}✓ Load balancers and target groups deleted${NC}"
echo -e "${GREEN}✓ EFS file systems deleted${NC}"
echo -e "${GREEN}✓ NAT Gateways deletion initiated${NC}"
echo -e "${GREEN}✓ Elastic IPs released${NC}"
echo ""
echo -e "${YELLOW}Note: Some resources may take 5-15 minutes to fully delete${NC}"
echo -e "${YELLOW}Check AWS Console to confirm all resources are deleted${NC}"
echo ""
echo -e "${GREEN}To verify deletion status, run:${NC}"
echo "   aws ce get-cost-and-usage --time-period Start=$(date -u -d '1 day ago' +%Y-%m-%d),End=$(date -u +%Y-%m-%d) --granularity DAILY --metrics 'UnblendedCost' --region us-east-1"