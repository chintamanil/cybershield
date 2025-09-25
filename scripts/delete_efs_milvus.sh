#!/bin/bash

# Delete EFS File System for Milvus Storage
# This script specifically targets the Milvus EFS storage

set -e

echo "========================================="
echo "DELETING EFS FILE SYSTEM (MILVUS STORAGE)"
echo "========================================="

# Configuration
REGION="us-east-1"
EFS_ID="fs-09343888fea9dc4a5"  # The specific EFS for Milvus

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Target EFS File System: $EFS_ID${NC}"
echo -e "${YELLOW}Name: cybershield-prod-milvus-storage${NC}"
echo ""

# Confirm the EFS exists and get its name
echo "Verifying EFS file system..."
EFS_NAME=$(aws efs describe-file-systems --file-system-id $EFS_ID --region $REGION --query 'FileSystems[0].Name' --output text 2>/dev/null || echo "NOT_FOUND")

if [ "$EFS_NAME" == "NOT_FOUND" ]; then
    echo -e "${RED}EFS file system $EFS_ID not found or already deleted${NC}"
    exit 0
fi

echo -e "${GREEN}Found EFS: $EFS_NAME${NC}"
echo ""

echo -e "${RED}WARNING: This will PERMANENTLY DELETE the Milvus data storage!${NC}"
echo -e "${RED}All Milvus vector data will be lost!${NC}"
read -p "Are you sure you want to delete this EFS? Type 'yes' to confirm: " confirmation

if [ "$confirmation" != "yes" ]; then
    echo "Deletion cancelled."
    exit 1
fi

echo ""
echo -e "${YELLOW}Starting EFS deletion process...${NC}"

# Step 1: Delete all mount targets first
echo -e "\n${YELLOW}Step 1: Deleting mount targets...${NC}"

MOUNT_TARGETS=$(aws efs describe-mount-targets --file-system-id $EFS_ID --region $REGION --query 'MountTargets[].MountTargetId' --output text 2>/dev/null || echo "")

if [ ! -z "$MOUNT_TARGETS" ]; then
    for mt in $MOUNT_TARGETS; do
        echo "   Deleting mount target: $mt"
        aws efs delete-mount-target --mount-target-id $mt --region $REGION 2>/dev/null || echo "   Failed to delete $mt (may already be deleted)"
    done
    echo -e "${GREEN}   ✓ Mount targets deletion initiated${NC}"

    # Wait for mount targets to be deleted
    echo "   Waiting for mount targets to be fully deleted..."
    sleep 10

    # Check if mount targets are deleted
    REMAINING_TARGETS=$(aws efs describe-mount-targets --file-system-id $EFS_ID --region $REGION --query 'MountTargets[].MountTargetId' --output text 2>/dev/null || echo "")

    if [ ! -z "$REMAINING_TARGETS" ]; then
        echo "   Waiting additional time for mount target deletion..."
        sleep 20
    fi
else
    echo "   No mount targets found"
fi

# Step 2: Delete the EFS file system
echo -e "\n${YELLOW}Step 2: Deleting EFS file system...${NC}"

echo "   Deleting EFS: $EFS_ID ($EFS_NAME)"
DELETE_RESULT=$(aws efs delete-file-system --file-system-id $EFS_ID --region $REGION 2>&1 || echo "FAILED")

if [[ "$DELETE_RESULT" == *"FAILED"* ]]; then
    echo -e "${RED}   Failed to delete EFS. It may still have active mount targets.${NC}"
    echo "   Attempting to force cleanup..."

    # Try one more time after waiting
    sleep 15
    aws efs delete-file-system --file-system-id $EFS_ID --region $REGION 2>/dev/null || {
        echo -e "${RED}   Could not delete EFS. Please check AWS Console.${NC}"
        echo "   Common issues:"
        echo "   - Mount targets still exist"
        echo "   - EFS is still mounted to EC2 instances"
        echo "   - Security group dependencies"
        exit 1
    }
fi

echo -e "${GREEN}   ✓ EFS file system deletion initiated${NC}"

# Step 3: Verify deletion
echo -e "\n${YELLOW}Step 3: Verifying deletion...${NC}"

sleep 5

# Check if EFS still exists
CHECK_EFS=$(aws efs describe-file-systems --file-system-id $EFS_ID --region $REGION 2>&1 || echo "DELETED")

if [[ "$CHECK_EFS" == *"DELETED"* ]] || [[ "$CHECK_EFS" == *"ResourceNotFoundException"* ]]; then
    echo -e "${GREEN}   ✓ EFS successfully deleted or deletion in progress${NC}"
else
    echo -e "${YELLOW}   EFS deletion initiated but may take a few minutes to complete${NC}"
fi

# Summary
echo -e "\n========================================="
echo -e "${GREEN}DELETION COMPLETE${NC}"
echo -e "========================================="
echo -e "${GREEN}✓ Mount targets deleted${NC}"
echo -e "${GREEN}✓ EFS file system $EFS_ID deletion initiated${NC}"
echo ""
echo -e "${YELLOW}Cost savings:${NC}"
echo "   - EFS storage costs: $0.30 per GB-month"
echo "   - This will stop all EFS-related charges for Milvus storage"
echo ""
echo -e "${YELLOW}Note:${NC}"
echo "   - Deletion may take 1-2 minutes to fully complete"
echo "   - Check AWS Console to confirm complete deletion"
echo "   - All Milvus vector data has been permanently deleted"