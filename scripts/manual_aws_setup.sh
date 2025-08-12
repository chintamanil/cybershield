#!/bin/bash
# Manual AWS Resource Creation for CyberShield (without CloudFormation)

set -e

echo "🔧 CyberShield Manual AWS Setup"
echo "==============================="
echo "Creating AWS resources manually using AWS CLI..."
echo ""

# Variables
PROJECT_NAME="cybershield"
REGION="us-east-1"
ACCOUNT_ID="840656856721"

# Create VPC
echo "🌐 Creating VPC..."
VPC_ID=$(aws ec2 create-vpc \
    --cidr-block 10.0.0.0/16 \
    --tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=${PROJECT_NAME}-vpc}]" \
    --query 'Vpc.VpcId' --output text)

echo "✅ VPC created: $VPC_ID"

# Enable DNS hostnames and resolution
aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-hostnames
aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-support

# Create Internet Gateway
echo "🌍 Creating Internet Gateway..."
IGW_ID=$(aws ec2 create-internet-gateway \
    --tag-specifications "ResourceType=internet-gateway,Tags=[{Key=Name,Value=${PROJECT_NAME}-igw}]" \
    --query 'InternetGateway.InternetGatewayId' --output text)

echo "✅ Internet Gateway created: $IGW_ID"

# Attach Internet Gateway to VPC
aws ec2 attach-internet-gateway --vpc-id $VPC_ID --internet-gateway-id $IGW_ID

# Get Availability Zones
AZ1=$(aws ec2 describe-availability-zones --query 'AvailabilityZones[0].ZoneName' --output text)
AZ2=$(aws ec2 describe-availability-zones --query 'AvailabilityZones[1].ZoneName' --output text)

echo "📍 Using Availability Zones: $AZ1, $AZ2"

# Create Public Subnets
echo "🏢 Creating Public Subnets..."
PUBLIC_SUBNET_1=$(aws ec2 create-subnet \
    --vpc-id $VPC_ID \
    --cidr-block 10.0.1.0/24 \
    --availability-zone $AZ1 \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${PROJECT_NAME}-public-1}]" \
    --query 'Subnet.SubnetId' --output text)

PUBLIC_SUBNET_2=$(aws ec2 create-subnet \
    --vpc-id $VPC_ID \
    --cidr-block 10.0.2.0/24 \
    --availability-zone $AZ2 \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${PROJECT_NAME}-public-2}]" \
    --query 'Subnet.SubnetId' --output text)

echo "✅ Public subnets: $PUBLIC_SUBNET_1, $PUBLIC_SUBNET_2"

# Create Private Subnets
echo "🔒 Creating Private Subnets..."
PRIVATE_SUBNET_1=$(aws ec2 create-subnet \
    --vpc-id $VPC_ID \
    --cidr-block 10.0.10.0/24 \
    --availability-zone $AZ1 \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${PROJECT_NAME}-private-1}]" \
    --query 'Subnet.SubnetId' --output text)

PRIVATE_SUBNET_2=$(aws ec2 create-subnet \
    --vpc-id $VPC_ID \
    --cidr-block 10.0.11.0/24 \
    --availability-zone $AZ2 \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${PROJECT_NAME}-private-2}]" \
    --query 'Subnet.SubnetId' --output text)

echo "✅ Private subnets: $PRIVATE_SUBNET_1, $PRIVATE_SUBNET_2"

# Create DB Subnets
echo "🗄️ Creating Database Subnets..."
DB_SUBNET_1=$(aws ec2 create-subnet \
    --vpc-id $VPC_ID \
    --cidr-block 10.0.20.0/24 \
    --availability-zone $AZ1 \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${PROJECT_NAME}-db-1}]" \
    --query 'Subnet.SubnetId' --output text)

DB_SUBNET_2=$(aws ec2 create-subnet \
    --vpc-id $VPC_ID \
    --cidr-block 10.0.21.0/24 \
    --availability-zone $AZ2 \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${PROJECT_NAME}-db-2}]" \
    --query 'Subnet.SubnetId' --output text)

echo "✅ Database subnets: $DB_SUBNET_1, $DB_SUBNET_2"

# Create NAT Gateway
echo "🔀 Creating NAT Gateway..."
# Allocate Elastic IP
NAT_EIP=$(aws ec2 allocate-address \
    --domain vpc \
    --tag-specifications "ResourceType=elastic-ip,Tags=[{Key=Name,Value=${PROJECT_NAME}-nat-eip}]" \
    --query 'AllocationId' --output text)

# Create NAT Gateway
NAT_GW=$(aws ec2 create-nat-gateway \
    --subnet-id $PUBLIC_SUBNET_1 \
    --allocation-id $NAT_EIP \
    --tag-specifications "ResourceType=nat-gateway,Tags=[{Key=Name,Value=${PROJECT_NAME}-nat}]" \
    --query 'NatGateway.NatGatewayId' --output text)

echo "✅ NAT Gateway created: $NAT_GW"
echo "⏳ Waiting for NAT Gateway to be available..."
aws ec2 wait nat-gateway-available --nat-gateway-ids $NAT_GW

# Create Route Tables
echo "🛣️ Creating Route Tables..."

# Public Route Table
PUBLIC_RT=$(aws ec2 create-route-table \
    --vpc-id $VPC_ID \
    --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=${PROJECT_NAME}-public-rt}]" \
    --query 'RouteTable.RouteTableId' --output text)

# Private Route Table
PRIVATE_RT=$(aws ec2 create-route-table \
    --vpc-id $VPC_ID \
    --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=${PROJECT_NAME}-private-rt}]" \
    --query 'RouteTable.RouteTableId' --output text)

echo "✅ Route tables: Public=$PUBLIC_RT, Private=$PRIVATE_RT"

# Add routes
aws ec2 create-route --route-table-id $PUBLIC_RT --destination-cidr-block 0.0.0.0/0 --gateway-id $IGW_ID
aws ec2 create-route --route-table-id $PRIVATE_RT --destination-cidr-block 0.0.0.0/0 --nat-gateway-id $NAT_GW

# Associate subnets with route tables
aws ec2 associate-route-table --subnet-id $PUBLIC_SUBNET_1 --route-table-id $PUBLIC_RT
aws ec2 associate-route-table --subnet-id $PUBLIC_SUBNET_2 --route-table-id $PUBLIC_RT
aws ec2 associate-route-table --subnet-id $PRIVATE_SUBNET_1 --route-table-id $PRIVATE_RT
aws ec2 associate-route-table --subnet-id $PRIVATE_SUBNET_2 --route-table-id $PRIVATE_RT

# Create Security Groups
echo "🔐 Creating Security Groups..."

# ALB Security Group
ALB_SG=$(aws ec2 create-security-group \
    --group-name "${PROJECT_NAME}-alb-sg" \
    --description "Security group for Application Load Balancer" \
    --vpc-id $VPC_ID \
    --tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=${PROJECT_NAME}-alb-sg}]" \
    --query 'GroupId' --output text)

# ECS Security Group
ECS_SG=$(aws ec2 create-security-group \
    --group-name "${PROJECT_NAME}-ecs-sg" \
    --description "Security group for ECS tasks" \
    --vpc-id $VPC_ID \
    --tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=${PROJECT_NAME}-ecs-sg}]" \
    --query 'GroupId' --output text)

# RDS Security Group
RDS_SG=$(aws ec2 create-security-group \
    --group-name "${PROJECT_NAME}-rds-sg" \
    --description "Security group for RDS database" \
    --vpc-id $VPC_ID \
    --tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=${PROJECT_NAME}-rds-sg}]" \
    --query 'GroupId' --output text)

# Redis Security Group
REDIS_SG=$(aws ec2 create-security-group \
    --group-name "${PROJECT_NAME}-redis-sg" \
    --description "Security group for Redis cluster" \
    --vpc-id $VPC_ID \
    --tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=${PROJECT_NAME}-redis-sg}]" \
    --query 'GroupId' --output text)

echo "✅ Security groups created"

# Configure Security Group Rules
echo "⚙️ Configuring Security Group Rules..."

# ALB - Allow HTTP/HTTPS from internet
aws ec2 authorize-security-group-ingress --group-id $ALB_SG --protocol tcp --port 80 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id $ALB_SG --protocol tcp --port 443 --cidr 0.0.0.0/0

# ECS - Allow traffic from ALB
aws ec2 authorize-security-group-ingress --group-id $ECS_SG --protocol tcp --port 8000 --source-group $ALB_SG

# RDS - Allow PostgreSQL from ECS
aws ec2 authorize-security-group-ingress --group-id $RDS_SG --protocol tcp --port 5432 --source-group $ECS_SG

# Redis - Allow Redis from ECS
aws ec2 authorize-security-group-ingress --group-id $REDIS_SG --protocol tcp --port 6379 --source-group $ECS_SG

# Create S3 Bucket
echo "🪣 Creating S3 Bucket..."
S3_BUCKET="${PROJECT_NAME}-data-${ACCOUNT_ID}-${REGION}"
aws s3 mb s3://$S3_BUCKET --region $REGION

echo "✅ S3 bucket created: $S3_BUCKET"

# Output summary
echo ""
echo "🎉 AWS Infrastructure Created Successfully!"
echo "=========================================="
echo ""
echo "📋 Resource Summary:"
echo "VPC ID: $VPC_ID"
echo "Public Subnets: $PUBLIC_SUBNET_1, $PUBLIC_SUBNET_2"
echo "Private Subnets: $PRIVATE_SUBNET_1, $PRIVATE_SUBNET_2"
echo "Database Subnets: $DB_SUBNET_1, $DB_SUBNET_2"
echo "Security Groups:"
echo "  - ALB: $ALB_SG"
echo "  - ECS: $ECS_SG"
echo "  - RDS: $RDS_SG"
echo "  - Redis: $REDIS_SG"
echo "S3 Bucket: $S3_BUCKET"
echo ""

# Save to environment file
echo "💾 Saving configuration to .env.aws..."
cat > ../.env.aws << EOF
# AWS Infrastructure Configuration
# Generated by manual_aws_setup.sh

AWS_ACCOUNT_ID=$ACCOUNT_ID
AWS_REGION=$REGION
VPC_ID=$VPC_ID
PUBLIC_SUBNET_1=$PUBLIC_SUBNET_1
PUBLIC_SUBNET_2=$PUBLIC_SUBNET_2
PRIVATE_SUBNET_1=$PRIVATE_SUBNET_1
PRIVATE_SUBNET_2=$PRIVATE_SUBNET_2
DB_SUBNET_1=$DB_SUBNET_1
DB_SUBNET_2=$DB_SUBNET_2
ALB_SECURITY_GROUP=$ALB_SG
ECS_SECURITY_GROUP=$ECS_SG
RDS_SECURITY_GROUP=$RDS_SG
REDIS_SECURITY_GROUP=$REDIS_SG
S3_BUCKET=$S3_BUCKET
EOF

echo "✅ Configuration saved to .env.aws"
echo ""
echo "🔄 Next Steps:"
echo "1. Create RDS database: ./scripts/create_rds.sh"
echo "2. Create Redis cluster: ./scripts/create_redis.sh"
echo "3. Create ECS cluster: ./scripts/create_ecs.sh"
echo "4. Deploy application: ./scripts/deploy_app.sh"