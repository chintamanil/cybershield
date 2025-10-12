# CyberShield AWS CDK Deployment Guide

Complete guide for deploying CyberShield infrastructure using AWS CDK.

## 🎯 Quick Start

```bash
# 1. Navigate to CDK directory
cd cdk

# 2. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env with your AWS account details

# 5. Bootstrap CDK (first time only)
cdk bootstrap aws://YOUR-ACCOUNT-ID/us-east-1

# 6. Deploy infrastructure
cdk deploy --all
```

## 📋 Prerequisites

### Required Software
- **Python 3.11+** - CDK application runtime
- **Node.js 18+** - AWS CDK CLI requirement
- **AWS CLI** - Configured with appropriate credentials
- **AWS CDK CLI** - Install globally: `npm install -g aws-cdk`

### AWS Requirements
- AWS account with administrator access
- AWS CLI configured: `aws configure`
- Sufficient service quotas for:
  - VPCs (1 per environment)
  - ECS Fargate tasks (varies by configuration)
  - RDS instances (1 per environment)
  - ElastiCache clusters (1 per environment)
  - Application Load Balancers (1 per environment)

### Domain Requirements (Optional)
- Registered domain name (e.g., cybershield-ai.com)
- Access to domain DNS settings
- If using external registrar, update nameservers to Route53

## 🔧 Detailed Setup

### 1. Environment Configuration

Create `.env` file from template:

```bash
cp .env.example .env
```

Required environment variables:

```bash
# AWS Configuration
AWS_ACCOUNT_ID=123456789012        # Your 12-digit AWS account ID
AWS_REGION=us-east-1               # AWS region for deployment

# Environment
ENVIRONMENT=dev                     # dev, staging, or prod

# Project Configuration
PROJECT_NAME=cybershield
DOMAIN_NAME=cybershield-ai.com     # Optional: your domain

# Network Configuration
VPC_CIDR=10.0.0.0/16
ENABLE_NAT_GATEWAY=false           # Set to false for cost savings in dev

# Database Configuration
DB_USERNAME=cybershield_admin
DB_NAME=cybershield

# Feature Flags
ENABLE_OPENSEARCH=false            # Disable for cost savings
ENABLE_EFS_FOR_MILVUS=true        # Enable for vector database persistence
ENABLE_SPOT_INSTANCES=true         # Enable for cost savings
```

### 2. CDK Bootstrap

Bootstrap your AWS environment (required once per account/region):

```bash
# Basic bootstrap
cdk bootstrap

# With specific account and region
cdk bootstrap aws://123456789012/us-east-1

# Multiple regions
cdk bootstrap \
  aws://123456789012/us-east-1 \
  aws://123456789012/us-west-2
```

### 3. Verify Configuration

Synthesize CloudFormation templates without deploying:

```bash
# Synthesize all stacks
cdk synth

# Synthesize specific stack
cdk synth CyberShieldDevNetworkStack

# View differences from deployed stacks
cdk diff
```

## 🚀 Deployment

### Development Environment

```bash
# Set environment
export ENVIRONMENT=dev

# Deploy all stacks
cdk deploy --all

# Deploy with automatic approval
cdk deploy --all --require-approval never

# Deploy specific stack
cdk deploy CyberShieldDevNetworkStack
```

### Staging Environment

```bash
# Set environment
export ENVIRONMENT=staging

# Deploy all stacks
cdk deploy --all

# Review changes before deployment
cdk diff
cdk deploy --all --require-approval always
```

### Production Environment

```bash
# Set environment
export ENVIRONMENT=prod

# Review changes carefully
cdk diff --all

# Deploy with explicit approval
cdk deploy --all --require-approval always

# Save outputs to file
cdk deploy --all --outputs-file outputs.json
```

## 📊 Stack Deployment Order

CDK automatically manages dependencies, but stacks deploy in this order:

1. **IAM Stack** → IAM roles and policies
2. **Network Stack** → VPC, subnets, security groups
3. **DNS Stack** → Route53, SSL certificates
4. **Storage Stack** → S3 buckets, EFS (optional)
5. **Data Stack** → RDS, ElastiCache, OpenSearch (optional)
6. **Load Balancer Stack** → ALB, target groups, listeners
7. **Compute Stack** → ECR, ECS cluster, services, auto-scaling
8. **Monitoring Stack** → CloudWatch alarms, dashboards
9. **Bedrock Stack** (optional) → AI/ML resources

## 🔍 Verification

### Check Stack Status

```bash
# List all stacks
cdk list

# View stack outputs
aws cloudformation describe-stacks \
  --stack-name CyberShieldDevComputeStack \
  --query 'Stacks[0].Outputs'
```

### Verify Resources

```bash
# Check ECS cluster
aws ecs describe-clusters \
  --clusters cybershield-dev

# Check load balancer
aws elbv2 describe-load-balancers \
  --names cybershield-dev-alb

# Check RDS instance
aws rds describe-db-instances \
  --db-instance-identifier cybershield-dev-postgres

# Test application endpoint
curl https://cybershield-ai.com/health
```

## 🐳 Container Deployment

### Build and Push Docker Images

```bash
# Authenticate with ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin \
  123456789012.dkr.ecr.us-east-1.amazonaws.com

# Build Docker image
cd ../  # Navigate to project root
docker build -f deployment/Dockerfile.aws \
  -t cybershield-backend:latest .

# Tag image
docker tag cybershield-backend:latest \
  123456789012.dkr.ecr.us-east-1.amazonaws.com/cybershield-dev:latest

# Push to ECR
docker push \
  123456789012.dkr.ecr.us-east-1.amazonaws.com/cybershield-dev:latest
```

### Update ECS Service

```bash
# Force new deployment (pulls latest image)
aws ecs update-service \
  --cluster cybershield-dev \
  --service cybershield-dev-backend \
  --force-new-deployment
```

## 🔄 Updates and Changes

### Update Stack Configuration

1. Modify configuration in `.env` or `config/environments.py`
2. Review changes: `cdk diff`
3. Deploy updates: `cdk deploy --all`

### Update Application Code

1. Build and push new Docker image to ECR
2. ECS will automatically deploy if using `:latest` tag
3. Or force new deployment: `aws ecs update-service --force-new-deployment`

### Rolling Updates

```bash
# Update specific stack
cdk deploy CyberShieldDevComputeStack

# Update multiple stacks
cdk deploy CyberShieldDevComputeStack CyberShieldDevMonitoringStack
```

## 🗑️ Cleanup and Teardown

### Destroy Individual Stack

```bash
# Destroy specific stack
cdk destroy CyberShieldDevMonitoringStack

# Destroy with force (skip confirmation)
cdk destroy CyberShieldDevMonitoringStack --force
```

### Destroy All Stacks

```bash
# Destroy all stacks (reverse dependency order)
cdk destroy --all

# Force destruction without confirmation
cdk destroy --all --force
```

### Manual Cleanup

Some resources may require manual deletion:

1. **ECR Images** - Delete manually if repository has images
2. **S3 Buckets** - Empty buckets before stack deletion
3. **RDS Snapshots** - Delete final snapshots if not needed
4. **EFS Data** - Backup data before deletion

```bash
# Empty S3 bucket
aws s3 rm s3://cybershield-dev-uploads --recursive

# Delete ECR images
aws ecr batch-delete-image \
  --repository-name cybershield-dev \
  --image-ids imageTag=latest
```

## 🐛 Troubleshooting

### Common Issues

#### 1. CDK Bootstrap Failed

```bash
# Error: Unable to resolve AWS account
# Solution: Configure AWS CLI
aws configure
aws sts get-caller-identity

# Error: Insufficient permissions
# Solution: Ensure IAM user has AdministratorAccess or required permissions
```

#### 2. Stack Deployment Failed

```bash
# View CloudFormation events
aws cloudformation describe-stack-events \
  --stack-name CyberShieldDevNetworkStack \
  --max-items 20

# Check CDK context
cdk context --clear  # Clear cached context
cdk synth  # Re-synthesize templates
```

#### 3. Resource Limit Exceeded

```bash
# Check service quotas
aws service-quotas list-service-quotas \
  --service-code ec2 \
  --query 'Quotas[?QuotaName==`VPCs per Region`]'

# Request quota increase via AWS Console:
# Service Quotas → AWS Services → Select service → Request quota increase
```

#### 4. SSL Certificate Validation Pending

```bash
# Certificate stuck in PENDING_VALIDATION
# Solution: Add DNS validation records to Route53

# If using external DNS:
# 1. Get validation records from ACM console
# 2. Add CNAME records to your DNS provider
# 3. Wait for validation (up to 30 minutes)
```

#### 5. ECS Task Failed to Start

```bash
# Check task logs
aws logs tail /ecs/cybershield-dev --follow

# Describe task
aws ecs describe-tasks \
  --cluster cybershield-dev \
  --tasks TASK_ID

# Common causes:
# - Image not found in ECR
# - Insufficient memory/CPU
# - Missing environment variables
# - IAM permissions issues
```

### Debug Commands

```bash
# View CDK version
cdk --version

# List all stacks
cdk list

# View stack template
cdk synth CyberShieldDevNetworkStack

# View stack metadata
aws cloudformation describe-stacks \
  --stack-name CyberShieldDevNetworkStack

# Check resource status
aws cloudformation list-stack-resources \
  --stack-name CyberShieldDevNetworkStack
```

## 💰 Cost Optimization

### Development Environment

- Disable NAT Gateway (`ENABLE_NAT_GATEWAY=false`)
- Use t3.micro instances for RDS and Redis
- Disable enhanced monitoring (`ENABLE_MONITORING=false`)
- Use minimal log retention (1 day)
- Disable OpenSearch (`ENABLE_OPENSEARCH=false`)
- Use Spot instances for ECS (`ENABLE_SPOT_INSTANCES=true`)

**Estimated Dev Cost**: ~$50-70/month

### Production Environment

- Enable NAT Gateway for security
- Use appropriate instance sizes based on load
- Enable monitoring and alarms
- Increase log retention (7-14 days)
- Consider Reserved Instances for predictable workloads
- Use Spot instances where appropriate

**Estimated Prod Cost**: ~$70-95/month (cost-optimized)

### Cost Monitoring

```bash
# View cost and usage
aws ce get-cost-and-usage \
  --time-period Start=2025-01-01,End=2025-01-31 \
  --granularity MONTHLY \
  --metrics BlendedCost \
  --group-by Type=SERVICE

# Set up cost alerts in AWS Budgets console
```

## 📝 Best Practices

### Security

1. **Secrets Management** - Use AWS Secrets Manager for sensitive data
2. **IAM Least Privilege** - Grant minimal required permissions
3. **Network Segmentation** - Use private subnets for databases
4. **Encryption** - Enable encryption at rest and in transit
5. **Security Groups** - Restrict access to necessary ports only

### Reliability

1. **Multi-AZ Deployment** - Enable for production databases
2. **Auto-Scaling** - Configure appropriate scaling policies
3. **Health Checks** - Monitor application and infrastructure health
4. **Backups** - Enable automated backups for critical data
5. **Monitoring** - Set up CloudWatch alarms for key metrics

### Operations

1. **Infrastructure as Code** - All changes through CDK
2. **Change Management** - Review diffs before deployment
3. **Documentation** - Keep configuration documented
4. **Tagging** - Use consistent tags for cost allocation
5. **Version Control** - Track all CDK code changes in Git

## 🔗 Additional Resources

- [AWS CDK Documentation](https://docs.aws.amazon.com/cdk/)
- [AWS CDK Python Reference](https://docs.aws.amazon.com/cdk/api/v2/python/)
- [CDK Best Practices](https://docs.aws.amazon.com/cdk/v2/guide/best-practices.html)
- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)
- [CyberShield Main Documentation](../CLAUDE.md)

## 📧 Support

For issues or questions:
- Review this deployment guide
- Check CloudFormation stack events
- Review CloudWatch logs
- Consult AWS documentation
- Open GitHub issue for bugs

---

**Last Updated**: January 2025
**CDK Version**: 2.100.0+
**AWS CLI Version**: 2.x+
