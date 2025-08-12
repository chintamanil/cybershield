# 🚀 CyberShield AWS Deployment Guide

Complete guide to deploy CyberShield on AWS with all security best practices.

## 📋 Prerequisites

✅ **AWS Account** with sufficient permissions (you have this!)
✅ **AWS CLI** installed and configured
✅ **Docker** installed and running
✅ **Node.js** installed (for AWS CDK)
✅ **Your API Keys** (VirusTotal, Shodan, AbuseIPDB, OpenAI)

## 🎯 Quick Start (5 Steps)

### Step 1: Initial AWS Setup
```bash
# Run the setup script
./scripts/aws_setup.sh
```

This will:
- Install AWS CLI and CDK (if needed)
- Configure AWS credentials
- Update CDK with your account ID/region

### Step 2: Deploy Infrastructure
```bash
# Deploy all AWS resources
./scripts/deploy_aws.sh
```

This creates:
- **VPC** with public/private subnets
- **RDS PostgreSQL** database (encrypted)
- **ElastiCache Redis** cluster (encrypted)
- **OpenSearch** domain for vector storage
- **ECS Fargate** service with auto-scaling
- **Application Load Balancer** with HTTPS
- **CloudFront CDN** with WAF protection
- **Secrets Manager** for API keys
- **CloudWatch** logging and monitoring

### Step 3: Configure API Keys
```bash
# Add your real API keys to AWS Secrets Manager
./scripts/configure_secrets.sh
```

You'll be prompted for:
- VirusTotal API Key
- Shodan API Key  
- AbuseIPDB API Key

### Step 4: Test Deployment
```bash
# Test all endpoints and functionality
./scripts/test_deployment.sh
```

### Step 5: Access Your Application
Your CyberShield platform will be available at:
- **CloudFront URL**: `https://d1234567890.cloudfront.net` (from script output)
- **Load Balancer URL**: `https://cybershield-alb-123456789.us-east-1.elb.amazonaws.com`

## 🏗️ Infrastructure Architecture

```
                                    ┌─────────────────┐
                                    │   CloudFront    │
                                    │   Distribution  │
                                    │   (Global CDN)  │
                                    └─────────┬───────┘
                                              │
                                    ┌─────────▼───────┐
                                    │       WAF       │
                                    │   (Security)    │
                                    └─────────┬───────┘
                                              │
    ┌─────────────────────────────────────────▼─────────────────────────────────────────┐
    │                                VPC                                                 │
    │                                                                                    │
    │  ┌─────────────────┐                                 ┌─────────────────┐         │
    │  │  Public Subnet  │                                 │  Public Subnet  │         │
    │  │                 │                                 │                 │         │
    │  │       ALB       │                                 │    NAT Gateway  │         │
    │  └─────────┬───────┘                                 └─────────────────┘         │
    │            │                                                                       │
    │  ┌─────────▼───────┐                                 ┌─────────────────┐         │
    │  │ Private Subnet  │                                 │ Private Subnet  │         │
    │  │                 │                                 │                 │         │
    │  │  ECS Fargate    │◄──────────────────────────────► │   OpenSearch    │         │
    │  │   (CyberShield) │                                 │     Domain      │         │
    │  └─────────┬───────┘                                 └─────────────────┘         │
    │            │                                                                       │
    │            ▼                                                                       │
    │  ┌─────────────────┐         ┌─────────────────┐     ┌─────────────────┐         │
    │  │ Database Subnet │         │ Database Subnet │     │ Database Subnet │         │
    │  │                 │         │                 │     │                 │         │
    │  │  RDS PostgreSQL │         │ ElastiCache     │     │    (Reserved)   │         │
    │  │   (Encrypted)   │         │     Redis       │     │                 │         │
    │  └─────────────────┘         └─────────────────┘     └─────────────────┘         │
    └────────────────────────────────────────────────────────────────────────────────────┘
```

## 🔧 Configuration Details

### Environment Variables (Automatically Set)
- `CYBERSHIELD_ENV=aws`
- `AWS_DEFAULT_REGION=your-region`
- `RDS_ENDPOINT=your-rds-endpoint`
- `ELASTICACHE_ENDPOINT=your-redis-endpoint`
- `OPENSEARCH_ENDPOINT=your-opensearch-endpoint`

### Secrets Manager Integration
- **API Keys**: Stored in `CyberShieldAPIKeys` secret
- **Database Credentials**: Auto-generated in `CyberShieldRDSCredentials`
- **Automatic Rotation**: Configured for enhanced security

### Security Features
- **Encryption at Rest**: All data encrypted with KMS
- **Encryption in Transit**: HTTPS/TLS everywhere
- **Network Isolation**: Private subnets for sensitive resources
- **WAF Protection**: Rate limiting and common attack prevention
- **Fine-grained IAM**: Least privilege access
- **VPC Flow Logs**: Network traffic monitoring

### Auto-Scaling Configuration
- **ECS Service**: 2-10 tasks based on CPU/memory
- **Database**: Read replicas for high availability
- **Redis**: Cluster mode for performance
- **OpenSearch**: Multi-AZ deployment

## 📊 Monitoring & Observability

### CloudWatch Dashboards
- **Application Metrics**: Response times, error rates
- **Infrastructure Metrics**: CPU, memory, disk usage
- **Custom Metrics**: Security analysis performance

### Logging
- **Application Logs**: `/aws/cybershield/application`
- **VPC Flow Logs**: Network traffic analysis
- **Load Balancer Logs**: Request/response logging
- **CloudFront Logs**: CDN access patterns

### Alerting
- **Health Check Failures**: Immediate notification
- **High Error Rates**: Automated scaling triggers
- **Security Events**: WAF blocks and suspicious activity

## 💰 Cost Optimization

### Estimated Monthly Costs (us-east-1)
- **ECS Fargate** (2 tasks): ~$30
- **RDS PostgreSQL** (t3.micro): ~$15
- **ElastiCache Redis** (t3.micro): ~$15
- **OpenSearch** (t3.small): ~$25
- **Data Transfer**: ~$10
- **Other Services**: ~$5
- **Total**: ~$100/month

### Cost-Saving Tips
1. **Use Spot Instances**: For non-critical workloads
2. **Reserved Instances**: 1-year savings for stable workloads
3. **Scheduled Scaling**: Scale down during off-hours
4. **S3 Lifecycle**: Archive old logs to cheaper storage

## 🔍 Troubleshooting

### Common Issues

#### ECS Tasks Won't Start
```bash
# Check ECS service events
aws ecs describe-services --cluster CyberShieldCluster --services CyberShieldService
```

#### Health Checks Failing
```bash
# Check recent logs
aws logs tail /aws/cybershield/application --since 30m
```

#### OpenSearch Access Issues
```bash
# Verify security group rules
aws ec2 describe-security-groups --group-names "OpenSearchSecurityGroup"
```

#### API Key Issues
```bash
# Test secret retrieval
aws secretsmanager get-secret-value --secret-id CyberShieldAPIKeys
```

### Log Analysis Commands
```bash
# Real-time log streaming
aws logs tail /aws/cybershield/application --follow

# Search for errors
aws logs filter-log-events \
  --log-group-name /aws/cybershield/application \
  --filter-pattern "ERROR"

# Check specific time range
aws logs filter-log-events \
  --log-group-name /aws/cybershield/application \
  --start-time $(date -d '1 hour ago' +%s)000
```

## 🚀 Advanced Configuration

### Custom Domain Setup
1. **Register Domain**: Route53 or external registrar
2. **SSL Certificate**: AWS Certificate Manager
3. **CloudFront**: Add custom domain
4. **Route53**: Point to CloudFront distribution

### Multi-Region Deployment
1. **Replicate Infrastructure**: Deploy stack in multiple regions
2. **Global Load Balancer**: Route53 health checks
3. **Data Synchronization**: Cross-region replication
4. **Disaster Recovery**: Automated failover

### Production Hardening
1. **Enable GuardDuty**: Threat detection
2. **Config Rules**: Compliance monitoring
3. **Security Hub**: Centralized security findings
4. **Systems Manager**: Patch management

## 📞 Support

### AWS Resources
- **Documentation**: https://docs.aws.amazon.com/
- **Support Center**: AWS Console → Support
- **Forums**: https://forums.aws.amazon.com/

### CyberShield Specific
- **Logs**: CloudWatch Logs in AWS Console
- **Metrics**: CloudWatch Dashboards
- **Health**: ECS Service health in AWS Console

## 🎉 Success!

Once deployed, your CyberShield platform provides:
- **Scalable Security Analysis**: Auto-scaling based on demand
- **Global Availability**: CloudFront CDN for worldwide access
- **Enterprise Security**: WAF, encryption, monitoring
- **Cost Optimization**: Pay only for what you use
- **Maintenance-Free**: Managed services handle updates

Your cybersecurity platform is now enterprise-ready on AWS! 🛡️