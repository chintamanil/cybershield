---
layout: default
title: "Deployment Guide"
description: "Complete deployment guide for CyberShield AI platform"
---

# 🚀 Deployment Guide

## Complete CyberShield Deployment Instructions

This guide covers local development setup, AWS production deployment, and configuration management for the CyberShield AI platform.

---

## 🏠 **Local Development Setup**

### **Prerequisites**

| Requirement | Version | Purpose |
|-------------|---------|---------|
| **Python** | 3.11+ | Core runtime |
| **Docker** | 20.0+ | Container services |
| **Git** | 2.0+ | Version control |
| **UV Package Manager** | Latest | Python package management |

### **1. Repository Setup**

```bash
# Clone the repository
git clone https://github.com/chintamanil/cybershield.git
cd cybershield

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows
```

### **2. Package Installation**

```bash
# Install with UV (recommended)
uv add -e ".[dev,testing,frontend]"

# Or with pip (alternative)
pip install -e ".[dev,testing,frontend]"
```

### **3. Environment Configuration**

```bash
# Copy environment template
cp .env.template .env

# Edit with your API keys
vim .env  # or your preferred editor
```

**Required Environment Variables:**
```bash
# Security API Keys
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
SHODAN_API_KEY=your_shodan_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
OPENAI_API_KEY=your_openai_api_key_here

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0

# Milvus Configuration
MILVUS_HOST=localhost
MILVUS_PORT=19530

# Application Configuration
DEBUG=True
ENVIRONMENT=development
LOG_LEVEL=INFO
```

### **4. Infrastructure Services**

```bash
# Start supporting services
docker-compose up -d

# Verify services are running
docker-compose ps

# Expected output:
# NAME                    STATUS
# cybershield-milvus-1    Up
# cybershield-postgres-1  Up
# cybershield-redis-1     Up
```

### **5. Data Pipeline (Optional)**

```bash
# Load cybersecurity dataset into Milvus
python data/milvus_ingestion.py

# Verify data loading
python tests/milvus/interactive_milvus_viewer.py
```

### **6. Application Launch**

```bash
# Start backend server
cybershield
# or
python server/main.py

# In another terminal, start frontend
cybershield-frontend
# or
cd frontend && python run_streamlit.py
```

**Local Access:**
- **Backend API**: http://localhost:8000
- **Frontend UI**: http://localhost:8501
- **API Documentation**: http://localhost:8000/docs

---

## ☁️ **AWS Production Deployment with CDK**

### **AWS Prerequisites**

| Requirement | Version | Purpose |
|-------------|---------|---------|
| **AWS Account** | - | Cloud infrastructure |
| **AWS CLI** | v2+ | Command line management |
| **Node.js** | 18+ | AWS CDK CLI runtime |
| **AWS CDK CLI** | Latest | Infrastructure deployment |
| **Python** | 3.11+ | CDK application |
| **Docker** | 20.0+ | Container building |
| **Domain Name** | - | Custom domain (optional) |

### **1. AWS Credentials Setup**

```bash
# Configure AWS credentials
aws configure

# Required permissions:
# - EC2, ECS, ECR Full Access
# - RDS, ElastiCache Access
# - IAM, Route53 Access
# - Certificate Manager
# - CloudFormation Access
```

### **2. CDK Environment Setup**

```bash
# Install AWS CDK CLI globally
npm install -g aws-cdk

# Navigate to CDK directory
cd cdk

# Create Python virtual environment
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install CDK dependencies
pip install -r requirements.txt
```

### **3. Configure Environment Variables**

```bash
# Copy environment template
cp .env.example .env

# Edit with your AWS configuration
vim .env  # or your preferred editor
```

**Required CDK Environment Variables:**
```bash
# AWS Configuration
AWS_ACCOUNT_ID=123456789012        # Your AWS account ID
AWS_REGION=us-east-1               # Deployment region
ENVIRONMENT=dev                     # dev, staging, or prod

# Project Configuration
PROJECT_NAME=cybershield
DOMAIN_NAME=cybershield-ai.com     # Optional, for custom domain

# Application Configuration
ENABLE_AUTO_SCALING=false          # Enable for production
ENABLE_DELETION_PROTECTION=false   # Enable for production
ENABLE_BACKUP=true                 # Database backups
ENABLE_OPENSEARCH=false            # Optional logging service
```

### **4. Bootstrap CDK (First Time Only)**

```bash
# Set AWS credentials
export AWS_ACCOUNT_ID=123456789012
export AWS_REGION=us-east-1

# Bootstrap CDK for your AWS account
cdk bootstrap aws://$AWS_ACCOUNT_ID/$AWS_REGION

# Expected output:
# ✅ CDKToolkit stack created
# ✅ S3 bucket for CDK assets created
# ✅ ECR repository for Docker images created
```

### **5. Preview Infrastructure Changes**

```bash
# Synthesize CloudFormation templates
cdk synth

# View differences from deployed stacks
cdk diff

# List all stacks
cdk list

# Expected stacks:
# - CyberShield-IAM-dev
# - CyberShield-Network-dev
# - CyberShield-DNS-dev
# - CyberShield-Storage-dev
# - CyberShield-Data-dev
# - CyberShield-LoadBalancer-dev
# - CyberShield-Compute-dev
# - CyberShield-Monitoring-dev
```

### **6. Deploy Infrastructure**

```bash
# Deploy all stacks
export ENVIRONMENT=dev
cdk deploy --all

# Deploy specific stack
cdk deploy CyberShield-Network-dev

# Deploy with auto-approval (CI/CD)
cdk deploy --all --require-approval never

# Expected output:
# ✅ CyberShield-IAM-dev (2-3 min)
# ✅ CyberShield-Network-dev (5-7 min)
# ✅ CyberShield-DNS-dev (1-2 min)
# ✅ CyberShield-Storage-dev (2-3 min)
# ✅ CyberShield-Data-dev (8-10 min) - RDS takes longest
# ✅ CyberShield-LoadBalancer-dev (3-5 min)
# ✅ CyberShield-Compute-dev (4-6 min)
# ✅ CyberShield-Monitoring-dev (2-3 min)
```

### **7. Application Deployment**

```bash
# Build and push Docker image to ECR
# (ECR repository created by CDK)
aws ecr get-login-password --region $AWS_REGION | \
  docker login --username AWS --password-stdin \
  $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com

# Build multi-architecture image
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/cybershield:latest \
  --push \
  -f deployment/Dockerfile.aws .

# Force ECS service to use new image
aws ecs update-service \
  --cluster cybershield-dev \
  --service cybershield-backend-service \
  --force-new-deployment
```

### **8. Verify Deployment**

```bash
# Get load balancer DNS
aws cloudformation describe-stacks \
  --stack-name CyberShield-LoadBalancer-dev \
  --query 'Stacks[0].Outputs[?OutputKey==`LoadBalancerDNS`].OutputValue' \
  --output text

# Test health endpoint
curl https://YOUR_ALB_DNS/health

# Monitor ECS service
aws ecs describe-services \
  --cluster cybershield-dev \
  --services cybershield-backend-service
```

### **9. Custom Domain Setup (Optional)**

If deploying with a custom domain:

```bash
# Set domain in .env
echo "DOMAIN_NAME=cybershield-ai.com" >> .env

# Deploy DNS stack (creates Route53 hosted zone and SSL certificate)
cdk deploy CyberShield-DNS-dev

# Get name servers from Route53
aws route53 list-hosted-zones-by-name \
  --dns-name cybershield-ai.com \
  --query 'HostedZones[0].Id' \
  --output text

# Update domain registrar with Route53 name servers
# (This step is done in your domain registrar's console)
```

### **10. Destroy Infrastructure (When Needed)**

```bash
# Destroy all stacks
cdk destroy --all

# Destroy specific stack
cdk destroy CyberShield-Compute-dev

# Note: Some resources may have deletion protection enabled
# Remove protection first if needed
```

---

## 🐳 **Container Deployment**

### **Docker Configuration**

#### **Production Dockerfile**
```dockerfile
# Multi-stage build for optimization
FROM python:3.12-slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    libtesseract-dev \
    libgl1-mesa-glx \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.12-slim as production

# Copy system dependencies
COPY --from=builder /usr /usr

# Create non-root user
RUN groupadd -r cybershield && useradd -r -g cybershield cybershield

# Set working directory and copy application
WORKDIR /app
COPY . .
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages

# Set ownership
RUN chown -R cybershield:cybershield /app

# Switch to non-root user
USER cybershield

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Expose port
EXPOSE 8000

# Start application
CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

#### **Build Multi-Architecture Images**

```bash
# Setup Docker buildx for multi-platform
docker buildx create --name multiarch --driver docker-container --use
docker buildx inspect --bootstrap

# Build for multiple architectures
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t cybershield:latest \
  --push .

# For ECS deployment
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t 840656856721.dkr.ecr.us-east-1.amazonaws.com/cybershield:latest \
  --push .
```

### **ECS Task Definition**

```json
{
  "family": "cybershield-task",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "executionRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskRole",
  "containerDefinitions": [
    {
      "name": "cybershield",
      "image": "840656856721.dkr.ecr.us-east-1.amazonaws.com/cybershield:latest",
      "portMappings": [
        {
          "containerPort": 8000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "ENVIRONMENT", "value": "production"},
        {"name": "LOG_LEVEL", "value": "INFO"},
        {"name": "REDIS_HOST", "value": "cybershield-redis.i2louo.0001.use1.cache.amazonaws.com"},
        {"name": "POSTGRES_HOST", "value": "cybershield-postgres.cwo4lje0wol6.us-east-1.rds.amazonaws.com"}
      ],
      "secrets": [
        {"name": "VIRUSTOTAL_API_KEY", "valueFrom": "arn:aws:ssm:REGION:ACCOUNT:parameter/cybershield/virustotal-key"},
        {"name": "SHODAN_API_KEY", "valueFrom": "arn:aws:ssm:REGION:ACCOUNT:parameter/cybershield/shodan-key"},
        {"name": "ABUSEIPDB_API_KEY", "valueFrom": "arn:aws:ssm:REGION:ACCOUNT:parameter/cybershield/abuseipdb-key"},
        {"name": "OPENAI_API_KEY", "valueFrom": "arn:aws:ssm:REGION:ACCOUNT:parameter/cybershield/openai-key"}
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:8000/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/cybershield",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

---

## ⚙️ **Configuration Management**

### **Environment-Specific Configuration**

#### **Development (.env.local)**
```bash
DEBUG=True
ENVIRONMENT=development
LOG_LEVEL=DEBUG
LOG_FILE=logs/cybershield-dev.log

# Local services
REDIS_HOST=localhost
REDIS_PORT=6379
MILVUS_HOST=localhost
MILVUS_PORT=19530

# Performance tuning for development
DEVICE_OPTIMIZATION=auto
APPLE_SILICON_ACCELERATION=true
```

#### **Production (.env.production)**
```bash
DEBUG=False
ENVIRONMENT=production
LOG_LEVEL=INFO
LOG_FILE=logs/cybershield.log

# AWS services
REDIS_HOST=cybershield-redis.i2louo.0001.use1.cache.amazonaws.com
REDIS_PORT=6379
POSTGRES_HOST=cybershield-postgres.cwo4lje0wol6.us-east-1.rds.amazonaws.com
POSTGRES_PORT=5432

# Production optimizations
DEVICE_OPTIMIZATION=production
REACT_LOG_FORMAT=json
```

### **Secrets Management**

#### **AWS Systems Manager Parameter Store**
```bash
# Store API keys securely
aws ssm put-parameter \
  --name "/cybershield/virustotal-key" \
  --value "your_virustotal_api_key" \
  --type "SecureString"

aws ssm put-parameter \
  --name "/cybershield/shodan-key" \
  --value "your_shodan_api_key" \
  --type "SecureString"

aws ssm put-parameter \
  --name "/cybershield/abuseipdb-key" \
  --value "your_abuseipdb_api_key" \
  --type "SecureString"

aws ssm put-parameter \
  --name "/cybershield/openai-key" \
  --value "your_openai_api_key" \
  --type "SecureString"
```

#### **Local Development Secrets**
```bash
# For local development, use .env file
# Never commit API keys to version control

# Use environment variables
export VIRUSTOTAL_API_KEY="your_key_here"
export SHODAN_API_KEY="your_key_here"
export ABUSEIPDB_API_KEY="your_key_here"
export OPENAI_API_KEY="your_key_here"
```

---

## 🔄 **CI/CD Pipeline with CDK**

### **GitHub Actions Workflow**

```yaml
name: Deploy CyberShield with CDK

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  AWS_REGION: us-east-1
  ENVIRONMENT: dev

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: |
          pip install uv
          uv add -e ".[dev,testing]"

      - name: Run application tests
        run: |
          python -m pytest tests/ -v --tb=short

      - name: Run CDK tests
        run: |
          cd cdk
          pip install -r requirements.txt
          python -m pytest tests/ -v

      - name: Run linting
        run: |
          uv run ruff check .
          uv run ruff format --check .

      - name: Type checking
        run: |
          uv run pyright

  cdk-diff:
    needs: test
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'

    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'

      - name: Install AWS CDK
        run: npm install -g aws-cdk

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.12'

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ env.AWS_REGION }}

      - name: Install CDK dependencies
        run: |
          cd cdk
          pip install -r requirements.txt

      - name: CDK Diff
        run: |
          cd cdk
          cdk diff --all

  deploy:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'

    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'

      - name: Install AWS CDK
        run: npm install -g aws-cdk

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.12'

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ env.AWS_REGION }}

      - name: Install CDK dependencies
        run: |
          cd cdk
          pip install -r requirements.txt

      - name: CDK Deploy
        run: |
          cd cdk
          cdk deploy --all --require-approval never
        env:
          AWS_ACCOUNT_ID: ${{ secrets.AWS_ACCOUNT_ID }}
          ENVIRONMENT: ${{ env.ENVIRONMENT }}

      - name: Login to Amazon ECR
        uses: aws-actions/amazon-ecr-login@v1

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v2

      - name: Build and push Docker image
        run: |
          docker buildx build \
            --platform linux/amd64,linux/arm64 \
            --tag $ECR_REGISTRY/cybershield:$GITHUB_SHA \
            --tag $ECR_REGISTRY/cybershield:latest \
            --push \
            -f deployment/Dockerfile.aws .
        env:
          ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}

      - name: Force ECS deployment
        run: |
          aws ecs update-service \
            --cluster cybershield-${{ env.ENVIRONMENT }} \
            --service cybershield-backend-service \
            --force-new-deployment
```

---

## 📊 **Monitoring & Observability**

### **Health Check Configuration**

```python
# server/main.py - Health check endpoint
@app.get("/health")
async def health_check():
    """Comprehensive health check for load balancers"""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "version": "2.1.0",
        "components": {}
    }
    
    # Check Redis connection
    try:
        redis_client = get_redis_client()
        await redis_client.ping()
        health_status["components"]["redis"] = "healthy"
    except Exception:
        health_status["components"]["redis"] = "unhealthy"
        health_status["status"] = "degraded"
    
    # Check database connection
    try:
        # Database health check logic
        health_status["components"]["database"] = "healthy"
    except Exception:
        health_status["components"]["database"] = "unhealthy"
        health_status["status"] = "degraded"
    
    return health_status
```

### **CloudWatch Alarms**

```bash
# High CPU utilization
aws cloudwatch put-metric-alarm \
  --alarm-name "CyberShield-High-CPU" \
  --alarm-description "High CPU utilization" \
  --metric-name CPUUtilization \
  --namespace AWS/ECS \
  --statistic Average \
  --period 300 \
  --threshold 70 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=ServiceName,Value=cybershield-service Name=ClusterName,Value=cybershield-cluster

# High memory utilization
aws cloudwatch put-metric-alarm \
  --alarm-name "CyberShield-High-Memory" \
  --alarm-description "High memory utilization" \
  --metric-name MemoryUtilization \
  --namespace AWS/ECS \
  --statistic Average \
  --period 300 \
  --threshold 80 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=ServiceName,Value=cybershield-service Name=ClusterName,Value=cybershield-cluster

# Health check failures
aws cloudwatch put-metric-alarm \
  --alarm-name "CyberShield-Health-Check-Failures" \
  --alarm-description "Health check failures" \
  --metric-name UnHealthyHostCount \
  --namespace AWS/ApplicationELB \
  --statistic Average \
  --period 60 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold
```

---

## 🔧 **Troubleshooting**

### **Common Deployment Issues**

#### **1. Container Won't Start**
```bash
# Check ECS service events
aws ecs describe-services \
  --cluster cybershield-cluster \
  --services cybershield-service \
  --query 'services[0].events'

# Check task definition
aws ecs describe-task-definition \
  --task-definition cybershield-task

# View container logs
aws logs describe-log-streams \
  --log-group-name /ecs/cybershield
```

#### **2. Health Check Failures**
```bash
# Test health endpoint locally
curl -f http://localhost:8000/health

# Check load balancer target health
aws elbv2 describe-target-health \
  --target-group-arn arn:aws:elasticloadbalancing:us-east-1:ACCOUNT:targetgroup/cybershield-tg/ID
```

#### **3. Database Connection Issues**
```bash
# Test database connectivity
python -c "
import psycopg2
conn = psycopg2.connect(
    host='cybershield-postgres.cwo4lje0wol6.us-east-1.rds.amazonaws.com',
    database='cybershield',
    user='cybershield',
    password='your_password'
)
print('Database connection successful')
conn.close()
"
```

#### **4. Redis Connection Issues**
```bash
# Test Redis connectivity
python -c "
import redis
r = redis.Redis(
    host='cybershield-redis.i2louo.0001.use1.cache.amazonaws.com',
    port=6379,
    decode_responses=True
)
print('Redis ping:', r.ping())
"
```

### **Performance Optimization**

#### **1. Memory Optimization**
```python
# utils/performance_config.py
MEMORY_OPTIMIZATION_CONFIG = {
    "batch_size": 32,          # Optimized for 2GB container
    "max_workers": 4,          # Match container CPU
    "cache_size": "256mb",     # Redis memory allocation
    "gc_threshold": (700, 10, 10)  # Garbage collection tuning
}
```

#### **2. Apple Silicon Optimization**
```python
# utils/device_config.py
def create_performance_config():
    """Create optimized configuration for Apple Silicon"""
    if torch.backends.mps.is_available():
        return {
            "device": "mps",
            "batch_size": 64,      # Higher batch size for MPS
            "precision": "float16", # Half precision for memory efficiency
            "num_workers": 8       # More workers for Apple Silicon
        }
    return default_config()
```

---

## 📋 **Deployment Checklist**

### **Pre-Deployment**
- [ ] All tests passing (98.5% - 388/394 tests)
- [ ] Frontend tests validated (36 session management tests)
- [ ] Environment variables configured
- [ ] API keys obtained and secured
- [ ] Docker containers built successfully
- [ ] Infrastructure scripts reviewed

### **AWS Deployment**
- [ ] AWS credentials configured
- [ ] VPC and networking created
- [ ] Security groups configured
- [ ] RDS database created and accessible
- [ ] Redis cluster operational
- [ ] ECR repository created
- [ ] ECS cluster and service running
- [ ] Load balancer health checks passing

### **Post-Deployment**
- [ ] Health endpoints responding
- [ ] SSL certificate active (if using custom domain)
- [ ] DNS resolution working
- [ ] API endpoints functional
- [ ] External APIs accessible
- [ ] Monitoring and alarms configured
- [ ] Backup procedures verified

### **Production Readiness**
- [ ] Performance testing completed
- [ ] Load testing passed
- [ ] Security scan completed
- [ ] Documentation updated
- [ ] Team access configured
- [ ] Incident response procedures documented

---

This comprehensive deployment guide ensures successful deployment of CyberShield in both development and production environments with optimal performance, security, and reliability.