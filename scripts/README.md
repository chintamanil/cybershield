# CyberShield Scripts Directory

## 📋 Script Index

This directory contains deployment, configuration, and maintenance scripts for the CyberShield platform.

### 🏗️ **Core Deployment Scripts**

| Script | Purpose | Status |
|--------|---------|--------|
| `aws_setup.sh` | Initial AWS infrastructure setup | ✅ Active |
| `deploy_aws.py` | Main deployment orchestrator (Python) | ✅ **Current** |
| `create_ecs.sh` | ECS cluster and service creation | ✅ Active |

### 🗄️ **Database & Services Setup**

| Script | Purpose | Status |
|--------|---------|--------|
| `create_rds.sh` | PostgreSQL database setup | ✅ Active |
| `create_redis.sh` | Redis cache setup | ✅ Active |
| `configure_opensearch.sh` | OpenSearch vector store setup | ✅ Active |

### 🌐 **Domain & SSL Management**

| Script | Purpose | Status |
|--------|---------|--------|
| `setup_ssl_only.sh` | SSL certificate request for cybershield-ai.com | ✅ **Production** |
| `update_alb_certificate.sh` | Update ALB with validated SSL certificate | ✅ **Production** |
| `fix_api_routing.sh` | Configure ALB routing for domain structure | ✅ **Production** |

### 🔍 **Monitoring**

| Script | Purpose | Status |
|--------|---------|--------|
| `check_opensearch_status.sh` | OpenSearch monitoring | ✅ Active |

### 📋 **Configuration**

All configuration is now handled dynamically by scripts. Policy templates have been moved to backup for reference.

## 🚀 **Quick Start Guide**

### **Full Deployment (Fresh Install)**
```bash
# 1. Initial infrastructure
./aws_setup.sh

# 2. Create ECS cluster and services
./create_ecs.sh

# 3. Main deployment orchestrator
python deploy_aws.py

# 4. Domain setup (if using custom domain)
./setup_ssl_only.sh
./update_alb_certificate.sh
./fix_api_routing.sh
```

### **Individual Component Setup**
```bash
# Database setup
./create_rds.sh
./create_redis.sh

# Vector store setup
./configure_opensearch.sh

# Domain & SSL setup (for cybershield-ai.com)
./setup_ssl_only.sh
./update_alb_certificate.sh
./fix_api_routing.sh
```

## 📊 **Script Dependencies**

```
aws_setup.sh
├── create_rds.sh
├── create_redis.sh
└── configure_opensearch.sh

create_ecs.sh
└── deploy_aws.py

Domain Setup (cybershield-ai.com):
setup_ssl_only.sh
└── update_alb_certificate.sh
    └── fix_api_routing.sh
```

## 🔧 **Maintenance**

### **Regular Checks**
- `check_opensearch_status.sh` - Monitor OpenSearch health

### **Policy Updates**
All IAM policies are now generated dynamically by the respective setup scripts.

## 🧹 **Cleanup History**

**Latest Cleanup: 2025-08-12 (Domain Migration Complete)**
- **Platform Status**: ✅ **PRODUCTION READY** at https://cybershield-ai.com
- Moved 13 obsolete frontend/routing scripts to backup after successful domain setup
- Scripts directory now contains only 11 essential scripts (57% reduction)
- Domain setup completed: SSL certificate, ALB routing, frontend configuration

**Removed (Domain Cleanup - 2025-08-12):**
- 5 frontend task definition iterations (superseded by working deployment)
- 3 frontend service scripts (superseded by working service) 
- 4 failed/obsolete routing scripts (superseded by `fix_api_routing.sh`)
- 1 health check script (debugging complete)

**Previous Cleanups:**
- Fourth Pass: Moved completed setup/test scripts (infrastructure deployed)
- Third Pass: Moved JSON policy templates (dynamic generation implemented)
- Second Pass: Removed redundant deployment scripts
- Initial Pass: Removed 9 obsolete scripts

## 📞 **Support**

- **Platform URL**: https://cybershield-ai.com (✅ Production)
- **SSL Certificate**: AWS Certificate Manager (auto-renewal enabled)
- **Current Configuration**: OpenAI LLM + Redis STM + Milvus Vector Store + Production SSL
- **Environment**: AWS production with cybershield-ai.com domain
- **Status**: ✅ **PRODUCTION DEPLOYMENT COMPLETE** as of 2025-08-12

### **Architecture:**
- **Frontend**: Streamlit UI at https://cybershield-ai.com/
- **Backend**: FastAPI at https://cybershield-ai.com/analyze
- **Infrastructure**: AWS ECS Fargate + ALB + Route 53 + ACM