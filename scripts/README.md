# CyberShield Scripts Directory

## 📋 Script Index

This directory contains deployment, configuration, and maintenance scripts for the CyberShield platform.

### 🏗️ **Core Deployment Scripts**

| Script | Purpose | Status |
|--------|---------|--------|
| `aws_setup.sh` | Initial AWS infrastructure setup | ✅ Active |
| `deploy_aws.py` | Main deployment orchestrator (Python) | ✅ **Current** |
| `create_ecs.sh` | ECS cluster and service creation | ✅ Active |
| `create_enhanced_task_definition.sh` | Latest task definition with Bedrock/OpenSearch | ✅ **Current** |

### 🗄️ **Database & Services Setup**

| Script | Purpose | Status |
|--------|---------|--------|
| `create_rds.sh` | PostgreSQL database setup | ✅ Active |
| `create_redis.sh` | Redis cache setup | ✅ Active |
| `configure_opensearch.sh` | OpenSearch vector store setup | ✅ Active |

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

# 2. Create ECS cluster
./create_ecs.sh

# 3. Deploy with latest configuration
./create_enhanced_task_definition.sh

# 4. Set up HTTPS
./setup_self_signed_https.sh

# 5. Configure auto-scaling
./setup_autoscaling.sh

# 6. Test deployment
./test_https_setup.sh
```

### **Individual Component Setup**
```bash
# Database setup
./create_rds.sh
./create_redis.sh

# Vector store setup
./configure_opensearch.sh

# HTTPS setup
./setup_self_signed_https.sh

# Auto-scaling setup
./setup_autoscaling.sh
```

## 📊 **Script Dependencies**

```
aws_setup.sh
├── create_rds.sh
├── create_redis.sh
└── configure_opensearch.sh

create_ecs.sh
└── create_enhanced_task_definition.sh

setup_self_signed_https.sh
└── test_https_setup.sh

setup_autoscaling_iam.sh
└── setup_autoscaling.sh
```

## 🔧 **Maintenance**

### **Regular Checks**
- `check_opensearch_status.sh` - Monitor OpenSearch health

### **Policy Updates**
All IAM policies are now generated dynamically by the respective setup scripts.

## 🧹 **Cleanup History**

**Latest Cleanup: 2025-08-12 (Fourth Pass)**
- Moved 6 completed setup/test scripts to backup (setup is complete)
- Infrastructure is now fully deployed and operational
- Scripts directory now contains only essential operational files

**Third Pass: 2025-08-12**
- Moved 4 unused JSON policy templates to backup
- Removed static configuration files (policies now generated dynamically)
- Further streamlined scripts directory

**Second Pass: 2025-08-12**
- Removed 2 additional redundant files
- Backed up removed files to `../backup/scripts_cleanup_20250812_153413/`
- Streamlined deployment workflow

**Previous Cleanup: 2025-08-12**
- Removed 9 obsolete/redundant scripts
- Backed up removed scripts to `../backup/scripts_backup_20250812/`
- Organized remaining 20 essential scripts

**Recently Removed (2025-08-12 Fourth Pass):**
- `setup_autoscaling.sh` (moved to backup - autoscaling configured ✅)
- `setup_autoscaling_iam.sh` (moved to backup - IAM roles created ✅)
- `setup_self_signed_https.sh` (moved to backup - HTTPS working ✅)
- `setup_opensearch.py` (moved to backup - development utility)
- `test_deployment.sh` (moved to backup - deployment validated ✅)
- `test_https_setup.sh` (moved to backup - HTTPS validated ✅)

**Third Pass (2025-08-12):**
- `autoscaling_policy.json` (moved to backup - policies generated dynamically)
- `create_bedrock_policy.json` (moved to backup - policies generated dynamically)
- `create_opensearch_policy.json` (moved to backup - policies generated dynamically)
- `create_opensearch_domain.json` (moved to backup - not used by scripts)

**Second Pass (2025-08-12):**
- `deploy_aws.sh` (redundant with more comprehensive `deploy_aws.py`)
- `manual_https_setup.md` (superseded by automated `setup_self_signed_https.sh`)

**Previously Removed Scripts:**
- `create_task_definition.sh` (superseded by enhanced version)
- `setup_https_alb.sh` (failed implementation)
- `ssl_permissions_policy.json` (unused due to IAM limits)
- `create_scaling_plan.sh` (failed due to permissions)
- `manual_aws_setup.sh` (redundant)
- `configure_secrets.sh` (not implemented)
- `deploy_service.sh` (merged into deploy_aws.py)
- `migrate_vector_data.py` (one-time migration)
- `setup_environment.py` (unused)

## 📞 **Support**

- **Current Configuration**: Bedrock LLM + OpenSearch + Self-signed HTTPS + Auto-scaling
- **Environment**: AWS production with dual local/cloud support
- **Status**: All scripts tested and functional as of 2025-08-12