---
layout: default
title: "AWS Infrastructure"
description: "Complete AWS deployment architecture and infrastructure setup"
---

# ☁️ AWS Infrastructure

## Production-Grade AWS Deployment Architecture

CyberShield is deployed on AWS using a comprehensive, scalable infrastructure that supports high availability, security, and performance optimization.

---

## 🏗️ **Complete AWS Architecture**

![CyberShield AI Platform](/cybershield/assets/cybershield.png)


---

<!-- ## 🌐 **Domain & SSL Configuration**

### **Custom Domain Setup**

| Component | Configuration | Status |
|-----------|---------------|--------|
| **Domain** | cybershield-ai.com | ✅ Active |
| **Registrar** | Namecheap | ✅ Purchased ($11.48/year) |
| **SSL Certificate** | AWS Certificate Manager | ✅ Auto-renewal enabled |
| **DNS Validation** | Route53 integration | ✅ Automated |



--- -->

## 🐳 **Container Infrastructure**

### **ECS Fargate Configuration**

```mermaid
graph TD
    subgraph "ECS Architecture"
        Cluster[ECS Cluster<br/>cybershield-cluster]

        subgraph "Service Configuration"
            Service[ECS Service<br/>Desired: 1, Running: 1]
            AutoScaling[Auto Scaling<br/>CPU/Memory based]
            DeploymentConfig[Rolling Deployment<br/>Blue/Green Capable]
        end

        subgraph "Task Definition"
            TaskDef[Task Definition<br/>cybershield-task]
            ContainerDef[Container Definition<br/>1 vCPU, 2GB RAM]

            subgraph "Multi-Architecture Support"
                ARM64[ARM64 Support<br/>Graviton2 instances]
                AMD64[AMD64 Support<br/>Traditional x86]
            end
        end

        subgraph "Health & Monitoring"
            HealthCheck[Health Check<br/>/health endpoint]
            CloudWatch[CloudWatch Logs<br/>Structured logging]
        end
    end

    Cluster --> Service
    Service --> TaskDef
    TaskDef --> ContainerDef
    ContainerDef --> ARM64
    ContainerDef --> AMD64
    Service --> HealthCheck
    ContainerDef --> CloudWatch

    %% Darker Arrow Styling
    linkStyle default stroke:#111,stroke-width:1px
```

### **Container Specifications**

| Resource | Specification | Rationale |
|----------|---------------|-----------|
| **CPU** | 1 vCPU | Optimized for AI workloads |
| **Memory** | 2048 MB | Supports ML models + caching |
| **Architecture** | ARM64/AMD64 | Multi-platform compatibility |
| **Health Check** | `/health` endpoint | 30s interval, 3 retries |
| **Logging** | CloudWatch Logs | Structured JSON logging |

---

## 🗄️ **Database Architecture**

### **RDS PostgreSQL Configuration**

```mermaid
graph LR
    subgraph "RDS Setup"
        RDS[RDS PostgreSQL 15.13]

        subgraph "Configuration"
            Instance[db.t3.micro<br/>1 vCPU, 1GB RAM]
            Storage[20GB GP2<br/>Encrypted]
            Backup[Automated Backups<br/>7-day retention]
        end

        subgraph "Network"
            SubnetGroup[DB Subnet Group<br/>Multi-AZ]
            SecurityGroup[Security Group<br/>Port 5432 from ECS]
        end

        subgraph "Features"
            Encryption[Encryption at Rest<br/>KMS managed]
            Monitoring[Enhanced Monitoring<br/>CloudWatch]
            MaintenanceWindow[Maintenance Window<br/>Auto-minor upgrades]
        end
    end

    RDS --> Instance
    RDS --> Storage
    RDS --> Backup
    RDS --> SubnetGroup
    RDS --> SecurityGroup
    RDS --> Encryption
    RDS --> Monitoring
    RDS --> MaintenanceWindow

    %% Darker Arrow Styling
    linkStyle default stroke:#111,stroke-width:1px
```

**Database Details:**
- **Engine**: PostgreSQL 15.13
- **Instance**: db.t3.micro (1 vCPU, 1GB RAM)
- **Storage**: 20GB GP2 with encryption
- **Endpoint**: `cybershield-postgres.cwo4lje0wol6.us-east-1.rds.amazonaws.com:5432`
- **Backups**: Automated daily backups, 7-day retention
- **Security**: VPC isolation, encrypted storage

### **ElastiCache Redis Configuration**

```mermaid
graph LR
    subgraph "Redis Setup"
        Redis[ElastiCache Redis 7.1.0]

        subgraph "Configuration"
            Instance[cache.t3.micro<br/>1 vCPU, 0.5GB RAM]
            ReplicationGroup[Single Node<br/>Cost optimized]
        end

        subgraph "Network"
            SubnetGroup[Cache Subnet Group<br/>Multi-AZ capable]
            SecurityGroup[Security Group<br/>Port 6379 from ECS]
        end

        subgraph "Features"
            InTransitEncryption[Encryption in Transit<br/>TLS enabled]
            BackupRetention[Snapshot Retention<br/>5-day retention]
            MaintenanceWindow[Maintenance Window<br/>Auto-patching]
        end
    end

    Redis --> Instance
    Redis --> ReplicationGroup
    Redis --> SubnetGroup
    Redis --> SecurityGroup
    Redis --> InTransitEncryption
    Redis --> BackupRetention
    Redis --> MaintenanceWindow

    %% Darker Arrow Styling
    linkStyle default stroke:#111,stroke-width:1px
```

**Cache Details:**
- **Engine**: Redis 7.1.0
- **Instance**: cache.t3.micro (1 vCPU, 0.5GB RAM)
- **Endpoint**: `cybershield-redis.i2louo.0001.use1.cache.amazonaws.com:6379`
- **Security**: VPC isolation, encryption in transit
- **Usage**: Session management, API caching, IOC storage

---

## 🔒 **Security Architecture**

### **Network Security**

```mermaid
graph TD
    subgraph "Security Layers"
        subgraph "Perimeter Security"
            WAF[AWS WAF<br/>Web Application Firewall]
            CloudFront[CloudFront<br/>DDoS Protection]
        end

        subgraph "Network Security"
            VPC[VPC Isolation<br/>10.0.0.0/16]
            NACL[Network ACLs<br/>Subnet-level filtering]
            SG[Security Groups<br/>Instance-level filtering]
        end

        subgraph "Data Security"
            KMS[AWS KMS<br/>Key Management]
            Encryption[Encryption at Rest<br/>RDS + EBS]
            TLS[TLS in Transit<br/>All communications]
        end

        subgraph "Access Control"
            IAM[IAM Roles & Policies<br/>Least privilege]
            SecretsManager[Secrets Manager<br/>API key management]
        end
    end
```

### **Security Group Configuration**

| Security Group | Purpose | Rules |
|----------------|---------|-------|
| **ALB Security Group** | `sg-022ba581db949e7ca` | HTTP (80) from Internet<br/>HTTPS (443) from Internet |
| **ECS Security Group** | `sg-04269afeceada14a6` | Port 8000 from ALB only |
| **RDS Security Group** | `sg-080ba65d29243ee89` | Port 5432 from ECS only |
| **Redis Security Group** | `sg-0273ea3f4e22547e5` | Port 6379 from ECS only |

### **IAM Roles & Policies**

```mermaid
graph LR
    subgraph "IAM Architecture"
        subgraph "ECS Roles"
            TaskRole[ECS Task Role<br/>Application permissions]
            ExecutionRole[ECS Execution Role<br/>Infrastructure permissions]
        end

        subgraph "Service Policies"
            ECRPolicy[ECR Access<br/>Container image pulls]
            LogsPolicy[CloudWatch Logs<br/>Log stream creation]
            SecretsPolicy[Secrets Manager<br/>Environment variables]
        end

        subgraph "Data Access"
            RDSPolicy[RDS Access<br/>Database connections]
            RedisPolicy[ElastiCache Access<br/>Cache operations]
        end
    end

    TaskRole --> ECRPolicy
    TaskRole --> RDSPolicy
    TaskRole --> RedisPolicy
    ExecutionRole --> LogsPolicy
    ExecutionRole --> SecretsPolicy

    %% Darker Arrow Styling
    linkStyle default stroke:#111,stroke-width:1px
```

---

## 📈 **Monitoring & Logging**

### **CloudWatch Integration**

```mermaid
graph TD
    subgraph "Monitoring Stack"
        subgraph "Metrics"
            ECSMetrics[ECS Service Metrics<br/>CPU, Memory, Tasks]
            ALBMetrics[ALB Metrics<br/>Request count, Latency]
            RDSMetrics[RDS Metrics<br/>Connections, Performance]
        end

        subgraph "Logs"
            AppLogs[Application Logs<br/>Structured JSON]
            AccessLogs[ALB Access Logs<br/>Request tracking]
            VPCLogs[VPC Flow Logs<br/>Network analysis]
        end

        subgraph "Alarms"
            HealthAlarm[Health Check Failures<br/>Auto-scaling triggers]
            PerformanceAlarm[Performance Thresholds<br/>Response time > 5s]
            ErrorAlarm[Error Rate Monitoring<br/>5xx responses > 5%]
        end
    end
```

### **Auto Scaling Configuration**

```mermaid
graph LR
    subgraph "Auto Scaling"
        Target[Target Tracking<br/>CPU Utilization: 70%<br/>Memory Utilization: 80%]

        subgraph "Scaling Policies"
            ScaleOut[Scale Out<br/>+1 task when CPU > 70%<br/>2 min evaluation]
            ScaleIn[Scale In<br/>-1 task when CPU < 30%<br/>5 min evaluation]
        end

        subgraph "Limits"
            MinCapacity[Minimum: 1 task<br/>Always available]
            MaxCapacity[Maximum: 10 tasks<br/>Cost control]
        end
    end

    Target --> ScaleOut
    Target --> ScaleIn
    ScaleOut --> MinCapacity
    ScaleIn --> MaxCapacity

    %% Darker Arrow Styling
    linkStyle default stroke:#111,stroke-width:1px
```

---

## 💰 **Cost Optimization**

### **Current Cost Structure (Monthly)**

| Service | Instance Type | Estimated Cost | Optimization |
|---------|---------------|----------------|--------------|
| **ECS Fargate** | 1 vCPU, 2GB RAM | $20-30 | Spot instances capable |
| **RDS PostgreSQL** | db.t3.micro | $15-20 | Free tier eligible |
| **ElastiCache Redis** | cache.t3.micro | $15-20 | Single node setup |
| **Application Load Balancer** | Standard ALB | $20-25 | Usage-based pricing |
| **Domain Registration** | cybershield-ai.com | $11.48/year | Annual renewal |
| **SSL Certificate** | AWS Certificate Manager | Free | AWS managed |
| **Data Transfer** | Outbound traffic | $5-10 | CDN optimization available |
| **Total Estimated** | - | **$70-95/month** | Production workload |

### **Cost Optimization Strategies**

```mermaid
graph TD
    subgraph "Cost Optimization"
        subgraph "Compute Optimization"
            Fargate[Fargate Spot<br/>Up to 90% savings]
            RightSizing[Right-sizing<br/>Performance monitoring]
        end

        subgraph "Storage Optimization"
            GP3[GP3 Storage<br/>Better price/performance]
            LifecyclePolicy[Lifecycle Policies<br/>Automated cleanup]
        end

        subgraph "Network Optimization"
            CDN[CloudFront CDN<br/>Reduced data transfer]
            VPCEndpoints[VPC Endpoints<br/>Eliminate NAT costs]
        end

        subgraph "Monitoring"
            CostExplorer[AWS Cost Explorer<br/>Usage analysis]
            Budgets[AWS Budgets<br/>Cost alerts]
        end
    end
```

---

## 🚀 **Deployment Process**

### **CI/CD Pipeline Architecture**

```mermaid
graph LR
    subgraph "Deployment Pipeline"
        Code[Code Changes<br/>GitHub Repository] --> Build[Docker Build<br/>Multi-architecture]
        Build --> Test[Test Execution<br/>115 test suite]
        Test --> Push[ECR Push<br/>Image versioning]
        Push --> Deploy[ECS Deployment<br/>Rolling update]
        Deploy --> Health[Health Checks<br/>Validation]
        Health --> Live[Live Traffic<br/>cybershield-ai.com]
    end

    %% Darker Arrow Styling
    linkStyle default stroke:#111,stroke-width:1px
```

### **Deployment Scripts**

| Script | Purpose | Location |
|--------|---------|----------|
| `aws_setup.sh` | Complete infrastructure setup | `scripts/` |
| `deploy_aws.py` | Application deployment | `scripts/` |
| `setup_ssl_only.sh` | SSL certificate configuration | `scripts/` |
| `fix_api_routing.sh` | Load balancer routing | `scripts/` |
| `update_alb_certificate.sh` | Certificate updates | `scripts/` |

---

## 🔄 **Disaster Recovery**

### **Backup Strategy**

```mermaid
graph TD
    subgraph "Backup & Recovery"
        subgraph "Database Backups"
            AutoBackup[Automated Daily Backups<br/>7-day retention]
            SnapBackup[Manual Snapshots<br/>Long-term storage]
        end

        subgraph "Application Backups"
            ECRVersions[ECR Image Versions<br/>Multiple image tags]
            ConfigBackup[Configuration Backup<br/>Infrastructure as Code]
        end

        subgraph "Recovery Procedures"
            PointInTime[Point-in-time Recovery<br/>RDS snapshots]
            BlueGreen[Blue/Green Deployment<br/>Zero-downtime updates]
        end
    end
```

### **High Availability Features**

- **Multi-AZ Deployment**: Database and cache in multiple availability zones
- **Auto Scaling**: Automatic scaling based on demand
- **Health Checks**: Continuous monitoring and automatic replacement
- **Load Balancing**: Traffic distribution across healthy instances
- **Backup & Recovery**: Automated backups with point-in-time recovery

---

This comprehensive AWS infrastructure provides enterprise-grade scalability, security, and reliability for the CyberShield AI platform, with optimized costs and automated management capabilities.