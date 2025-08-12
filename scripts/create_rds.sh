#!/bin/bash
# Create RDS PostgreSQL Database for CyberShield

set -e

echo "🗄️ Creating RDS PostgreSQL Database"
echo "===================================="

# Load environment variables from the correct path
if [ -f "../.env.aws" ]; then
    source ../.env.aws
elif [ -f ".env.aws" ]; then
    source .env.aws
else
    echo "❌ Error: .env.aws file not found"
    exit 1
fi

echo "Creating DB subnet group..."
DB_SUBNET_GROUP_NAME="${PROJECT_NAME:-cybershield}-db-subnet-group"

# Check if DB subnet group already exists
if aws rds describe-db-subnet-groups --db-subnet-group-name "$DB_SUBNET_GROUP_NAME" >/dev/null 2>&1; then
    echo "✅ DB subnet group already exists: $DB_SUBNET_GROUP_NAME"
else
    # Create DB subnet group
    aws rds create-db-subnet-group \
        --db-subnet-group-name "$DB_SUBNET_GROUP_NAME" \
        --db-subnet-group-description "Database subnet group for CyberShield" \
        --subnet-ids "$DB_SUBNET_1" "$DB_SUBNET_2" \
        --tags Key=Name,Value="$DB_SUBNET_GROUP_NAME" \
               Key=Project,Value=cybershield
    
    echo "✅ DB subnet group created: $DB_SUBNET_GROUP_NAME"
fi

echo "Creating RDS PostgreSQL instance..."
DB_INSTANCE_ID="${PROJECT_NAME:-cybershield}-postgres"
DB_NAME="cybershield"
DB_USERNAME="cybershield"
DB_PASSWORD="CyberShield2024!SecurePass"

# Create RDS instance
aws rds create-db-instance \
    --db-instance-identifier "$DB_INSTANCE_ID" \
    --db-instance-class "db.t3.micro" \
    --engine "postgres" \
    --engine-version "15.13" \
    --master-username "$DB_USERNAME" \
    --master-user-password "$DB_PASSWORD" \
    --db-name "$DB_NAME" \
    --allocated-storage 20 \
    --storage-type "gp2" \
    --storage-encrypted \
    --vpc-security-group-ids "$RDS_SECURITY_GROUP" \
    --db-subnet-group-name "$DB_SUBNET_GROUP_NAME" \
    --backup-retention-period 7 \
    --no-deletion-protection \
    --tags Key=Name,Value="$DB_INSTANCE_ID" \
           Key=Project,Value=cybershield \
           Key=Environment,Value=production

echo "✅ RDS instance creation initiated: $DB_INSTANCE_ID"
echo "⏳ Waiting for database to be available (this may take 5-10 minutes)..."

# Wait for database to be available
aws rds wait db-instance-available --db-instance-identifier "$DB_INSTANCE_ID"

# Get the RDS endpoint
RDS_ENDPOINT=$(aws rds describe-db-instances \
    --db-instance-identifier "$DB_INSTANCE_ID" \
    --query 'DBInstances[0].Endpoint.Address' \
    --output text)

echo "✅ Database is now available!"
echo "📋 Database Details:"
echo "   Instance ID: $DB_INSTANCE_ID"
echo "   Endpoint: $RDS_ENDPOINT"
echo "   Database: $DB_NAME"
echo "   Username: $DB_USERNAME"
echo "   Port: 5432"

# Update .env.aws with RDS information
echo ""
echo "💾 Updating .env.aws with database configuration..."

# Add RDS configuration to .env.aws
if [ -f "../.env.aws" ]; then
    ENV_FILE="../.env.aws"
elif [ -f ".env.aws" ]; then
    ENV_FILE=".env.aws"
else
    echo "❌ Error: .env.aws file not found for updating"
    exit 1
fi

cat >> "$ENV_FILE" << EOF

# RDS PostgreSQL Configuration
RDS_ENDPOINT=$RDS_ENDPOINT
RDS_PORT=5432
RDS_DATABASE=$DB_NAME
RDS_USERNAME=$DB_USERNAME
RDS_PASSWORD=$DB_PASSWORD
DB_SUBNET_GROUP=$DB_SUBNET_GROUP_NAME
RDS_INSTANCE_ID=$DB_INSTANCE_ID
EOF

echo "✅ Configuration updated in .env.aws"
echo ""
echo "🔄 Next Steps:"
echo "1. Create Redis cluster: ./scripts/create_redis.sh"
echo "2. Create ECS cluster: ./scripts/create_ecs.sh"
echo "3. Deploy application: ./scripts/deploy_app.sh"
echo ""
echo "⚠️  Database Password: $DB_PASSWORD"
echo "   Store this password securely - it's needed for application configuration"