# Database Configuration

This directory contains database configuration files and scripts for CyberShield.

## Structure

```
database/
├── postgres/
│   └── init_postgres.sql    # PostgreSQL initialization script
└── README.md               # This file
```

## PostgreSQL Setup

The `postgres/init_postgres.sql` file contains:
- Database schema creation
- PII storage tables
- Session management structures
- Required extensions and indexes

This script is automatically executed when the PostgreSQL container starts for the first time.

## Usage

The database is configured in `docker-compose.yaml` and will be automatically initialized when you run:

```bash
docker-compose up -d postgres
```

## Connection Details

- **Host**: localhost
- **Port**: 5432
- **Database**: cybershield
- **Username**: postgres
- **Password**: in env

## Tables Created

1. **pii_sessions** - PII detection session management
2. **pii_mappings** - Mapping between masked tokens and original values
3. **analysis_logs** - Analysis request logging
4. **threat_intel** - Threat intelligence caching

## Notes

- The database uses persistent volumes for data retention
- Health checks are configured to ensure database availability
- All sensitive data is properly encrypted and indexed