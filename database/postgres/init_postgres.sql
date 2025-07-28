-- PostgreSQL initialization script for CyberShield
-- Creates database schema for PII storage and other features

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create PII sessions table
CREATE TABLE IF NOT EXISTS pii_sessions (
    session_id VARCHAR(64) PRIMARY KEY,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    metadata JSONB
);

-- Create PII mappings table
CREATE TABLE IF NOT EXISTS pii_mappings (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(64) REFERENCES pii_sessions(session_id) ON DELETE CASCADE,
    mask_token VARCHAR(32) NOT NULL,
    original_value TEXT NOT NULL,
    pii_type VARCHAR(32) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    hash_value VARCHAR(64) NOT NULL,
    UNIQUE(session_id, mask_token)
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_pii_mappings_session ON pii_mappings(session_id);
CREATE INDEX IF NOT EXISTS idx_pii_mappings_hash ON pii_mappings(hash_value);
CREATE INDEX IF NOT EXISTS idx_pii_sessions_expires ON pii_sessions(expires_at);

-- Create audit log table for PII access
CREATE TABLE IF NOT EXISTS pii_audit_log (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(64),
    action VARCHAR(32) NOT NULL,
    mask_token VARCHAR(32),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address INET,
    user_agent TEXT
);

-- Create indexes for audit log
CREATE INDEX IF NOT EXISTS idx_pii_audit_session ON pii_audit_log(session_id);
CREATE INDEX IF NOT EXISTS idx_pii_audit_timestamp ON pii_audit_log(timestamp);

-- Create function to automatically cleanup expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_pii_sessions()
RETURNS void AS $$
BEGIN
    DELETE FROM pii_mappings
    WHERE session_id IN (
        SELECT session_id FROM pii_sessions
        WHERE expires_at < CURRENT_TIMESTAMP
    );

    DELETE FROM pii_sessions
    WHERE expires_at < CURRENT_TIMESTAMP;
END;
$$ LANGUAGE plpgsql;

-- Create a scheduled job to cleanup expired sessions (if pg_cron is available)
-- SELECT cron.schedule('cleanup-expired-pii', '0 2 * * *', 'SELECT cleanup_expired_pii_sessions();');

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;

-- Insert initial data or configuration if needed
-- This can be expanded based on requirements

COMMENT ON TABLE pii_sessions IS 'PII processing sessions with expiration';
COMMENT ON TABLE pii_mappings IS 'Secure mappings between mask tokens and original PII values';
COMMENT ON TABLE pii_audit_log IS 'Audit trail for PII access and operations';