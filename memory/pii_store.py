# Secure PII Mapping Store with Redis cache and PostgreSQL history
import json
import logging
import hashlib
import os
from datetime import datetime, timedelta
from typing import Dict, Optional
import redis
import psycopg2

logger = logging.getLogger(__name__)

class PIISecureStore:
    """Secure PII mapping store with Redis cache and PostgreSQL history"""

    def __init__(self, redis_host=None, redis_port=None,
                 pg_host=None, pg_port=None, pg_db=None,
                 pg_user=None, pg_password=None):
        """
        Initialize PII store with Redis cache and PostgreSQL history

        Args:
            redis_host: Redis host for caching (defaults to env REDIS_HOST or localhost)
            redis_port: Redis port (defaults to env REDIS_PORT or 6379)
            pg_host: PostgreSQL host for long-term storage (defaults to env POSTGRES_HOST or localhost)
            pg_port: PostgreSQL port (defaults to env POSTGRES_PORT or 5432)
            pg_db: PostgreSQL database name (defaults to env POSTGRES_DB or cybershield)
            pg_user: PostgreSQL username (defaults to env POSTGRES_USER or postgres)
            pg_password: PostgreSQL password (defaults to env POSTGRES_PASSWORD or postgres)
        """
        # Load configuration from environment variables with fallbacks
        self.redis_host = redis_host or os.getenv('REDIS_HOST', 'localhost')
        self.redis_port = int(redis_port or os.getenv('REDIS_PORT', 6379))
        self.pg_host = pg_host or os.getenv('POSTGRES_HOST', 'localhost')
        self.pg_port = int(pg_port or os.getenv('POSTGRES_PORT', 5432))
        self.pg_db = pg_db or os.getenv('POSTGRES_DB', 'cybershield')
        self.pg_user = pg_user or os.getenv('POSTGRES_USER', 'postgres')
        self.pg_password = pg_password or os.getenv('POSTGRES_PASSWORD', 'postgres')
        self.redis_cache = None
        self.pg_conn = None
        self.session_id = None

        # Initialize Redis cache
        try:
            self.redis_cache = redis.Redis(
                host=self.redis_host,
                port=self.redis_port,
                db=1,  # Use separate DB for PII cache
                decode_responses=True
            )
            self.redis_cache.ping()
            logger.info(f"Connected to Redis for PII caching at {self.redis_host}:{self.redis_port}")
        except Exception as e:
            logger.error(f"Failed to connect to Redis at {self.redis_host}:{self.redis_port}: {e}")
            self.redis_cache = None

        # Initialize PostgreSQL
        try:
            self.pg_conn = psycopg2.connect(
                host=self.pg_host,
                port=self.pg_port,
                database=self.pg_db,
                user=self.pg_user,
                password=self.pg_password
            )
            self._create_pii_tables()
            logger.info(f"Connected to PostgreSQL for PII history at {self.pg_host}:{self.pg_port}")
        except Exception as e:
            logger.error(f"Failed to connect to PostgreSQL at {self.pg_host}:{self.pg_port}: {e}")
            self.pg_conn = None

    def _create_pii_tables(self):
        """Create PostgreSQL tables for PII storage"""
        if not self.pg_conn:
            return

        try:
            with self.pg_conn.cursor() as cursor:
                # PII sessions table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS pii_sessions (
                        session_id VARCHAR(64) PRIMARY KEY,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP,
                        metadata JSONB
                    )
                """)

                # PII mappings table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS pii_mappings (
                        id SERIAL PRIMARY KEY,
                        session_id VARCHAR(64) REFERENCES pii_sessions(session_id),
                        mask_token VARCHAR(32) NOT NULL,
                        original_value TEXT NOT NULL,
                        pii_type VARCHAR(32) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        hash_value VARCHAR(64) NOT NULL,
                        UNIQUE(session_id, mask_token)
                    )
                """)

                # Create indexes
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_pii_mappings_session
                    ON pii_mappings(session_id)
                """)

                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_pii_mappings_hash
                    ON pii_mappings(hash_value)
                """)

                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_pii_sessions_expires
                    ON pii_sessions(expires_at)
                """)

            self.pg_conn.commit()
            logger.info("PII tables created successfully")

        except Exception as e:
            logger.error(f"Failed to create PII tables: {e}")
            self.pg_conn.rollback()

    def start_session(self, session_id: str, ttl_hours: int = 24, metadata: Dict = None):
        """Start a new PII session"""
        try:
            # Set session in Redis cache
            if self.redis_cache:
                session_data = {
                    "session_id": session_id,
                    "created_at": datetime.now().isoformat(),
                    "expires_at": (datetime.now() + timedelta(hours=ttl_hours)).isoformat(),
                    "metadata": metadata or {}
                }
                self.redis_cache.setex(
                    f"pii_session:{session_id}",
                    ttl_hours * 3600,
                    json.dumps(session_data)
                )

            # Store session in PostgreSQL
            if self.pg_conn:
                with self.pg_conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO pii_sessions (session_id, expires_at, metadata)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (session_id)
                        DO UPDATE SET expires_at = EXCLUDED.expires_at, metadata = EXCLUDED.metadata
                    """, (
                        session_id,
                        datetime.now() + timedelta(hours=ttl_hours),
                        json.dumps(metadata or {})
                    ))
                self.pg_conn.commit()

            self.session_id = session_id
            logger.info(f"Started PII session: {session_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to start PII session: {e}")
            return False

    def store_mapping(self, mask_token: str, original_value: str, pii_type: str = "unknown") -> bool:
        """Store PII mapping securely"""
        if not self.session_id:
            logger.error("No active session")
            return False

        try:
            # Hash the original value for security
            hash_value = hashlib.sha256(original_value.encode()).hexdigest()

            # Store in Redis cache
            if self.redis_cache:
                cache_key = f"pii_mapping:{self.session_id}:{mask_token}"
                mapping_data = {
                    "original_value": original_value,
                    "pii_type": pii_type,
                    "hash_value": hash_value,
                    "created_at": datetime.now().isoformat()
                }
                self.redis_cache.setex(
                    cache_key,
                    3600,  # 1 hour cache
                    json.dumps(mapping_data)
                )

            # Store in PostgreSQL
            if self.pg_conn:
                with self.pg_conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO pii_mappings (session_id, mask_token, original_value, pii_type, hash_value)
                        VALUES (%s, %s, %s, %s, %s)
                        ON CONFLICT (session_id, mask_token)
                        DO UPDATE SET original_value = EXCLUDED.original_value,
                                    pii_type = EXCLUDED.pii_type,
                                    hash_value = EXCLUDED.hash_value
                    """, (self.session_id, mask_token, original_value, pii_type, hash_value))
                self.pg_conn.commit()

            logger.info(f"Stored PII mapping: {mask_token} -> {pii_type}")
            return True

        except Exception as e:
            logger.error(f"Failed to store PII mapping: {e}")
            return False

    def get_mapping(self, mask_token: str) -> Optional[str]:
        """Retrieve original value for mask token"""
        if not self.session_id:
            return None

        try:
            # Try Redis cache first
            if self.redis_cache:
                cache_key = f"pii_mapping:{self.session_id}:{mask_token}"
                cached_data = self.redis_cache.get(cache_key)
                if cached_data:
                    mapping_data = json.loads(cached_data)
                    return mapping_data.get("original_value")

            # Fallback to PostgreSQL
            if self.pg_conn:
                with self.pg_conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT original_value FROM pii_mappings
                        WHERE session_id = %s AND mask_token = %s
                    """, (self.session_id, mask_token))
                    result = cursor.fetchone()
                    if result:
                        return result[0]

            return None

        except Exception as e:
            logger.error(f"Failed to retrieve PII mapping: {e}")
            return None

    def get_session_mappings(self) -> Dict[str, str]:
        """Get all mappings for current session"""
        if not self.session_id:
            return {}

        try:
            mappings = {}

            # Try Redis cache first
            if self.redis_cache:
                pattern = f"pii_mapping:{self.session_id}:*"
                keys = self.redis_cache.keys(pattern)
                for key in keys:
                    mask_token = key.split(":")[-1]
                    cached_data = self.redis_cache.get(key)
                    if cached_data:
                        mapping_data = json.loads(cached_data)
                        mappings[mask_token] = mapping_data.get("original_value")

            # Fallback to PostgreSQL
            if self.pg_conn and not mappings:
                with self.pg_conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT mask_token, original_value FROM pii_mappings
                        WHERE session_id = %s
                    """, (self.session_id,))
                    for row in cursor.fetchall():
                        mappings[row[0]] = row[1]

            return mappings

        except Exception as e:
            logger.error(f"Failed to get session mappings: {e}")
            return {}

    def cleanup_expired_sessions(self):
        """Clean up expired sessions and mappings"""
        try:
            if self.pg_conn:
                with self.pg_conn.cursor() as cursor:
                    # Delete expired sessions and their mappings
                    cursor.execute("""
                        DELETE FROM pii_mappings
                        WHERE session_id IN (
                            SELECT session_id FROM pii_sessions
                            WHERE expires_at < CURRENT_TIMESTAMP
                        )
                    """)

                    cursor.execute("""
                        DELETE FROM pii_sessions
                        WHERE expires_at < CURRENT_TIMESTAMP
                    """)

                self.pg_conn.commit()
                logger.info("Cleaned up expired PII sessions")

        except Exception as e:
            logger.error(f"Failed to cleanup expired sessions: {e}")

    def end_session(self):
        """End current session"""
        if self.session_id:
            logger.info(f"Ended PII session: {self.session_id}")
            self.session_id = None

    def is_connected(self) -> bool:
        """Check if both Redis and PostgreSQL are connected"""
        redis_ok = self.redis_cache and self.redis_cache.ping()
        pg_ok = self.pg_conn and not self.pg_conn.closed
        return redis_ok and pg_ok