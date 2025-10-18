"""
Session Storage for CyberShield
Manages session-based context storage in Redis and PostgreSQL.
"""

from datetime import datetime
from typing import Any

from utils.logging_config import get_logger

logger = get_logger(__name__, component="session_storage")


class SessionStorage:
    """
    Manages session-based context storage for cross-request memory.

    Features:
    - Store and retrieve IOCs per session
    - Store analysis history for attack chain correlation
    - Merge IOCs across multiple requests
    - Optional PostgreSQL persistence for long-term storage
    """

    def __init__(self, memory=None, postgres_client=None):
        """
        Initialize SessionStorage.

        Args:
            memory: RedisSTM instance for short-term storage (30 min TTL)
            postgres_client: Optional PostgreSQL client for long-term storage
        """
        self.memory = memory
        self.postgres_client = postgres_client
        self.default_ttl = 1800  # 30 minutes

    async def store_iocs(
        self, session_id: str, iocs: dict[str, list[str]], merge: bool = True
    ) -> bool:
        """
        Store IOCs for a session in Redis.

        Args:
            session_id: Session identifier
            iocs: Dictionary of IOC types and values
                  e.g., {"ips": ["1.2.3.4"], "domains": ["evil.com"], "hashes": [...]}
            merge: If True, merge with existing IOCs. If False, replace.

        Returns:
            True if successful, False otherwise
        """
        if not self.memory or not session_id:
            logger.warning("Cannot store IOCs: missing memory or session_id")
            return False

        try:
            cache_key = f"cybershield:session:{session_id}:iocs"

            if merge:
                # Get existing IOCs and merge
                existing = await self.memory.get(cache_key) or {}
                merged_iocs = self._merge_iocs(existing, iocs)
                iocs_to_store = merged_iocs
            else:
                iocs_to_store = iocs

            # Store in Redis with TTL
            await self.memory.set(cache_key, iocs_to_store, ttl=self.default_ttl)

            logger.info(
                "Stored IOCs for session",
                session_id=session_id,
                ioc_count=sum(len(v) for v in iocs_to_store.values()),
                merge_mode=merge,
            )

            return True

        except Exception as e:
            logger.error("Failed to store IOCs", error=str(e), session_id=session_id)
            return False

    async def get_iocs(self, session_id: str) -> dict[str, list[str]] | None:
        """
        Retrieve IOCs for a session from Redis.

        Args:
            session_id: Session identifier

        Returns:
            Dictionary of IOCs or None if not found
        """
        if not self.memory or not session_id:
            return None

        try:
            cache_key = f"cybershield:session:{session_id}:iocs"
            iocs = await self.memory.get(cache_key)

            if iocs:
                logger.debug(
                    "Retrieved IOCs for session",
                    session_id=session_id,
                    ioc_count=sum(len(v) for v in iocs.values()),
                )
            else:
                logger.debug("No IOCs found for session", session_id=session_id)

            return iocs

        except Exception as e:
            logger.error("Failed to retrieve IOCs", error=str(e), session_id=session_id)
            return None

    async def store_analysis_event(
        self, session_id: str, analysis_result: dict[str, Any]
    ) -> bool:
        """
        Store an analysis event in session history.

        Args:
            session_id: Session identifier
            analysis_result: Complete analysis result dictionary

        Returns:
            True if successful, False otherwise
        """
        if not self.memory or not session_id:
            logger.warning("Cannot store analysis event: missing memory or session_id")
            return False

        try:
            cache_key = f"cybershield:session:{session_id}:history"

            # Create history entry
            history_entry = {
                "timestamp": datetime.now().isoformat(),
                "input_text": analysis_result.get("input_analysis", {}).get(
                    "original_text", ""
                ),
                "iocs_found": analysis_result.get("ioc_analysis", {}).get(
                    "extracted_iocs", {}
                ),
                "threats_detected": self._extract_threat_summary(
                    analysis_result.get("threat_analysis", {})
                ),
                "risk_level": self._calculate_risk_level(analysis_result),
                "summary": self._generate_entry_summary(analysis_result),
            }

            # Get existing history and append
            existing_history = await self.memory.get(cache_key) or []
            existing_history.append(history_entry)

            # Keep last 50 entries
            if len(existing_history) > 50:
                existing_history = existing_history[-50:]

            # Store with TTL
            await self.memory.set(cache_key, existing_history, ttl=self.default_ttl)

            logger.info(
                "Stored analysis event",
                session_id=session_id,
                history_count=len(existing_history),
            )

            return True

        except Exception as e:
            logger.error(
                "Failed to store analysis event", error=str(e), session_id=session_id
            )
            return False

    async def get_session_history(
        self, session_id: str, limit: int = 10
    ) -> list[dict[str, Any]]:
        """
        Retrieve session history from Redis.

        Args:
            session_id: Session identifier
            limit: Maximum number of recent events to return

        Returns:
            List of analysis events (most recent first)
        """
        if not self.memory or not session_id:
            return []

        try:
            cache_key = f"cybershield:session:{session_id}:history"
            history = await self.memory.get(cache_key) or []

            # Return most recent entries
            recent_history = history[-limit:] if len(history) > limit else history

            logger.debug(
                "Retrieved session history",
                session_id=session_id,
                event_count=len(recent_history),
            )

            return list(reversed(recent_history))  # Most recent first

        except Exception as e:
            logger.error(
                "Failed to retrieve session history",
                error=str(e),
                session_id=session_id,
            )
            return []

    async def store_pii_mapping(
        self, session_id: str, pii_mapping: dict[str, str]
    ) -> bool:
        """
        Store PII mapping for a session (masked values).

        Args:
            session_id: Session identifier
            pii_mapping: Dictionary mapping PII tokens to masked values

        Returns:
            True if successful, False otherwise
        """
        if not self.memory or not session_id:
            return False

        try:
            cache_key = f"cybershield:session:{session_id}:pii"
            await self.memory.set(cache_key, pii_mapping, ttl=self.default_ttl)

            logger.info(
                "Stored PII mapping",
                session_id=session_id,
                pii_count=len(pii_mapping),
            )

            return True

        except Exception as e:
            logger.error(
                "Failed to store PII mapping", error=str(e), session_id=session_id
            )
            return False

    async def get_pii_mapping(self, session_id: str) -> dict[str, str] | None:
        """
        Retrieve PII mapping for a session.

        Args:
            session_id: Session identifier

        Returns:
            Dictionary of PII mappings or None
        """
        if not self.memory or not session_id:
            return None

        try:
            cache_key = f"cybershield:session:{session_id}:pii"
            return await self.memory.get(cache_key)

        except Exception as e:
            logger.error(
                "Failed to retrieve PII mapping", error=str(e), session_id=session_id
            )
            return None

    async def clear_session(self, session_id: str) -> bool:
        """
        Clear all data for a session.

        Args:
            session_id: Session identifier

        Returns:
            True if successful, False otherwise
        """
        if not self.memory or not session_id:
            return False

        try:
            # Delete all session keys
            keys = [
                f"cybershield:session:{session_id}:iocs",
                f"cybershield:session:{session_id}:history",
                f"cybershield:session:{session_id}:pii",
            ]

            for key in keys:
                await self.memory.delete(key)

            logger.info("Cleared session data", session_id=session_id)
            return True

        except Exception as e:
            logger.error("Failed to clear session", error=str(e), session_id=session_id)
            return False

    # PostgreSQL methods (optional for Phase 6)

    async def persist_to_postgres(
        self, session_id: str, analysis_result: dict[str, Any]
    ) -> bool:
        """
        Persist analysis to PostgreSQL for long-term storage.

        Args:
            session_id: Session identifier
            analysis_result: Complete analysis result

        Returns:
            True if successful, False otherwise
        """
        if not self.postgres_client:
            logger.debug("PostgreSQL client not available, skipping persistence")
            return False

        # TODO: Implement PostgreSQL persistence in Phase 6
        logger.warning("PostgreSQL persistence not yet implemented")
        return False

    # Helper methods

    def _merge_iocs(
        self, existing: dict[str, list[str]], new: dict[str, list[str]]
    ) -> dict[str, list[str]]:
        """
        Merge new IOCs with existing ones, removing duplicates while preserving order.

        IMPORTANT: Chronological order is preserved so the most recent IOC is always last.
        This is critical for pronoun resolution ("same IP" → most recent IP).
        """
        merged = existing.copy()

        for ioc_type, values in new.items():
            if ioc_type in merged:
                # Merge while preserving insertion order and removing duplicates
                combined = merged[ioc_type] + values
                seen = set()
                # Deduplicate while maintaining order: keep first occurrence
                merged[ioc_type] = [
                    x for x in combined if not (x in seen or seen.add(x))
                ]
            else:
                merged[ioc_type] = values

        return merged

    def _extract_threat_summary(self, threat_analysis: dict) -> dict[str, int]:
        """Extract threat count summary from analysis."""
        return {
            "high_risk": threat_analysis.get("high_risk_count", 0),
            "medium_risk": threat_analysis.get("medium_risk_count", 0),
            "low_risk": threat_analysis.get("low_risk_count", 0),
            "total": threat_analysis.get("total_analyzed", 0),
        }

    def _calculate_risk_level(self, analysis_result: dict) -> str:
        """Calculate overall risk level for the analysis."""
        threat_analysis = analysis_result.get("threat_analysis", {})
        high_risk = threat_analysis.get("high_risk_count", 0)
        medium_risk = threat_analysis.get("medium_risk_count", 0)

        if high_risk > 0:
            return "high"
        elif medium_risk > 0:
            return "medium"
        else:
            return "low"

    def _generate_entry_summary(self, analysis_result: dict) -> str:
        """Generate a brief summary of the analysis."""
        ioc_analysis = analysis_result.get("ioc_analysis", {})
        threat_analysis = analysis_result.get("threat_analysis", {})

        ioc_count = ioc_analysis.get("ioc_count", 0)
        high_risk = threat_analysis.get("high_risk_count", 0)
        medium_risk = threat_analysis.get("medium_risk_count", 0)

        if high_risk > 0:
            return f"{ioc_count} IOCs detected, {high_risk} high-risk threats"
        elif medium_risk > 0:
            return f"{ioc_count} IOCs detected, {medium_risk} medium-risk threats"
        elif ioc_count > 0:
            return f"{ioc_count} IOCs detected, no significant threats"
        else:
            return "No IOCs or threats detected"
