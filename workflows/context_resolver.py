"""
Context Resolver for CyberShield
Resolves pronoun references and enriches input text with session context.
"""

import re
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
from utils.logging_config import get_logger

logger = get_logger(__name__, component="context_resolver")


class ContextResolver:
    """
    Resolves context references and enriches user input with session data.

    Handles pronouns like:
    - "same IP", "that IP", "this IP"
    - "same domain", "that domain"
    - "same hash", "that hash"
    - "the user", "same user"
    - "entire attack chain", "full timeline"
    """

    def __init__(self, memory=None, llm_client=None):
        """
        Initialize ContextResolver.

        Args:
            memory: RedisSTM instance for session storage
            llm_client: Optional LLM client for complex context resolution
        """
        self.memory = memory
        self.llm_client = llm_client

        # Pronoun patterns for different IOC types
        self.pronoun_patterns = {
            "ip": [
                r"\b(same|that|this|the)\s+(ip|address|host)\b",
                r"\bsame\s+ip\s+address\b",
                r"\bthat\s+ip\b",
                r"\bthis\s+host\b",
            ],
            "domain": [
                r"\b(same|that|this|the)\s+(domain|site|website|url)\b",
                r"\bsame\s+domain\b",
                r"\bthat\s+site\b",
            ],
            "hash": [
                r"\b(same|that|this|the)\s+(hash|file|malware|sample)\b",
                r"\bsame\s+file\s+hash\b",
                r"\bthat\s+malware\b",
            ],
            "email": [
                r"\b(same|that|this|the)\s+(user|email|account)\b",
                r"\bsame\s+user\b",
                r"\bthat\s+account\b",
            ],
            "attack_chain": [
                r"\b(entire|full|complete|whole)\s+(attack|chain|sequence|timeline)\b",
                r"\bsummarize\s+(everything|all|the\s+activity)\b",
                r"\bwhat\s+happened\b",
                r"\battack\s+progression\b",
            ],
        }

    async def resolve_and_enrich(
        self, input_text: str, session_id: Optional[str] = None
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Main method to resolve context references and enrich input.

        Args:
            input_text: User's original input text
            session_id: Session ID for context retrieval

        Returns:
            Tuple of (enriched_text, context_metadata)
        """
        logger.info(
            "Context resolution started",
            input_length=len(input_text),
            has_session=bool(session_id),
        )

        # Initialize metadata
        context_metadata = {
            "original_text": input_text,
            "enriched": False,
            "context_used": {},
            "resolution_method": None,
            "timestamp": datetime.now().isoformat(),
        }

        # Early return if no session ID
        if not session_id:
            logger.debug("No session_id provided, skipping context resolution")
            return input_text, context_metadata

        # Check if input needs context resolution
        needs_context = self._detect_context_references(input_text)
        if not needs_context:
            logger.debug("No context references detected")
            return input_text, context_metadata

        logger.info("Context references detected", reference_types=needs_context)

        # Fetch session context from Redis
        session_context = await self._fetch_session_context(session_id)
        if not session_context:
            logger.warning(
                "No session context found",
                session_id=session_id,
                needs_context=needs_context,
            )
            return input_text, context_metadata

        # Resolve pronouns and enrich text
        enriched_text = input_text
        context_used = {}

        # Try pattern-based resolution first (fast)
        enriched_text, context_used = self._resolve_pronouns(
            enriched_text, session_context, needs_context
        )

        # If pattern-based resolution failed and LLM is available, use LLM
        if enriched_text == input_text and self.llm_client:
            logger.info("Pattern-based resolution unchanged, trying LLM resolution")
            enriched_text, context_used = await self._use_llm_resolution(
                input_text, session_context
            )

        # Update metadata
        if enriched_text != input_text:
            context_metadata["enriched"] = True
            context_metadata["enriched_text"] = enriched_text
            context_metadata["context_used"] = context_used
            context_metadata["resolution_method"] = (
                "llm" if self.llm_client and context_used else "pattern"
            )

            logger.info(
                "Context resolution successful",
                original_length=len(input_text),
                enriched_length=len(enriched_text),
                context_items=len(context_used),
            )
        else:
            logger.debug("Context resolution did not modify input")

        return enriched_text, context_metadata

    def _detect_context_references(self, text: str) -> List[str]:
        """
        Detect if input text contains context references.

        Args:
            text: Input text to analyze

        Returns:
            List of detected reference types
        """
        detected = []
        text_lower = text.lower()

        for ref_type, patterns in self.pronoun_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    detected.append(ref_type)
                    break  # One match per type is enough

        return detected

    async def _fetch_session_context(
        self, session_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Fetch session context from Redis.

        Args:
            session_id: Session ID to fetch

        Returns:
            Dictionary with IOCs and history, or None
        """
        if not self.memory:
            logger.warning("No memory instance available for context fetching")
            return None

        try:
            # Fetch IOCs
            iocs_key = f"cybershield:session:{session_id}:iocs"
            iocs = await self.memory.get(iocs_key)

            # Fetch history
            history_key = f"cybershield:session:{session_id}:history"
            history = await self.memory.get(history_key)

            if not iocs and not history:
                logger.debug("No IOCs or history found for session", session_id=session_id)
                return None

            context = {"iocs": iocs or {}, "history": history or []}

            logger.debug(
                "Session context fetched",
                session_id=session_id,
                ioc_count=sum(len(v) for v in iocs.values()) if iocs else 0,
                history_count=len(history) if history else 0,
            )

            return context

        except Exception as e:
            logger.error("Failed to fetch session context", error=str(e), session_id=session_id)
            return None

    def _resolve_pronouns(
        self, text: str, session_context: Dict[str, Any], reference_types: List[str]
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Resolve pronoun references using pattern matching.

        Args:
            text: Input text with pronouns
            session_context: Context from Redis
            reference_types: Detected reference types

        Returns:
            Tuple of (enriched_text, context_used)
        """
        enriched_text = text
        context_used = {}
        iocs = session_context.get("iocs", {})

        # Resolve IP references
        if "ip" in reference_types and iocs.get("ips"):
            latest_ip = iocs["ips"][-1]  # Most recent IP
            for pattern in self.pronoun_patterns["ip"]:
                if re.search(pattern, enriched_text, re.IGNORECASE):
                    enriched_text = re.sub(
                        pattern, latest_ip, enriched_text, flags=re.IGNORECASE, count=1
                    )
                    context_used["ip"] = latest_ip
                    logger.debug(f"Resolved IP reference to {latest_ip}")
                    break

        # Resolve domain references
        if "domain" in reference_types and iocs.get("domains"):
            latest_domain = iocs["domains"][-1]
            for pattern in self.pronoun_patterns["domain"]:
                if re.search(pattern, enriched_text, re.IGNORECASE):
                    enriched_text = re.sub(
                        pattern, latest_domain, enriched_text, flags=re.IGNORECASE, count=1
                    )
                    context_used["domain"] = latest_domain
                    logger.debug(f"Resolved domain reference to {latest_domain}")
                    break

        # Resolve hash references
        if "hash" in reference_types and iocs.get("hashes"):
            latest_hash = iocs["hashes"][-1]
            for pattern in self.pronoun_patterns["hash"]:
                if re.search(pattern, enriched_text, re.IGNORECASE):
                    enriched_text = re.sub(
                        pattern, f"hash {latest_hash}", enriched_text, flags=re.IGNORECASE, count=1
                    )
                    context_used["hash"] = latest_hash
                    logger.debug(f"Resolved hash reference to {latest_hash}")
                    break

        # Resolve email/user references
        if "email" in reference_types and iocs.get("emails"):
            latest_email = iocs["emails"][-1]
            for pattern in self.pronoun_patterns["email"]:
                if re.search(pattern, enriched_text, re.IGNORECASE):
                    enriched_text = re.sub(
                        pattern, latest_email, enriched_text, flags=re.IGNORECASE, count=1
                    )
                    context_used["email"] = latest_email
                    logger.debug(f"Resolved email reference to {latest_email}")
                    break

        # Handle attack chain summarization requests
        if "attack_chain" in reference_types:
            history = session_context.get("history", [])
            if history:
                # Add context about number of events
                summary_context = f"Based on {len(history)} previous security events: "
                enriched_text = summary_context + enriched_text
                context_used["attack_chain"] = {
                    "event_count": len(history),
                    "events": history,
                }
                logger.debug(f"Added attack chain context with {len(history)} events")

        return enriched_text, context_used

    async def _use_llm_resolution(
        self, text: str, session_context: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Use LLM for complex context resolution (fallback).

        Args:
            text: Input text with references
            session_context: Context from Redis

        Returns:
            Tuple of (enriched_text, context_used)
        """
        if not self.llm_client:
            return text, {}

        try:
            # Prepare context summary for LLM
            iocs = session_context.get("iocs", {})
            history = session_context.get("history", [])

            context_summary = "Previous context:\n"
            if iocs.get("ips"):
                context_summary += f"- IPs: {', '.join(iocs['ips'][-3:])}\n"
            if iocs.get("domains"):
                context_summary += f"- Domains: {', '.join(iocs['domains'][-3:])}\n"
            if iocs.get("hashes"):
                context_summary += f"- Hashes: {', '.join(iocs['hashes'][-2:])}\n"
            if history:
                context_summary += f"- {len(history)} previous security events\n"

            # Create LLM prompt
            prompt = f"""{context_summary}

User query: "{text}"

Task: Resolve any pronoun references (e.g., "same IP", "that domain") to the actual values from context.
If the query asks for a summary or timeline, keep it as is but note what context is needed.

Return only the resolved query text, nothing else."""

            # Call LLM (implementation depends on LLM client type)
            # This is a placeholder - actual implementation would use the LLM client
            response = await self._call_llm(prompt)

            if response and response != text:
                logger.info("LLM resolution successful")
                return response, {"llm_enriched": True, "original": text}

        except Exception as e:
            logger.error("LLM resolution failed", error=str(e))

        return text, {}

    async def _call_llm(self, prompt: str) -> Optional[str]:
        """
        Call LLM with the given prompt.

        Args:
            prompt: Prompt for LLM

        Returns:
            LLM response or None
        """
        # Placeholder - actual implementation depends on LLM client
        # This would use OpenAI, Anthropic, or other LLM provider
        logger.debug("LLM resolution called but not yet implemented")
        return None
