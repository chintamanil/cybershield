# PIIAgent detects and masks PII using regex and stores mapping securely
import re
import uuid
import logging
from typing import Tuple, Dict
from memory.pii_store import PIISecureStore

logger = logging.getLogger(__name__)

class PIIAgent:
    def __init__(self, memory=None):
        self.memory = memory  # Redis connection for backward compatibility
        self.pii_store = PIISecureStore()  # Secure PII store
        self.current_session = None

    async def start_session(self, session_id: str = None) -> str:
        """Start a new PII processing session"""
        if not session_id:
            session_id = str(uuid.uuid4())

        if self.pii_store.start_session(session_id):
            self.current_session = session_id
            logger.info(f"Started PII session: {session_id}")
            return session_id
        else:
            logger.error("Failed to start PII session")
            return None

    async def mask_pii(self, text: str, session_id: str = None) -> Tuple[str, Dict]:
        """
        Detect and mask PII in text

        Args:
            text: Input text to process
            session_id: Optional session ID, creates new if not provided

        Returns:
            Tuple of (masked_text, mapping_dict)
        """
        if not session_id and not self.current_session:
            session_id = await self.start_session()
        elif session_id:
            self.current_session = session_id
            await self.start_session(session_id)

        # Enhanced PII patterns
        patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'ipv4': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
            'phone': r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
            'mac_address': r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b'
        }

        masked_text = text
        mapping = {}
        mask_counter = 0

        for pii_type, pattern in patterns.items():
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                original_value = match.group()
                mask_token = f"[MASK_{mask_counter}]"

                # Replace in masked text
                masked_text = masked_text.replace(original_value, mask_token)

                # Store mapping securely
                if self.pii_store.store_mapping(mask_token, original_value, pii_type):
                    mapping[mask_token] = {
                        "original": original_value,
                        "type": pii_type,
                        "position": match.span()
                    }
                    mask_counter += 1
                else:
                    logger.warning(f"Failed to store PII mapping for {mask_token}")

        # Backward compatibility with old memory system
        if self.memory:
            for token, data in mapping.items():
                await self.memory.set(token, data["original"])

        logger.info(f"Masked {len(mapping)} PII items in session {self.current_session}")
        return masked_text, mapping

    async def unmask_text(self, masked_text: str, session_id: str = None) -> str:
        """Unmask text using stored mappings"""
        if not session_id:
            session_id = self.current_session

        if not session_id:
            logger.error("No session ID provided for unmasking")
            return masked_text

        # Get all mappings for session
        mappings = self.pii_store.get_session_mappings()

        # Replace mask tokens with original values
        unmasked_text = masked_text
        for mask_token, original_value in mappings.items():
            unmasked_text = unmasked_text.replace(mask_token, original_value)

        return unmasked_text

    async def get_mapping(self, mask_token: str, session_id: str = None) -> str:
        """Get original value for a mask token"""
        if not session_id:
            session_id = self.current_session

        if not session_id:
            return None

        return self.pii_store.get_mapping(mask_token)

    async def end_session(self, session_id: str = None):
        """End current PII session"""
        if session_id or self.current_session:
            self.pii_store.end_session()
            self.current_session = None
            logger.info(f"Ended PII session: {session_id or self.current_session}")

    async def cleanup_expired_sessions(self):
        """Clean up expired PII sessions"""
        self.pii_store.cleanup_expired_sessions()
