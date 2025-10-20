"""
User Feedback Component for Streamlit Frontend.

Provides thumbs up/down feedback collection with:
- Simple feedback buttons
- Optional text feedback
- Redis storage for analytics
- Feedback history tracking
"""

import asyncio
import json
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

import redis.asyncio as redis
import streamlit as st

from utils.logging_config import get_security_logger

logger = get_security_logger('user_feedback')


class FeedbackCollector:
    """
    Feedback collection and storage for user responses.

    Stores feedback in Redis for analytics and improvement tracking.
    """

    def __init__(
        self,
        redis_host: str = 'localhost',
        redis_port: int = 6379,
        redis_db: int = 0,
    ):
        """
        Initialize feedback collector.

        Args:
            redis_host: Redis host
            redis_port: Redis port
            redis_db: Redis database number
        """
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.redis_db = redis_db
        self.redis_client = None

    async def connect(self) -> None:
        """Connect to Redis"""
        if not self.redis_client:
            self.redis_client = await redis.Redis(
                host=self.redis_host,
                port=self.redis_port,
                db=self.redis_db,
                decode_responses=True,
            )
        logger.info('feedback_collector_connected')

    async def close(self) -> None:
        """Close Redis connection"""
        if self.redis_client:
            await self.redis_client.close()
        logger.info('feedback_collector_closed')

    async def store_feedback(
        self,
        feedback_id: str,
        user_id: str,
        query: str,
        response: str,
        rating: str,  # 'positive' or 'negative'
        feedback_text: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Store user feedback in Redis.

        Args:
            feedback_id: Unique feedback identifier
            user_id: User identifier
            query: Original query text
            response: System response
            rating: 'positive' or 'negative'
            feedback_text: Optional feedback text
            metadata: Additional metadata (e.g., model version, endpoint)

        Returns:
            True if successfully stored
        """
        if not self.redis_client:
            await self.connect()

        feedback_data = {
            'feedback_id': feedback_id,
            'user_id': user_id,
            'query': query,
            'response': response[:500],  # Truncate long responses
            'rating': rating,
            'feedback_text': feedback_text or '',
            'timestamp': datetime.now().isoformat(),
            'metadata': metadata or {},
        }

        try:
            # Store individual feedback
            key = f'feedback:{feedback_id}'
            await self.redis_client.setex(
                key,
                60 * 60 * 24 * 90,  # Keep for 90 days
                json.dumps(feedback_data),
            )

            # Add to rating-specific sorted set (for analytics)
            rating_key = f'feedback:{rating}:list'
            await self.redis_client.zadd(
                rating_key,
                {feedback_id: datetime.now().timestamp()},
            )

            # Add to user's feedback history
            user_key = f'feedback:user:{user_id}'
            await self.redis_client.zadd(
                user_key,
                {feedback_id: datetime.now().timestamp()},
            )

            # Increment rating counters
            counter_key = f'feedback:stats:{rating}'
            await self.redis_client.incr(counter_key)

            logger.info(
                'feedback_stored',
                feedback_id=feedback_id,
                user_id=user_id,
                rating=rating,
            )

            return True

        except Exception as e:
            logger.error('feedback_storage_failed', error=str(e))
            return False

    async def get_feedback_stats(self) -> Dict[str, Any]:
        """
        Get aggregate feedback statistics.

        Returns:
            Dictionary with feedback stats
        """
        if not self.redis_client:
            await self.connect()

        try:
            positive_count = await self.redis_client.get('feedback:stats:positive')
            negative_count = await self.redis_client.get('feedback:stats:negative')

            positive_count = int(positive_count) if positive_count else 0
            negative_count = int(negative_count) if negative_count else 0
            total_count = positive_count + negative_count

            satisfaction_rate = (
                (positive_count / total_count * 100) if total_count > 0 else 0
            )

            stats = {
                'total_feedback': total_count,
                'positive_feedback': positive_count,
                'negative_feedback': negative_count,
                'satisfaction_rate': satisfaction_rate,
            }

            logger.debug('feedback_stats_retrieved', stats=stats)

            return stats

        except Exception as e:
            logger.error('feedback_stats_failed', error=str(e))
            return {
                'total_feedback': 0,
                'positive_feedback': 0,
                'negative_feedback': 0,
                'satisfaction_rate': 0,
            }


def render_feedback_widget(
    query: str,
    response: str,
    user_id: str = 'anonymous',
    feedback_collector: Optional[FeedbackCollector] = None,
) -> None:
    """
    Render feedback widget in Streamlit.

    Args:
        query: User's original query
        response: System's response
        user_id: User identifier
        feedback_collector: FeedbackCollector instance (creates if None)
    """
    # Generate unique feedback ID
    feedback_id = f'fb_{uuid.uuid4().hex[:12]}'

    # Feedback section
    st.divider()
    st.subheader('Was this response helpful?')

    col1, col2, col3 = st.columns([1, 1, 4])

    with col1:
        if st.button('👍 Yes', key=f'thumbs_up_{feedback_id}'):
            # Store positive feedback
            if feedback_collector:
                asyncio.run(
                    feedback_collector.store_feedback(
                        feedback_id=feedback_id,
                        user_id=user_id,
                        query=query,
                        response=response,
                        rating='positive',
                    )
                )
            st.success('Thanks for your feedback!')
            logger.info('positive_feedback_submitted', feedback_id=feedback_id)

    with col2:
        if st.button('👎 No', key=f'thumbs_down_{feedback_id}'):
            # Show feedback form
            st.session_state[f'show_feedback_form_{feedback_id}'] = True
            logger.info('negative_feedback_initiated', feedback_id=feedback_id)

    # Show detailed feedback form if thumbs down was clicked
    if st.session_state.get(f'show_feedback_form_{feedback_id}', False):
        with st.form(key=f'feedback_form_{feedback_id}'):
            st.write('**Help us improve:**')

            feedback_text = st.text_area(
                'What went wrong? (Optional)',
                placeholder="e.g., The response was inaccurate, too slow, didn't answer my question...",
                height=100,
            )

            submitted = st.form_submit_button('Submit Feedback')

            if submitted:
                # Store negative feedback with text
                if feedback_collector:
                    asyncio.run(
                        feedback_collector.store_feedback(
                            feedback_id=feedback_id,
                            user_id=user_id,
                            query=query,
                            response=response,
                            rating='negative',
                            feedback_text=feedback_text,
                        )
                    )

                st.success('Thank you for helping us improve!')
                st.session_state[f'show_feedback_form_{feedback_id}'] = False
                logger.info(
                    'negative_feedback_submitted',
                    feedback_id=feedback_id,
                    has_text=bool(feedback_text),
                )


def render_feedback_stats_sidebar(
    feedback_collector: Optional[FeedbackCollector] = None,
) -> None:
    """
    Render feedback statistics in Streamlit sidebar.

    Args:
        feedback_collector: FeedbackCollector instance
    """
    if not feedback_collector:
        feedback_collector = FeedbackCollector()

    try:
        stats = asyncio.run(feedback_collector.get_feedback_stats())

        st.sidebar.divider()
        st.sidebar.subheader('📊 User Feedback')

        col1, col2 = st.sidebar.columns(2)

        with col1:
            st.metric(
                'Total',
                stats['total_feedback'],
            )

        with col2:
            st.metric(
                'Satisfaction',
                f'{stats["satisfaction_rate"]:.1f}%',
            )

        # Progress bar for satisfaction rate
        if stats['total_feedback'] > 0:
            st.sidebar.progress(
                stats['satisfaction_rate'] / 100,
                text=f'👍 {stats["positive_feedback"]} | 👎 {stats["negative_feedback"]}',
            )

    except Exception as e:
        logger.error('feedback_stats_display_failed', error=str(e))
        st.sidebar.info('Feedback stats unavailable')


# Example integration with Streamlit app
if __name__ == '__main__':
    import streamlit as st

    st.set_page_config(page_title='CyberShield Feedback Demo', page_icon='🛡️')

    st.title('🛡️ CyberShield Feedback Demo')

    # Initialize feedback collector
    collector = FeedbackCollector()

    # Render stats in sidebar
    render_feedback_stats_sidebar(collector)

    # Main content
    st.subheader('Threat Analysis Response')

    example_query = 'What attacks involved IP 192.168.1.100?'
    example_response = """
    Based on our threat intelligence database, IP 192.168.1.100 has been involved in 5 attack records:

    - 3 DDoS attacks
    - 2 Malware infections
    - Severity: High

    This IP is associated with a known botnet and should be blocked.
    """

    st.text_area('Query', example_query, disabled=True)
    st.text_area('Response', example_response, disabled=True, height=200)

    # Render feedback widget
    render_feedback_widget(
        query=example_query,
        response=example_response,
        user_id='demo_user',
        feedback_collector=collector,
    )

    st.divider()
    st.info('💡 Tip: Click thumbs up or thumbs down to provide feedback!')
