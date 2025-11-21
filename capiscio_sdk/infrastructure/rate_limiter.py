"""Rate limiting implementation."""
import time
from typing import Dict
from ..types import RateLimitInfo
from ..errors import CapiscioRateLimitError


class RateLimiter:
    """Token bucket rate limiter."""

    def __init__(self, requests_per_minute: int = 60):
        """
        Initialize rate limiter.

        Args:
            requests_per_minute: Maximum requests allowed per minute
        """
        self._requests_per_minute = requests_per_minute
        self._buckets: Dict[str, Dict[str, float]] = {}
        self._bucket_capacity = requests_per_minute
        self._refill_rate = requests_per_minute / 60.0  # tokens per second

    def check(self, identifier: str) -> RateLimitInfo:
        """
        Check rate limit for identifier without consuming tokens.

        Args:
            identifier: Unique identifier (e.g., agent URL or IP address)

        Returns:
            RateLimitInfo with current rate limit status
        """
        now = time.time()
        bucket = self._get_or_create_bucket(identifier, now)

        # Calculate current tokens (don't actually refill yet)
        time_elapsed = now - bucket["last_refill"]
        tokens_to_add = time_elapsed * self._refill_rate
        current_tokens = min(
            self._bucket_capacity, bucket["tokens"] + tokens_to_add
        )

        # Calculate reset time (when bucket will be full again)
        tokens_needed = self._bucket_capacity - current_tokens
        seconds_to_full = tokens_needed / self._refill_rate if tokens_needed > 0 else 0
        reset_at = now + seconds_to_full

        return RateLimitInfo(
            requests_allowed=self._requests_per_minute,
            requests_used=int(self._bucket_capacity - current_tokens),
            reset_at=reset_at,
        )

    def consume(self, identifier: str, tokens: float = 1.0) -> None:
        """
        Consume tokens from bucket.

        Args:
            identifier: Unique identifier
            tokens: Number of tokens to consume (default 1.0)

        Raises:
            CapiscioRateLimitError: If rate limit exceeded
        """
        now = time.time()
        bucket = self._get_or_create_bucket(identifier, now)

        # Refill tokens first
        time_elapsed = now - bucket["last_refill"]
        tokens_to_add = time_elapsed * self._refill_rate
        bucket["tokens"] = min(
            self._bucket_capacity, bucket["tokens"] + tokens_to_add
        )
        bucket["last_refill"] = now

        # Check if enough tokens available
        if bucket["tokens"] < tokens:
            # Calculate retry after time
            tokens_needed = tokens - bucket["tokens"]
            retry_after = tokens_needed / self._refill_rate

            raise CapiscioRateLimitError(
                f"Rate limit exceeded for {identifier}",
                retry_after_seconds=int(retry_after) + 1,
            )

        # Consume tokens
        bucket["tokens"] -= tokens

    def reset(self, identifier: str) -> None:
        """
        Reset rate limit for identifier.

        Args:
            identifier: Unique identifier to reset
        """
        self._buckets.pop(identifier, None)

    def clear(self) -> None:
        """Clear all rate limit buckets."""
        self._buckets.clear()

    def _get_or_create_bucket(self, identifier: str, now: float) -> Dict[str, float]:
        """Get or create bucket for identifier."""
        if identifier not in self._buckets:
            self._buckets[identifier] = {
                "tokens": float(self._bucket_capacity),
                "last_refill": now,
            }
        return self._buckets[identifier]
