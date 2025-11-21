"""Tests for rate limiter."""
import pytest
import time
from capiscio_sdk.infrastructure.rate_limiter import RateLimiter
from capiscio_sdk.errors import CapiscioRateLimitError


@pytest.fixture
def limiter():
    """Create rate limiter instance."""
    return RateLimiter(requests_per_minute=60)


def test_rate_limiter_check(limiter):
    """Test checking rate limit status."""
    info = limiter.check("test_id")
    assert info.requests_allowed == 60
    assert info.requests_used == 0
    assert info.requests_remaining == 60


def test_rate_limiter_consume(limiter):
    """Test consuming tokens."""
    # Consume multiple tokens to make the difference visible
    limiter.consume("test_id", 5.0)
    limiter.consume("test_id", 5.0)
    
    info = limiter.check("test_id")
    
    # Should have consumed at least 9 tokens (allowing for minimal refill)
    assert info.requests_remaining <= 51


def test_rate_limiter_exceed(limiter):
    """Test exceeding rate limit."""
    # Consume all tokens
    for _ in range(60):
        limiter.consume("test_id", 1.0)

    # Next request should fail
    with pytest.raises(CapiscioRateLimitError) as exc_info:
        limiter.consume("test_id", 1.0)

    assert exc_info.value.retry_after_seconds > 0


def test_rate_limiter_separate_buckets(limiter):
    """Test that different identifiers have separate buckets."""
    # Exhaust one identifier
    for _ in range(60):
        limiter.consume("id1", 1.0)

    # Other identifier should still work
    limiter.consume("id2", 1.0)  # Should not raise


def test_rate_limiter_refill():
    """Test token refill over time."""
    limiter = RateLimiter(requests_per_minute=60)  # 1 token per second

    # Consume some tokens
    limiter.consume("test_id", 10.0)
    info = limiter.check("test_id")
    initial_remaining = info.requests_remaining

    # Wait for refill
    time.sleep(0.5)
    info = limiter.check("test_id")
    assert info.requests_remaining >= initial_remaining


def test_rate_limiter_reset(limiter):
    """Test resetting rate limit."""
    # Consume tokens
    limiter.consume("test_id", 10.0)
    
    # Reset
    limiter.reset("test_id")
    info = limiter.check("test_id")
    
    # After reset, should have full capacity
    assert info.requests_remaining == 60


def test_rate_limiter_clear(limiter):
    """Test clearing all buckets."""
    limiter.consume("id1", 10.0)
    limiter.consume("id2", 10.0)

    limiter.clear()

    info1 = limiter.check("id1")
    info2 = limiter.check("id2")
    assert info1.requests_used == 0
    assert info2.requests_used == 0
