"""Tests for validation cache."""
import pytest
import time
from capiscio_sdk.infrastructure.cache import ValidationCache
from capiscio_sdk.types import ValidationResult


@pytest.fixture
def cache():
    """Create cache instance."""
    return ValidationCache(max_size=10, ttl=1)


@pytest.fixture
def result():
    """Create test validation result."""
    return ValidationResult(success=True, score=100)


def test_cache_set_and_get(cache, result):
    """Test setting and getting cache entry."""
    cache.set("test_key", result)
    cached = cache.get("test_key")
    assert cached is not None
    assert cached.success == result.success
    assert cached.score == result.score


def test_cache_get_nonexistent(cache):
    """Test getting nonexistent cache entry."""
    cached = cache.get("nonexistent")
    assert cached is None


def test_cache_ttl_expiration(cache, result):
    """Test cache entry expiration."""
    cache.set("test_key", result)
    assert cache.get("test_key") is not None

    # Wait for TTL to expire
    time.sleep(1.1)
    assert cache.get("test_key") is None


def test_cache_invalidate(cache, result):
    """Test cache invalidation."""
    cache.set("test_key", result)
    assert cache.get("test_key") is not None

    cache.invalidate("test_key")
    assert cache.get("test_key") is None


def test_cache_clear(cache, result):
    """Test clearing all cache entries."""
    cache.set("key1", result)
    cache.set("key2", result)
    assert cache.size() == 2

    cache.clear()
    assert cache.size() == 0


def test_cache_max_size(result):
    """Test cache max size enforcement."""
    cache = ValidationCache(max_size=2, ttl=60)
    cache.set("key1", result)
    cache.set("key2", result)
    cache.set("key3", result)  # Should evict oldest

    # Cache should maintain max size
    assert cache.size() <= 2
