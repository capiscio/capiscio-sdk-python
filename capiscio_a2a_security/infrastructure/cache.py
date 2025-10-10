"""Validation result caching."""
import time
from typing import Optional
from cachetools import TTLCache
from ..types import ValidationResult, CacheEntry


class ValidationCache:
    """In-memory cache for validation results with TTL."""

    def __init__(self, max_size: int = 1000, ttl: int = 300):
        """
        Initialize validation cache.

        Args:
            max_size: Maximum number of entries to cache
            ttl: Time-to-live in seconds (default 5 minutes)
        """
        self._cache: TTLCache[str, CacheEntry] = TTLCache(maxsize=max_size, ttl=ttl)
        self._ttl = ttl

    def get(self, key: str) -> Optional[ValidationResult]:
        """
        Get validation result from cache.

        Args:
            key: Cache key (e.g., agent URL or message ID)

        Returns:
            Cached ValidationResult or None if not found
        """
        entry = self._cache.get(key)
        if entry is None:
            return None

        return entry.result

    def set(self, key: str, result: ValidationResult) -> None:
        """
        Store validation result in cache.

        Args:
            key: Cache key
            result: ValidationResult to cache
        """
        entry = CacheEntry(
            result=result,
            cached_at=time.time(),
            ttl=self._ttl,
        )
        self._cache[key] = entry

    def invalidate(self, key: str) -> None:
        """
        Remove entry from cache.

        Args:
            key: Cache key to invalidate
        """
        self._cache.pop(key, None)

    def clear(self) -> None:
        """Clear all entries from cache."""
        self._cache.clear()

    def size(self) -> int:
        """
        Get current cache size.

        Returns:
            Number of entries in cache
        """
        return len(self._cache)
