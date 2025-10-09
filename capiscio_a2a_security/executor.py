"""Security executor wrapper for A2A agents."""
import logging
from typing import Any, Dict, Optional, Callable
from functools import wraps

from .config import SecurityConfig
from .validators import MessageValidator, ProtocolValidator
from .infrastructure import ValidationCache, RateLimiter
from .types import ValidationResult
from .errors import (
    CapiscioValidationError,
    CapiscioRateLimitError,
    CapiscioSecurityError,
)

logger = logging.getLogger(__name__)


class CapiscioSecurityExecutor:
    """
    Security wrapper for A2A agent executors.
    
    Provides runtime validation, rate limiting, and security checks
    for A2A agent interactions.
    """

    def __init__(
        self,
        delegate: Any,
        config: Optional[SecurityConfig] = None,
    ):
        """
        Initialize security executor.

        Args:
            delegate: The agent executor to wrap
            config: Security configuration (defaults to production preset)
        """
        self.delegate = delegate
        self.config = config or SecurityConfig.production()
        
        # Initialize components
        self._message_validator = MessageValidator()
        self._protocol_validator = ProtocolValidator()
        
        # Initialize infrastructure
        if self.config.upstream.cache_validation:
            self._cache = ValidationCache(
                max_size=1000,
                ttl=self.config.upstream.cache_timeout,
            )
        else:
            self._cache = None
            
        if self.config.downstream.enable_rate_limiting:
            self._rate_limiter = RateLimiter(
                requests_per_minute=self.config.downstream.rate_limit_requests_per_minute
            )
        else:
            self._rate_limiter = None

    def execute(self, message: Dict[str, Any], **kwargs) -> Any:
        """
        Execute agent with security checks.

        Args:
            message: The A2A message to process
            **kwargs: Additional arguments passed to delegate

        Returns:
            Result from delegate execution

        Raises:
            CapiscioValidationError: If validation fails
            CapiscioRateLimitError: If rate limit exceeded
        """
        # Extract identifier for rate limiting (sender URL or ID)
        identifier = self._extract_identifier(message)
        
        # Check rate limit
        if self._rate_limiter and identifier:
            try:
                self._rate_limiter.consume(identifier)
            except CapiscioRateLimitError as e:
                if self.config.fail_mode == "block":
                    raise
                elif self.config.fail_mode == "monitor":
                    logger.warning(f"Rate limit exceeded for {identifier}: {e}")
                # Continue execution in log/monitor mode

        # Validate message
        if self.config.downstream.validate_schema:
            validation_result = self._validate_message(message)
            
            if not validation_result.success:
                error = CapiscioValidationError(
                    "Message validation failed", validation_result
                )
                
                if self.config.fail_mode == "block":
                    raise error
                elif self.config.fail_mode == "monitor":
                    logger.warning(f"Validation failed: {error.errors}")
                elif self.config.fail_mode == "log":
                    logger.info(f"Validation issues detected: {validation_result.issues}")

        # Execute delegate
        try:
            result = self.delegate.execute(message, **kwargs)
            return result
        except Exception as e:
            if self.config.fail_mode != "log":
                raise
            logger.error(f"Delegate execution failed: {e}")
            raise

    def _extract_identifier(self, message: Dict[str, Any]) -> Optional[str]:
        """Extract identifier from message for rate limiting."""
        sender = message.get("sender", {})
        if isinstance(sender, dict):
            return sender.get("url") or sender.get("id")
        return None

    def _validate_message(self, message: Dict[str, Any]) -> ValidationResult:
        """Validate message with caching."""
        # Try cache first
        if self._cache:
            message_id = message.get("id")
            if message_id:
                cached = self._cache.get(message_id)
                if cached:
                    logger.debug(f"Using cached validation for message {message_id}")
                    return cached

        # Validate
        result = self._message_validator.validate(message)
        
        # Cache result
        if self._cache and message.get("id"):
            self._cache.set(message.get("id"), result)
            
        return result

    def __getattr__(self, name: str) -> Any:
        """Delegate attribute access to wrapped executor."""
        return getattr(self.delegate, name)


def secure(
    agent: Any,
    config: Optional[SecurityConfig] = None,
) -> CapiscioSecurityExecutor:
    """
    Wrap an agent executor with security middleware (minimal pattern).

    Args:
        agent: Agent executor to wrap
        config: Security configuration (defaults to production)

    Returns:
        Secured agent executor

    Example:
        ```python
        agent = secure(MyAgentExecutor())
        ```
    """
    return CapiscioSecurityExecutor(agent, config)


def secure_agent(
    config: Optional[SecurityConfig] = None,
) -> Callable:
    """
    Decorator to secure an agent executor class (decorator pattern).

    Args:
        config: Security configuration (defaults to production)

    Returns:
        Decorator function

    Example:
        ```python
        @secure_agent(config=SecurityConfig.strict())
        class MyAgent:
            def execute(self, message):
                # ... agent logic
        ```
    """
    def decorator(cls):
        @wraps(cls)
        def wrapper(*args, **kwargs):
            instance = cls(*args, **kwargs)
            return CapiscioSecurityExecutor(instance, config)
        return wrapper
    return decorator
