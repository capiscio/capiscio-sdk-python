"""Security executor wrapper for A2A agents."""
import logging
from typing import Any, Dict, Optional, Callable
from functools import wraps

try:
    from a2a.server.agent_execution import RequestContext
except ImportError:
    RequestContext = Any  # type: ignore[misc,assignment]

from .config import SecurityConfig
from .validators import MessageValidator, ProtocolValidator
from .infrastructure import ValidationCache, RateLimiter
from .types import ValidationResult
from .errors import (
    CapiscioValidationError,
    CapiscioRateLimitError,
)

logger = logging.getLogger(__name__)


class CapiscioSecurityExecutor:
    """
    Security wrapper for A2A agent executors.
    
    Provides runtime validation, rate limiting, and security checks
    for A2A agent interactions. Implements the AgentExecutor interface.
    """

    def __init__(
        self,
        delegate: Any,
        config: Optional[SecurityConfig] = None,
    ):
        """
        Initialize security executor.

        Args:
            delegate: The agent executor to wrap (must implement AgentExecutor interface)
            config: Security configuration (defaults to production preset)
        """
        self.delegate = delegate
        self.config = config or SecurityConfig.production()
        
        # Initialize components
        self._message_validator = MessageValidator()
        self._protocol_validator = ProtocolValidator()
        
        # Initialize infrastructure
        self._cache: Optional[ValidationCache]
        self._rate_limiter: Optional[RateLimiter]
        
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

    async def execute(self, context: RequestContext, event_queue: Any) -> None:
        """
        Execute agent with security checks.

        Args:
            context: RequestContext with message and task information
            event_queue: EventQueue for publishing events

        Raises:
            CapiscioValidationError: If validation fails in block mode
            CapiscioRateLimitError: If rate limit exceeded in block mode
        """
        # Extract message for validation
        message = context.message
        if not message:
            logger.warning("No message in context")
            await self.delegate.execute(context, event_queue)
            return
        
        # Convert message to dict for validation (our validators expect dict format)
        message_dict = message.model_dump() if hasattr(message, 'model_dump') else {}
        
        # Extract identifier for rate limiting
        identifier = message_dict.get("message_id") or message.message_id
        
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
            validation_result = self._validate_message(message_dict)
            
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
            await self.delegate.execute(context, event_queue)
        except Exception as e:
            if self.config.fail_mode != "log":
                raise
            logger.error(f"Delegate execution failed: {e}")
            raise

    async def cancel(self, context: RequestContext, event_queue: Any) -> None:
        """
        Cancel task with passthrough to delegate.

        Args:
            context: RequestContext with task to cancel
            event_queue: EventQueue for publishing cancellation event
        """
        # Cancellation just passes through - no security checks needed
        await self.delegate.cancel(context, event_queue)

    async def validate_agent_card(self, url: str) -> ValidationResult:
        """
        Validate an agent card from a URL.
        
        Uses CoreValidator which delegates to Go core for consistent
        validation across all CapiscIO SDKs.
        
        Args:
            url: URL to the agent card or agent root
            
        Returns:
            ValidationResult with scores
        """
        from .validators import CoreValidator
        with CoreValidator() as validator:
            return await validator.fetch_and_validate(url)

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
            msg_id = message.get("id")
            if isinstance(msg_id, str):
                self._cache.set(msg_id, result)
            
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
) -> Callable[[type], Callable[..., CapiscioSecurityExecutor]]:
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
    def decorator(cls: type) -> Callable[..., CapiscioSecurityExecutor]:
        @wraps(cls)
        def wrapper(*args: Any, **kwargs: Any) -> CapiscioSecurityExecutor:
            instance = cls(*args, **kwargs)
            return CapiscioSecurityExecutor(instance, config)
        return wrapper
    return decorator
