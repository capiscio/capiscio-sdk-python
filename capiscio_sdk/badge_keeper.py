"""BadgeKeeper - Automatic badge renewal for continuous operation.

BadgeKeeper monitors badge expiration and automatically renews badges
before they expire, ensuring uninterrupted agent authentication.

Example:
    >>> from capiscio_sdk import BadgeKeeper, SimpleGuard
    >>> 
    >>> # Basic usage
    >>> keeper = BadgeKeeper(
    ...     api_url="https://registry.capisc.io",
    ...     api_key="your-api-key",
    ...     agent_id="your-agent-id",
    ...     renewal_threshold=10,  # Renew 10s before expiry
    ... )
    >>> keeper.start()
    >>> # Badge automatically renews in background
    >>> current_badge = keeper.get_current_badge()
    >>> keeper.stop()
    >>> 
    >>> # Integration with SimpleGuard
    >>> guard = SimpleGuard()
    >>> keeper = BadgeKeeper(
    ...     api_url="https://registry.capisc.io",
    ...     api_key="your-api-key",
    ...     agent_id="your-agent-id",
    ...     on_renew=lambda token: guard.set_badge_token(token),
    ... )
    >>> keeper.start()
"""

import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Callable, Dict, Any

from capiscio_sdk._rpc.client import CapiscioRPCClient
from capiscio_sdk.errors import CapiscioSecurityError

logger = logging.getLogger(__name__)


@dataclass
class BadgeKeeperConfig:
    """Configuration for BadgeKeeper.
    
    Attributes:
        api_url: Badge CA URL (e.g., https://registry.capisc.io)
        api_key: API key for badge issuance
        agent_id: Agent identifier (UUID or DID)
        mode: Keeper mode ('ca' or 'pop', default: 'ca')
        output_file: Path to write badge file (default: badge.jwt)
        ttl_seconds: Badge TTL in seconds (default: 300 = 5 minutes)
        renewal_threshold: Renew this many seconds before expiry (default: 10)
        check_interval: Check interval in seconds (default: 5)
        trust_level: Trust level for CA mode (1-4, default: 1)
        rpc_address: Optional custom RPC address for capiscio-core
        on_renew: Optional callback(token: str) called when badge renews
        max_retries: Max retry attempts on renewal failure (default: 3)
        retry_backoff: Base backoff seconds for exponential retry (default: 2)
    """
    api_url: str
    api_key: str
    agent_id: str
    mode: str = "ca"
    output_file: str = "badge.jwt"
    ttl_seconds: int = 300
    renewal_threshold: int = 10
    check_interval: int = 5
    trust_level: int = 1
    rpc_address: Optional[str] = None
    on_renew: Optional[Callable[[str], None]] = None
    max_retries: int = 3
    retry_backoff: int = 2


class BadgeKeeper:
    """Automatic badge renewal manager.
    
    BadgeKeeper runs a background thread that monitors badge expiration
    and automatically requests new badges before they expire. This ensures
    continuous agent authentication without manual intervention.
    
    The keeper integrates with SimpleGuard via the on_renew callback,
    allowing seamless badge token updates for outbound request signing.
    """

    def __init__(
        self,
        api_url: str,
        api_key: str,
        agent_id: str,
        mode: str = "ca",
        output_file: str = "badge.jwt",
        ttl_seconds: int = 300,
        renewal_threshold: int = 10,
        check_interval: int = 5,
        trust_level: int = 1,
        rpc_address: Optional[str] = None,
        on_renew: Optional[Callable[[str], None]] = None,
        max_retries: int = 3,
        retry_backoff: int = 2,
    ):
        """Initialize BadgeKeeper.
        
        Args:
            api_url: Badge CA URL (e.g., https://registry.capisc.io)
            api_key: API key for badge issuance
            agent_id: Agent identifier (UUID or DID)
            mode: Keeper mode ('ca' or 'pop', default: 'ca')
            output_file: Path to write badge file (default: badge.jwt)
            ttl_seconds: Badge TTL in seconds (default: 300 = 5 minutes)
            renewal_threshold: Renew this many seconds before expiry (default: 10)
            check_interval: Check interval in seconds (default: 5)
            trust_level: Trust level for CA mode (1-4, default: 1)
            rpc_address: Optional custom RPC address for capiscio-core
            on_renew: Optional callback(token: str) called when badge renews
            max_retries: Max retry attempts on renewal failure (default: 3)
            retry_backoff: Base backoff seconds for exponential retry (default: 2)
        """
        self.config = BadgeKeeperConfig(
            api_url=api_url,
            api_key=api_key,
            agent_id=agent_id,
            mode=mode,
            output_file=output_file,
            ttl_seconds=ttl_seconds,
            renewal_threshold=renewal_threshold,
            check_interval=check_interval,
            trust_level=trust_level,
            rpc_address=rpc_address,
            on_renew=on_renew,
            max_retries=max_retries,
            retry_backoff=retry_backoff,
        )
        
        self._rpc_client: Optional[CapiscioRPCClient] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._current_badge: Optional[str] = None
        self._badge_lock = threading.Lock()
        self._running = False

    def start(self) -> None:
        """Start the badge keeper background thread.
        
        Raises:
            CapiscioSecurityError: If keeper is already running
        """
        if self._running:
            raise CapiscioSecurityError("BadgeKeeper is already running")
        
        logger.info(
            f"Starting BadgeKeeper (mode={self.config.mode}, "
            f"threshold={self.config.renewal_threshold}s)"
        )
        
        self._stop_event.clear()
        self._running = True
        self._thread = threading.Thread(target=self._run_keeper, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the badge keeper background thread."""
        if not self._running:
            return
        
        logger.info("Stopping BadgeKeeper...")
        self._stop_event.set()
        
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        
        if self._rpc_client:
            self._rpc_client.close()
            self._rpc_client = None
        
        self._running = False
        logger.info("BadgeKeeper stopped")

    def get_current_badge(self) -> Optional[str]:
        """Get the current badge token.
        
        Returns:
            Current badge token, or None if no badge yet
        """
        with self._badge_lock:
            return self._current_badge

    def is_running(self) -> bool:
        """Check if keeper is running.
        
        Returns:
            True if keeper is running, False otherwise
        """
        return self._running

    def _run_keeper(self) -> None:
        """Background thread that runs the keeper loop."""
        try:
            # Initialize RPC client
            self._rpc_client = CapiscioRPCClient(
                address=self.config.rpc_address or "unix:///tmp/capiscio.sock"
            )
            
            logger.debug("BadgeKeeper thread started, streaming events from core...")
            
            # Stream events from capiscio-core keeper
            for event in self._rpc_client.badge.start_keeper(
                mode=self.config.mode,
                output_file=self.config.output_file,
                agent_id=self.config.agent_id,
                api_key=self.config.api_key,
                ca_url=self.config.api_url,
                ttl_seconds=self.config.ttl_seconds,
                renew_before_seconds=self.config.renewal_threshold,
                check_interval_seconds=self.config.check_interval,
                trust_level=self.config.trust_level,
            ):
                # Check stop signal
                if self._stop_event.is_set():
                    logger.debug("Stop event detected, exiting keeper loop")
                    break
                
                self._handle_keeper_event(event)
            
            logger.debug("Keeper event stream ended")
            
        except Exception as e:
            logger.error(f"BadgeKeeper error: {e}", exc_info=True)
            self._running = False
        finally:
            if self._rpc_client:
                self._rpc_client.close()
                self._rpc_client = None

    def _handle_keeper_event(self, event: Dict[str, Any]) -> None:
        """Handle a keeper event from the stream.
        
        Args:
            event: Event dict from start_keeper stream
        """
        event_type = event.get("type")
        
        if event_type == "started":
            logger.info(
                f"BadgeKeeper started for agent {self.config.agent_id}"
            )
        
        elif event_type == "renewed":
            badge_token = event.get("token")
            badge_jti = event.get("badge_jti", "unknown")
            expires_ts = event.get("expires_at", 0)
            
            if badge_token:
                with self._badge_lock:
                    self._current_badge = badge_token
                
                # Call renewal callback if configured
                if self.config.on_renew:
                    try:
                        self.config.on_renew(badge_token)
                        logger.debug("Called on_renew callback")
                    except Exception as e:
                        logger.error(f"Error in on_renew callback: {e}")
                
                # Format expiry time
                if expires_ts > 0:
                    expires_dt = datetime.fromtimestamp(expires_ts, timezone.utc)
                    logger.info(
                        f"Badge renewed (jti={badge_jti[:8]}..., "
                        f"expires={expires_dt.isoformat()})"
                    )
                else:
                    logger.info(f"Badge renewed (jti={badge_jti[:8]}...)")
            else:
                logger.warning("Renewed event but no token in response")
        
        elif event_type == "error":
            error_msg = event.get("error", "Unknown error")
            error_code = event.get("error_code", "")
            logger.error(
                f"BadgeKeeper error: {error_msg} "
                f"(code={error_code})"
            )
        
        elif event_type == "stopped":
            logger.info("BadgeKeeper stopped by core")
            self._stop_event.set()
        
        else:
            logger.debug(f"Unknown keeper event type: {event_type}")

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
        return False
