"""
CapiscIO Connect - "Let's Encrypt" style agent identity.

All cryptographic operations (key generation, DID derivation) are performed
by the capiscio-core Go library via gRPC, ensuring consistency across SDKs.

Usage:
    from capiscio_sdk import CapiscIO
    
    # One-liner to get a production-ready agent
    agent = CapiscIO.connect(api_key="sk_live_...")
    
    # Use the agent
    print(agent.did)           # did:key:z6Mk...
    print(agent.badge)         # Current badge (auto-renewed)
    agent.emit("task_started", {"task_id": "123"})
"""

import os
import logging
import httpx
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass, field

from ._rpc.client import CapiscioRPCClient
from .errors import ConfigurationError

logger = logging.getLogger(__name__)

# Default paths
DEFAULT_CONFIG_DIR = Path.home() / ".capiscio"
DEFAULT_KEYS_DIR = DEFAULT_CONFIG_DIR / "keys"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.toml"

# Default server URLs
PROD_REGISTRY = "https://registry.capisc.io"
PROD_DASHBOARD = "https://app.capisc.io"


@dataclass
class AgentIdentity:
    """Represents a fully-configured agent identity."""
    
    agent_id: str
    did: str
    name: str
    api_key: str
    server_url: str
    keys_dir: Path
    badge: Optional[str] = None
    badge_expires_at: Optional[str] = None
    _guard: Any = field(default=None, repr=False)
    _keeper: Any = field(default=None, repr=False)
    _emitter: Any = field(default=None, repr=False)
    
    def emit(self, event_type: str, data: Dict[str, Any]) -> bool:
        """Emit an event to the registry."""
        if not self._emitter:
            from .events import EventEmitter
            self._emitter = EventEmitter(
                server_url=self.server_url,
                api_key=self.api_key,
                agent_id=self.agent_id,
            )
        return self._emitter.emit(event_type, data)
    
    def get_badge(self) -> Optional[str]:
        """Get current badge (auto-renewed if needed)."""
        if self._keeper:
            return self._keeper.get_current_badge()
        return self.badge
    
    def status(self) -> Dict[str, Any]:
        """Get agent status including badge validity."""
        return {
            "agent_id": self.agent_id,
            "did": self.did,
            "name": self.name,
            "server": self.server_url,
            "badge_valid": self.badge is not None,
            "badge_expires_at": self.badge_expires_at,
        }


class CapiscIO:
    """
    CapiscIO SDK - "Let's Encrypt" style agent identity.
    
    Provides seamless agent identity management:
    - Auto-creates agents if they don't exist
    - Auto-generates and stores cryptographic keys
    - Auto-derives and registers DIDs
    - Auto-requests and renews badges
    
    Usage:
        agent = CapiscIO.connect(api_key="sk_live_...")
        print(agent.did)
    """
    
    @classmethod
    def connect(
        cls,
        api_key: str,
        *,
        name: Optional[str] = None,
        agent_id: Optional[str] = None,
        server_url: str = PROD_REGISTRY,
        keys_dir: Optional[Path] = None,
        auto_badge: bool = True,
        dev_mode: bool = False,
    ) -> AgentIdentity:
        """
        Connect to CapiscIO and get a fully-configured agent identity.
        
        This is the main entry point - it handles everything automatically:
        1. Finds or creates the agent
        2. Generates keys if needed
        3. Derives and registers DID
        4. Requests badge (if auto_badge=True)
        5. Sets up auto-renewal
        
        Args:
            api_key: Your CapiscIO API key (sk_live_... or sk_test_...)
            name: Agent name (auto-generated if omitted)
            agent_id: Specific agent ID to use (auto-discovered if omitted)
            server_url: Registry server URL (default: production)
            keys_dir: Directory for keys (default: ~/.capiscio/keys/{agent_id}/)
            auto_badge: Whether to automatically request a badge
            dev_mode: Use self-signed badges (Trust Level 0)
            
        Returns:
            AgentIdentity with full credentials and methods
            
        Example:
            agent = CapiscIO.connect(api_key="sk_live_abc123")
            print(f"Agent DID: {agent.did}")
            agent.emit("agent_started", {"version": "1.0"})
        """
        connector = _Connector(
            api_key=api_key,
            name=name,
            agent_id=agent_id,
            server_url=server_url,
            keys_dir=keys_dir,
            auto_badge=auto_badge,
            dev_mode=dev_mode,
        )
        return connector.connect()
    
    @classmethod
    def from_env(cls, **kwargs) -> AgentIdentity:
        """
        Connect using environment variables.
        
        Reads from:
        - CAPISCIO_API_KEY (required)
        - CAPISCIO_AGENT_ID (optional)
        - CAPISCIO_AGENT_NAME (optional)
        - CAPISCIO_SERVER_URL (optional, default: production)
        - CAPISCIO_DEV_MODE (optional, default: false)
        """
        api_key = os.environ.get("CAPISCIO_API_KEY")
        if not api_key:
            raise ValueError(
                "CAPISCIO_API_KEY environment variable is required. "
                "Get your API key at https://app.capisc.io"
            )
        
        return cls.connect(
            api_key=api_key,
            agent_id=os.environ.get("CAPISCIO_AGENT_ID"),
            name=os.environ.get("CAPISCIO_AGENT_NAME"),
            server_url=os.environ.get("CAPISCIO_SERVER_URL", PROD_REGISTRY),
            dev_mode=os.environ.get("CAPISCIO_DEV_MODE", "").lower() in ("true", "1", "yes"),
            **kwargs,
        )


class _Connector:
    """Internal class that handles the connection logic."""
    
    def __init__(
        self,
        api_key: str,
        name: Optional[str],
        agent_id: Optional[str],
        server_url: str,
        keys_dir: Optional[Path],
        auto_badge: bool,
        dev_mode: bool,
    ):
        self.api_key = api_key
        self.name = name
        self.agent_id = agent_id
        self.server_url = server_url.rstrip("/")
        self.keys_dir = keys_dir
        self.auto_badge = auto_badge
        self.dev_mode = dev_mode
        
        # HTTP client for registry API
        self._client = httpx.Client(
            base_url=self.server_url,
            headers={
                "X-Capiscio-Registry-Key": self.api_key,
                "Content-Type": "application/json",
            },
            timeout=30.0,
        )
        
        # gRPC client for capiscio-core (crypto operations)
        self._rpc_client: Optional[CapiscioRPCClient] = None
    
    def connect(self) -> AgentIdentity:
        """Execute the full connection flow."""
        logger.info("Connecting to CapiscIO...")
        
        # Step 1: Find or create agent
        agent_data = self._ensure_agent()
        self.agent_id = agent_data["id"]
        self.name = agent_data.get("name") or self.name or f"Agent-{self.agent_id[:8]}"
        
        logger.info(f"Agent: {self.name} ({self.agent_id})")
        
        # Step 2: Set up keys directory
        if not self.keys_dir:
            self.keys_dir = DEFAULT_KEYS_DIR / self.agent_id
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        
        # Step 3: Initialize identity via capiscio-core Init RPC (one call does everything)
        did = self._init_identity()
        logger.info(f"DID: {did}")
        
        # Step 4: Set up badge (if auto_badge)
        badge = None
        badge_expires_at = None
        keeper = None
        guard = None
        
        if self.auto_badge and not self.dev_mode:
            badge, badge_expires_at, keeper, guard = self._setup_badge()
            if badge:
                logger.info(f"Badge acquired (expires: {badge_expires_at})")
        
        return AgentIdentity(
            agent_id=self.agent_id,
            did=did,
            name=self.name,
            api_key=self.api_key,
            server_url=self.server_url,
            keys_dir=self.keys_dir,
            badge=badge,
            badge_expires_at=badge_expires_at,
            _guard=guard,
            _keeper=keeper,
        )
    
    def _ensure_agent(self) -> Dict[str, Any]:
        """Find existing agent or create new one."""
        if self.agent_id:
            # Fetch specific agent
            resp = self._client.get(f"/v1/agents/{self.agent_id}")
            if resp.status_code == 200:
                data = resp.json()
                return data.get("data", data)
            elif resp.status_code == 404:
                raise ValueError(f"Agent {self.agent_id} not found")
            else:
                raise RuntimeError(f"Failed to fetch agent: {resp.text}")
        
        # List agents and find by name or use first one
        resp = self._client.get("/v1/agents")
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to list agents: {resp.text}")
        
        data = resp.json()
        agents = data.get("data", data) if isinstance(data.get("data", data), list) else []
        
        # Find by name if specified
        if self.name:
            for agent in agents:
                if agent.get("name") == self.name:
                    return agent
        
        # Use first agent if available
        if agents:
            return agents[0]
        
        # Create new agent
        return self._create_agent()
    
    def _create_agent(self) -> Dict[str, Any]:
        """Create a new agent."""
        name = self.name or f"Agent-{os.urandom(4).hex()}"
        
        resp = self._client.post("/v1/agents", json={
            "name": name,
            "protocol": "a2a",
        })
        
        if resp.status_code not in (200, 201):
            raise RuntimeError(f"Failed to create agent: {resp.text}")
        
        data = resp.json()
        logger.info(f"Created new agent: {name}")
        return data.get("data", data)
    
    def _init_identity(self) -> str:
        """Initialize identity via capiscio-core Init RPC.
        
        This is the "Let's Encrypt" style one-call setup that:
        1. Generates Ed25519 key pair
        2. Derives did:key URI
        3. Registers DID with the server
        4. Creates agent-card.json
        
        All cryptographic operations are performed by capiscio-core Go library.
        """
        did_file_path = self.keys_dir / "did.txt"
        private_key_path = self.keys_dir / "private.jwk"
        
        # Check if we already have a DID and keys (for idempotency)
        if did_file_path.exists() and private_key_path.exists():
            logger.debug("Using existing identity from prior init")
            return did_file_path.read_text().strip()
        
        # Connect to capiscio-core gRPC
        if not self._rpc_client:
            self._rpc_client = CapiscioRPCClient()
            self._rpc_client.connect()
        
        logger.info("Initializing identity via capiscio-core Init RPC...")
        
        # Call Init RPC - one call does everything
        result, error = self._rpc_client.simpleguard.init(
            api_key=self.api_key,
            agent_id=self.agent_id,
            server_url=self.server_url,
            output_dir=str(self.keys_dir),
            force=False,
        )
        
        if error:
            raise ConfigurationError(f"Failed to initialize identity: {error}")
        
        did = result["did"]
        
        # Save DID for future reference (idempotency check)
        did_file_path.write_text(did)
        
        logger.info(f"Identity initialized: {did}")
        if result.get("registered"):
            logger.info("DID registered with server")
        
        return did
    
    def _setup_badge(self):
        """Set up BadgeKeeper for automatic badge management."""
        try:
            from .badge_keeper import BadgeKeeper
            from .simple_guard import SimpleGuard
            
            # Set up SimpleGuard with correct parameters
            guard = SimpleGuard(
                base_dir=str(self.keys_dir.parent),
                agent_id=self.agent_id,
                dev_mode=self.dev_mode,
            )
            
            # Set up BadgeKeeper with correct parameters
            keeper = BadgeKeeper(
                api_url=self.server_url,
                api_key=self.api_key,
                agent_id=self.agent_id,
                mode="dev" if self.dev_mode else "ca",
                output_file=str(self.keys_dir / "badge.jwt"),
            )
            
            # Start the keeper and get initial badge
            keeper.start()
            badge = keeper.get_current_badge()
            expires_at = getattr(keeper, 'badge_expires_at', None)
            
            return badge, expires_at, keeper, guard
            
        except Exception as e:
            logger.warning(f"Badge setup failed (continuing without badge): {e}")
            return None, None, None, None


# Convenience alias
connect = CapiscIO.connect
from_env = CapiscIO.from_env
