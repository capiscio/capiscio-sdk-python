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

import json
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


# =============================================================================
# Standalone Helper Functions (for testing and direct use)
# =============================================================================

def _read_did_from_keys(identity_path: Path) -> Optional[str]:
    """
    Read DID from an identity directory.
    
    Per RFC-002 §6.1, did:key is deterministically derived from the public key,
    so public.jwk kid field is authoritative. Falls back to did.txt for legacy.
    
    Args:
        identity_path: Path to identity directory containing key files
        
    Returns:
        DID string or None if not recoverable
    """
    # Primary: public.jwk kid field (RFC-002 §6.1 - authoritative source)
    public_jwk_path = identity_path / "public.jwk"
    if public_jwk_path.exists():
        try:
            with open(public_jwk_path) as f:
                public_jwk = json.load(f)
                if "kid" in public_jwk:
                    logger.debug("Recovered DID from public.jwk kid field")
                    return public_jwk["kid"]
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to read public.jwk: {e}")
    
    # Fallback: did.txt (legacy/explicit override)
    did_txt = identity_path / "did.txt"
    if did_txt.exists():
        did = did_txt.read_text().strip()
        if did:
            logger.debug("Recovered DID from did.txt (legacy)")
            return did
    
    return None


def _ensure_did_registered(
    server_url: str,
    api_key: str,
    agent_id: str,
    did: str,
    public_key_jwk: Optional[dict] = None,
) -> bool:
    """
    Ensure DID is registered with the server.
    
    Uses PATCH /v1/sdk/agents/{id}/identity endpoint.
    Handles 409 Conflict as success (identity already registered).
    
    Args:
        server_url: Registry server URL
        api_key: API key for authentication
        agent_id: Agent UUID
        did: DID to register
        public_key_jwk: Optional public key JWK dict (Ed25519 format)
        
    Returns:
        True if registered (or already exists), False on error
    """
    url = f"{server_url}/v1/sdk/agents/{agent_id}/identity"
    headers = {
        "X-Capiscio-Registry-Key": api_key,
        "Content-Type": "application/json",
    }
    payload = {"did": did}
    if public_key_jwk:
        payload["publicKey"] = public_key_jwk
    
    try:
        resp = httpx.patch(url, headers=headers, json=payload, timeout=30.0)
        
        if resp.status_code == 200:
            logger.debug(f"DID registered successfully: {did}")
            return True
        elif resp.status_code == 409:
            # Identity already exists - this is fine for recovery
            logger.debug(f"DID already registered (409 Conflict): {did}")
            return True
        else:
            logger.warning(f"DID registration failed: {resp.status_code} - {resp.text}")
            return False
            
    except httpx.RequestError as e:
        logger.warning(f"DID registration request failed: {e}")
        return False


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
    
    def close(self) -> None:
        """Clean up resources."""
        if self._emitter:
            self._emitter.close()
            self._emitter = None
        if self._keeper:
            try:
                self._keeper.stop()
            except Exception:
                pass
            self._keeper = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


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
        
        try:
            # Step 1: Find or create agent
            agent_data = self._ensure_agent()
            self.agent_id = agent_data["id"]
            self.name = agent_data.get("name") or self.name or f"Agent-{self.agent_id[:8]}"
            
            logger.info(f"Agent: {self.name} ({self.agent_id})")
            
            # Step 2: Set up keys directory
            # For default keys_dir, use {DEFAULT_KEYS_DIR}/{agent_id}/ for multi-agent support.
            # For user-provided keys_dir, preserve exact path for backward compatibility.
            if self.keys_dir is None:
                self.keys_dir = DEFAULT_KEYS_DIR / self.agent_id
            self.keys_dir.mkdir(parents=True, exist_ok=True)
            
            # Step 3: Initialize identity via capiscio-core Init RPC (one call does everything)
            # If keys already exist locally, we recover the DID without calling core.
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
        finally:
            # Clean up clients to avoid resource leaks
            if self._rpc_client:
                try:
                    self._rpc_client.close()
                except Exception:
                    pass
            self._client.close()
    
    def _ensure_agent(self) -> Dict[str, Any]:
        """Find existing agent or create new one.
        
        Priority order:
        1. If agent_id is provided explicitly, use that
        2. If local keys exist, use that agent (prevents duplicates)
        3. Search by name on server
        4. Use first available agent
        5. Create new agent
        
        This prevents accidentally creating duplicate agents when names change.
        """
        try:
            if self.agent_id:
                # Fetch specific agent
                resp = self._client.get(f"/v1/agents/{self.agent_id}")
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("data", data)
                elif resp.status_code == 404:
                    raise ValueError(f"Agent {self.agent_id} not found")
                else:
                    raise RuntimeError(f"Failed to fetch agent (status {resp.status_code})")
            
            # Check for local keys directory - if we have keys, use that agent
            local_agent = self._find_agent_from_local_keys()
            if local_agent:
                logger.debug(f"Found local identity for agent {local_agent['id']}")
                return local_agent
            
            # List agents and find by name or use first one
            resp = self._client.get("/v1/agents")
            if resp.status_code != 200:
                raise RuntimeError(f"Failed to list agents (status {resp.status_code})")
        except httpx.RequestError as e:
            raise RuntimeError(f"Network error connecting to server: {type(e).__name__}") from e
        
        data = resp.json()
        agents = data.get("data", data) if isinstance(data.get("data", data), list) else []
        
        # Find by name if specified
        if self.name:
            for agent in agents:
                if agent.get("name") == self.name:
                    return agent
            # Name specified but not found - create new agent with that name
            return self._create_agent()
        
        # No name specified - use first agent if available
        if agents:
            return agents[0]
        
        # No agents exist - create new agent
        return self._create_agent()
    
    def _find_agent_from_local_keys(self) -> Optional[Dict[str, Any]]:
        """Check if we have local keys for any agent and verify it exists on server.
        
        This prevents creating duplicate agents when the same machine reconnects.
        Keys define identity - we match by finding agent_id subdirectories with valid keys
        and verifying the agent exists on the server with matching DID.
        """
        import re
        uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
        
        # Check user-provided keys_dir first, then default
        search_dirs = []
        if self.keys_dir and Path(self.keys_dir).exists():
            user_keys_dir = Path(self.keys_dir)
            search_dirs.append(user_keys_dir)
            
            # Backward compat: check if user provided flat keys_dir (keys directly in dir)
            if (user_keys_dir / "private.jwk").exists() and (user_keys_dir / "public.jwk").exists():
                # Flat structure - check if parent dir name is UUID
                if uuid_pattern.match(user_keys_dir.name):
                    local_did = _read_did_from_keys(user_keys_dir)
                    if local_did:
                        agent_id = user_keys_dir.name
                        try:
                            resp = self._client.get(f"/v1/agents/{agent_id}")
                            if resp.status_code == 200:
                                agent_data = resp.json().get("data", resp.json())
                                server_did = agent_data.get("did")
                                # Verify DID matches if server has one
                                if not server_did or server_did == local_did:
                                    return agent_data
                                logger.debug(f"DID mismatch: local={local_did}, server={server_did}")
                        except Exception:
                            pass
                            
        if DEFAULT_KEYS_DIR.exists():
            search_dirs.append(DEFAULT_KEYS_DIR)
        
        if not search_dirs:
            return None
        
        # Scan keys directories for agent subdirs with valid keys
        try:
            for keys_base in search_dirs:
                for subdir in keys_base.iterdir():
                    if not subdir.is_dir():
                        continue
                    
                    private_key = subdir / "private.jwk"
                    public_key = subdir / "public.jwk"
                    
                    if not (private_key.exists() and public_key.exists()):
                        continue
                    
                    # Found keys - verify agent_id looks like a UUID before API call
                    agent_id = subdir.name
                    if not uuid_pattern.match(agent_id):
                        logger.debug(f"Skipping non-UUID directory: {agent_id}")
                        continue
                    
                    # Read local DID for verification
                    local_did = _read_did_from_keys(subdir)
                    
                    # Verify agent exists on server with matching DID
                    try:
                        resp = self._client.get(f"/v1/agents/{agent_id}")
                        if resp.status_code == 200:
                            agent_data = resp.json().get("data", resp.json())
                            server_did = agent_data.get("did")
                            
                            # If server has DID, verify it matches local keys
                            if server_did and local_did and server_did != local_did:
                                logger.warning(f"DID mismatch for {agent_id}: local={local_did}, server={server_did}")
                                continue  # Don't use mismatched agent
                            
                            return agent_data
                    except Exception:
                        continue  # Agent doesn't exist or network error
        except Exception:
            pass  # Can't scan directory, continue with normal flow
        
        return None
    
    def _create_agent(self) -> Dict[str, Any]:
        """Create a new agent."""
        name = self.name or f"Agent-{os.urandom(4).hex()}"
        
        try:
            resp = self._client.post("/v1/agents", json={
                "name": name,
                "protocol": "a2a",
            })
        except httpx.RequestError as e:
            raise RuntimeError(f"Network error creating agent: {type(e).__name__}") from e
        
        if resp.status_code not in (200, 201):
            raise RuntimeError(f"Failed to create agent (status {resp.status_code})")
        
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
        
        Identity Recovery:
        - If keys exist locally (private.jwk + public.jwk), we derive the DID
          from public.jwk's `kid` field (per RFC-002 §6.1: did:key is self-describing)
        - No did.txt file is required - it's redundant
        - If server has a did:web assigned, we use that instead
        """
        private_key_path = self.keys_dir / "private.jwk"
        public_key_path = self.keys_dir / "public.jwk"
        
        # Check if we already have keys (for idempotency)
        if private_key_path.exists() and public_key_path.exists():
            logger.debug("Found existing keys - recovering identity")
            
            # Derive DID from public key's kid field (RFC-002 §6.1: did:key is self-describing)
            try:
                public_jwk = json.loads(public_key_path.read_text())
                did = public_jwk.get("kid")
                if did and did.startswith("did:"):
                    logger.info(f"Recovered identity from existing keys: {did}")
                    
                    # Ensure DID is registered with server (may have failed previously)
                    # Server's DID is authoritative - may be did:web instead of did:key
                    server_did = self._ensure_did_registered(did, public_jwk)
                    
                    return server_did if server_did else did
                else:
                    logger.warning("public.jwk exists but has no valid kid field - regenerating")
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to read public.jwk: {e} - regenerating")
        
        # No valid keys exist - generate new identity via Init RPC
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
            # Log detailed error for debugging, but avoid exposing it in the exception
            logger.error(f"Init RPC failed during identity initialization: {error}")
            raise ConfigurationError("Failed to initialize identity. Check logs for details.")
        
        did = result["did"]
        
        logger.info(f"Identity initialized: {did}")
        if result.get("registered"):
            logger.info("DID registered with server")
        
        return did
    
    def _ensure_did_registered(self, did: str, public_jwk: dict) -> Optional[str]:
        """Ensure the DID is registered with the server.
        
        This handles the case where keys were generated but server registration failed.
        
        Returns:
            Server's DID if different from local DID, None otherwise.
        """
        try:
            # Check if server already has a DID for this agent
            resp = self._client.get(f"/v1/agents/{self.agent_id}")
            if resp.status_code != 200:
                logger.warning(f"Failed to check agent DID status: {resp.status_code}")
                return None
            
            agent_data = resp.json().get("data", resp.json())
            server_did = agent_data.get("did")
            
            if server_did:
                # Server has a DID - could be did:web (production) or did:key
                if server_did != did:
                    logger.info(f"Server has different DID ({server_did}), using server's (authoritative)")
                    return server_did  # Return server's DID so caller can use it
                return None
            
            # Server has no DID - try to register using PATCH (partial update)
            logger.info("Registering DID with server...")
            
            resp = self._client.patch(
                f"/v1/sdk/agents/{self.agent_id}/identity",
                json={"did": did, "publicKey": public_jwk},
            )
            
            if resp.status_code == 200:
                logger.info("DID registered with server")
            elif resp.status_code == 409:
                # Identity already exists (RFC-003 §9.5 immutability) - this is expected
                logger.debug("Identity already registered (immutable per RFC-003)")
            else:
                # Endpoint may not exist or may have issues - log but continue
                logger.warning(f"DID registration returned {resp.status_code} - continuing with local DID")
                
        except Exception as e:
            # Don't fail connection just because registration failed
            logger.warning(f"DID registration check failed: {e} - continuing with local DID")
        
        return None
    
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
            # Get expiration from keeper if available, otherwise None
            expires_at = None
            if hasattr(keeper, 'badge_expires_at'):
                expires_at = keeper.badge_expires_at
            elif hasattr(keeper, 'get_badge_expiration'):
                expires_at = keeper.get_badge_expiration()
            
            return badge, expires_at, keeper, guard
            
        except Exception as e:
            logger.warning(f"Badge setup failed (continuing without badge): {e}")
            return None, None, None, None


# Convenience alias
connect = CapiscIO.connect
from_env = CapiscIO.from_env
