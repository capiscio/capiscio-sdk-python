"""gRPC client wrapper for capiscio-core."""

from typing import Generator, Optional

import grpc

from capiscio_sdk._rpc.process import ProcessManager, get_process_manager

# Import generated stubs
from capiscio_sdk._rpc.gen.capiscio.v1 import badge_pb2, badge_pb2_grpc
from capiscio_sdk._rpc.gen.capiscio.v1 import did_pb2, did_pb2_grpc
from capiscio_sdk._rpc.gen.capiscio.v1 import mcp_pb2, mcp_pb2_grpc
from capiscio_sdk._rpc.gen.capiscio.v1 import trust_pb2, trust_pb2_grpc
from capiscio_sdk._rpc.gen.capiscio.v1 import revocation_pb2, revocation_pb2_grpc
from capiscio_sdk._rpc.gen.capiscio.v1 import scoring_pb2, scoring_pb2_grpc
from capiscio_sdk._rpc.gen.capiscio.v1 import simpleguard_pb2, simpleguard_pb2_grpc
from capiscio_sdk._rpc.gen.capiscio.v1 import registry_pb2, registry_pb2_grpc


class CapiscioRPCClient:
    """High-level gRPC client for capiscio-core.
    
    This client manages the connection to the capiscio-core gRPC server
    and provides access to all services.
    
    Usage:
        # Auto-start local server
        client = CapiscioRPCClient()
        client.connect()
        
        # Use DID service
        result = client.did.parse("did:web:example.com:agents:my-agent")
        
        # Use badge service
        badge = client.badge.parse_badge(token)
        
        client.close()
        
        # Or use as context manager
        with CapiscioRPCClient() as client:
            result = client.did.parse("did:web:example.com")
    """
    
    def __init__(
        self,
        address: Optional[str] = None,
        auto_start: bool = True,
    ) -> None:
        """Initialize the client.
        
        Args:
            address: gRPC server address. If None, auto-starts local server.
            auto_start: Whether to auto-start local server if address is None.
        """
        self._address = address
        self._auto_start = auto_start and address is None
        self._channel: Optional[grpc.Channel] = None
        self._process_manager: Optional[ProcessManager] = None
        
        # Service stubs (initialized on connect)
        self._badge_stub: Optional[badge_pb2_grpc.BadgeServiceStub] = None
        self._did_stub: Optional[did_pb2_grpc.DIDServiceStub] = None
        self._mcp_stub: Optional[mcp_pb2_grpc.MCPServiceStub] = None
        self._trust_stub: Optional[trust_pb2_grpc.TrustStoreServiceStub] = None
        self._revocation_stub: Optional[revocation_pb2_grpc.RevocationServiceStub] = None
        self._scoring_stub: Optional[scoring_pb2_grpc.ScoringServiceStub] = None
        self._simpleguard_stub: Optional[simpleguard_pb2_grpc.SimpleGuardServiceStub] = None
        self._registry_stub: Optional[registry_pb2_grpc.RegistryServiceStub] = None
        
        # Service wrappers
        self._badge: Optional["BadgeClient"] = None
        self._did: Optional["DIDClient"] = None
        self._mcp: Optional["MCPClient"] = None
        self._trust: Optional["TrustStoreClient"] = None
        self._revocation: Optional["RevocationClient"] = None
        self._scoring: Optional["ScoringClient"] = None
        self._simpleguard: Optional["SimpleGuardClient"] = None
        self._registry: Optional["RegistryClient"] = None
    
    def connect(self, timeout: float = 10.0) -> "CapiscioRPCClient":
        """Connect to the gRPC server.
        
        Args:
            timeout: Connection timeout in seconds
            
        Returns:
            self for chaining
        """
        if self._channel is not None:
            return self  # Already connected
        
        # Determine address
        address = self._address
        if address is None and self._auto_start:
            self._process_manager = get_process_manager()
            address = self._process_manager.ensure_running(timeout=timeout)
        elif address is None:
            address = "unix:///tmp/capiscio.sock"
        
        # Create channel
        if address.startswith("unix://"):
            self._channel = grpc.insecure_channel(address)
        else:
            self._channel = grpc.insecure_channel(address)
        
        # Initialize stubs
        self._badge_stub = badge_pb2_grpc.BadgeServiceStub(self._channel)
        self._did_stub = did_pb2_grpc.DIDServiceStub(self._channel)
        self._mcp_stub = mcp_pb2_grpc.MCPServiceStub(self._channel)
        self._trust_stub = trust_pb2_grpc.TrustStoreServiceStub(self._channel)
        self._revocation_stub = revocation_pb2_grpc.RevocationServiceStub(self._channel)
        self._scoring_stub = scoring_pb2_grpc.ScoringServiceStub(self._channel)
        self._simpleguard_stub = simpleguard_pb2_grpc.SimpleGuardServiceStub(self._channel)
        self._registry_stub = registry_pb2_grpc.RegistryServiceStub(self._channel)
        
        # Initialize service wrappers
        self._badge = BadgeClient(self._badge_stub)
        self._did = DIDClient(self._did_stub)
        self._mcp = MCPClient(self._mcp_stub)
        self._trust = TrustStoreClient(self._trust_stub)
        self._revocation = RevocationClient(self._revocation_stub)
        self._scoring = ScoringClient(self._scoring_stub)
        self._simpleguard = SimpleGuardClient(self._simpleguard_stub)
        self._registry = RegistryClient(self._registry_stub)
        
        return self
    
    def close(self) -> None:
        """Close the connection."""
        if self._channel is not None:
            self._channel.close()
            self._channel = None
        
        # Clear stubs
        self._badge_stub = None
        self._did_stub = None
        self._mcp_stub = None
        self._trust_stub = None
        self._revocation_stub = None
        self._scoring_stub = None
        self._simpleguard_stub = None
        self._registry_stub = None
    
    def __enter__(self) -> "CapiscioRPCClient":
        return self.connect()
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
    
    def _ensure_connected(self) -> None:
        if self._channel is None:
            self.connect()
    
    @property
    def badge(self) -> "BadgeClient":
        """Access the BadgeService."""
        self._ensure_connected()
        assert self._badge is not None
        return self._badge
    
    @property
    def did(self) -> "DIDClient":
        """Access the DIDService."""
        self._ensure_connected()
        assert self._did is not None
        return self._did
    
    @property
    def mcp(self) -> "MCPClient":
        """Access the MCPService (RFC-006 / RFC-007)."""
        self._ensure_connected()
        assert self._mcp is not None
        return self._mcp
    
    @property
    def trust(self) -> "TrustStoreClient":
        """Access the TrustStoreService."""
        self._ensure_connected()
        assert self._trust is not None
        return self._trust
    
    @property
    def revocation(self) -> "RevocationClient":
        """Access the RevocationService."""
        self._ensure_connected()
        assert self._revocation is not None
        return self._revocation
    
    @property
    def scoring(self) -> "ScoringClient":
        """Access the ScoringService."""
        self._ensure_connected()
        assert self._scoring is not None
        return self._scoring
    
    @property
    def simpleguard(self) -> "SimpleGuardClient":
        """Access the SimpleGuardService."""
        self._ensure_connected()
        assert self._simpleguard is not None
        return self._simpleguard
    
    @property
    def registry(self) -> "RegistryClient":
        """Access the RegistryService."""
        self._ensure_connected()
        assert self._registry is not None
        return self._registry


class BadgeClient:
    """Client wrapper for BadgeService."""
    
    def __init__(self, stub: badge_pb2_grpc.BadgeServiceStub) -> None:
        self._stub = stub
    
    def sign_badge(
        self,
        claims: dict,
        private_key_jwk: str,
        key_id: str = "",
    ) -> tuple[str, dict]:
        """Sign a new badge.
        
        Args:
            claims: Badge claims dictionary
            private_key_jwk: Private key in JWK JSON format
            key_id: Optional key ID
            
        Returns:
            Tuple of (token, claims)
        """
        pb_claims = badge_pb2.BadgeClaims(
            jti=claims.get("jti", ""),
            iss=claims.get("iss", ""),
            sub=claims.get("sub", ""),
            iat=claims.get("iat", 0),
            exp=claims.get("exp", 0),
            aud=claims.get("aud", []),
            domain=claims.get("domain", ""),
            agent_name=claims.get("agent_name", ""),
        )
        
        request = badge_pb2.SignBadgeRequest(
            claims=pb_claims,
            private_key_jwk=private_key_jwk,
            key_id=key_id,
        )
        
        response = self._stub.SignBadge(request)
        return response.token, _claims_to_dict(response.claims)
    
    def verify_badge(
        self,
        token: str,
        public_key_jwk: str = "",
    ) -> tuple[bool, Optional[dict], Optional[str]]:
        """Verify a badge token.
        
        Args:
            token: Badge JWT token
            public_key_jwk: Public key in JWK JSON format
            
        Returns:
            Tuple of (valid, claims, error_message)
        """
        request = badge_pb2.VerifyBadgeRequest(
            token=token,
            public_key_jwk=public_key_jwk,
        )
        
        response = self._stub.VerifyBadge(request)
        claims = _claims_to_dict(response.claims) if response.claims else None
        error = response.error_message if response.error_message else None
        return response.valid, claims, error
    
    def verify_badge_with_options(
        self,
        token: str,
        accept_self_signed: bool = False,
        trusted_issuers: Optional[list[str]] = None,
        audience: str = "",
        skip_revocation: bool = False,
        skip_agent_status: bool = False,
        mode: str = "online",
        fail_open: bool = False,
        stale_threshold_seconds: int = 300,
    ) -> tuple[bool, Optional[dict], list[str], Optional[str]]:
        """Verify a badge token with full options.
        
        This is the recommended method for verifying badges, especially
        self-signed (Level 0) badges from did:key issuers.
        
        Args:
            token: Badge JWT token
            accept_self_signed: Accept Level 0 self-signed badges (did:key issuer)
            trusted_issuers: List of trusted issuer DIDs
            audience: Expected audience (your service's identifier)
            skip_revocation: Skip revocation check
            skip_agent_status: Skip agent status check
            mode: Verification mode ('online', 'offline', 'hybrid')
            fail_open: RFC-002 v1.3 §7.5 - Allow verification when cache is stale (default: False)
            stale_threshold_seconds: RFC-002 v1.3 §7.5 - Max cache staleness in seconds (default: 300)
            
        Returns:
            Tuple of (valid, claims, warnings, error_message)
            
        Example:
            # Verify a self-signed badge
            valid, claims, warnings, error = client.badge.verify_badge_with_options(
                token,
                accept_self_signed=True,
            )
            if valid:
                print(f"Badge valid for {claims['sub']}")
                print(f"Trust level: {claims['trust_level']}")
        """
        # Map mode string to proto enum
        mode_map = {
            "online": badge_pb2.VerifyMode.VERIFY_MODE_ONLINE,
            "offline": badge_pb2.VerifyMode.VERIFY_MODE_OFFLINE,
            "hybrid": badge_pb2.VerifyMode.VERIFY_MODE_HYBRID,
        }
        verify_mode = mode_map.get(mode.lower(), badge_pb2.VerifyMode.VERIFY_MODE_ONLINE)
        
        options = badge_pb2.VerifyOptions(
            mode=verify_mode,
            trusted_issuers=trusted_issuers or [],
            audience=audience,
            skip_revocation=skip_revocation,
            skip_agent_status=skip_agent_status,
            accept_self_signed=accept_self_signed,
            fail_open=fail_open,
            stale_threshold_seconds=stale_threshold_seconds,
        )
        
        request = badge_pb2.VerifyBadgeWithOptionsRequest(
            token=token,
            options=options,
        )
        
        response = self._stub.VerifyBadgeWithOptions(request)
        claims = _claims_to_dict(response.claims) if response.claims else None
        warnings = list(response.warnings) if response.warnings else []
        error = response.error_message if response.error_message else None
        return response.valid, claims, warnings, error
    
    def parse_badge(self, token: str) -> tuple[Optional[dict], Optional[str]]:
        """Parse badge claims without verification.
        
        Args:
            token: Badge JWT token
            
        Returns:
            Tuple of (claims, error_message)
        """
        request = badge_pb2.ParseBadgeRequest(token=token)
        response = self._stub.ParseBadge(request)
        claims = _claims_to_dict(response.claims) if response.claims else None
        error = response.error_message if response.error_message else None
        return claims, error

    def request_badge(
        self,
        agent_id: str,
        api_key: str,
        ca_url: str = "",
        domain: str = "",
        ttl_seconds: int = 300,
        trust_level: int = 1,
        audience: Optional[list[str]] = None,
    ) -> tuple[bool, Optional[dict], Optional[str]]:
        """Request a badge from a Certificate Authority (RFC-002 §12.1).
        
        This requests a new badge from the CapiscIO registry CA. The badge
        is signed by the CA and can be used for authenticated A2A communication.
        
        Args:
            agent_id: Agent UUID to request badge for
            api_key: API key for authentication (sk_live_... or sk_test_...)
            ca_url: CA URL (default: https://registry.capisc.io)
            domain: Agent domain (optional, uses registered domain)
            ttl_seconds: Badge TTL in seconds (default: 300 per RFC-002)
            trust_level: Trust level 1-4 (default: 1=DV)
            audience: Optional audience restrictions
            
        Returns:
            Tuple of (success, result_dict, error_message)
            result_dict contains: token, jti, subject, trust_level, expires_at
            
        Example:
            success, result, error = client.badge.request_badge(
                agent_id="my-agent-uuid",
                api_key=os.environ["CAPISCIO_API_KEY"],
            )
            if success:
                token = result["token"]
                print(f"Badge expires: {result['expires_at']}")
        """
        # Map trust level int to proto enum
        trust_level_map = {
            0: badge_pb2.TrustLevel.TRUST_LEVEL_SELF_SIGNED,
            1: badge_pb2.TrustLevel.TRUST_LEVEL_DV,
            2: badge_pb2.TrustLevel.TRUST_LEVEL_OV,
            3: badge_pb2.TrustLevel.TRUST_LEVEL_EV,
            4: badge_pb2.TrustLevel.TRUST_LEVEL_CV,
        }
        pb_trust_level = trust_level_map.get(
            trust_level, badge_pb2.TrustLevel.TRUST_LEVEL_DV
        )
        
        request = badge_pb2.RequestBadgeRequest(
            agent_id=agent_id,
            ca_url=ca_url,
            api_key=api_key,
            domain=domain,
            ttl_seconds=ttl_seconds,
            trust_level=pb_trust_level,
            audience=audience or [],
        )
        
        response = self._stub.RequestBadge(request)
        
        if not response.success:
            return False, None, response.error
        
        result = {
            "token": response.token,
            "jti": response.jti,
            "subject": response.subject,
            "trust_level": _trust_level_to_string(response.trust_level),
            "expires_at": response.expires_at,
        }
        return True, result, None

    def request_pop_badge(
        self,
        agent_did: str,
        private_key_jwk: str,
        api_key: str,
        ca_url: str = "",
        ttl_seconds: int = 300,
        audience: Optional[list[str]] = None,
    ) -> tuple[bool, Optional[dict], Optional[str]]:
        """Request a badge using Proof of Possession (RFC-003).
        
        This requests a badge using the PoP challenge-response protocol,
        providing IAL-1 assurance with cryptographic key binding.
        
        Args:
            agent_did: Agent DID (did:web:... or did:key:...)
            private_key_jwk: Private key in JWK format (JSON string)
            api_key: API key for authentication
            ca_url: CA URL (default: https://registry.capisc.io)
            ttl_seconds: Badge TTL in seconds (default: 300 per RFC-002)
            audience: Optional audience restrictions
            
        Returns:
            Tuple of (success, result_dict, error_message)
            result_dict contains: token, jti, subject, trust_level, 
                                 assurance_level, expires_at, cnf
            
        Example:
            import json
            
            # Load private key
            with open("private.jwk") as f:
                private_key_jwk = json.dumps(json.load(f))
            
            success, result, error = client.badge.request_pop_badge(
                agent_did="did:web:registry.capisc.io:agents:my-agent",
                private_key_jwk=private_key_jwk,
                api_key=os.environ["CAPISCIO_API_KEY"],
            )
            if success:
                token = result["token"]
                print(f"IAL-1 badge with cnf: {result['cnf']}")
        """
        request = badge_pb2.RequestPoPBadgeRequest(
            agent_did=agent_did,
            private_key_jwk=private_key_jwk,
            ca_url=ca_url,
            api_key=api_key,
            ttl_seconds=ttl_seconds,
            audience=audience or [],
        )
        
        response = self._stub.RequestPoPBadge(request)
        
        if not response.success:
            return False, None, response.error
        
        result = {
            "token": response.token,
            "jti": response.jti,
            "subject": response.subject,
            "trust_level": response.trust_level,
            "assurance_level": response.assurance_level,
            "expires_at": response.expires_at,
            "cnf": dict(response.cnf),
        }
        return True, result, None

    def start_keeper(
        self,
        mode: str,
        output_file: str = "badge.jwt",
        agent_id: str = "",
        api_key: str = "",
        ca_url: str = "",
        private_key_path: str = "",
        domain: str = "",
        ttl_seconds: int = 300,
        renew_before_seconds: int = 60,
        check_interval_seconds: int = 30,
        trust_level: int = 1,
    ) -> Generator[dict, None, None]:
        """Start a badge keeper daemon (RFC-002 §7.3).
        
        The keeper automatically renews badges before they expire, ensuring
        continuous operation. Returns a generator of keeper events.
        
        Args:
            mode: 'ca' for CA mode, 'self-sign' for development
            output_file: Path to write badge file
            agent_id: Agent UUID (required for CA mode)
            api_key: API key (required for CA mode)
            ca_url: CA URL (default: https://registry.capisc.io)
            private_key_path: Path to private key JWK (required for self-sign)
            domain: Agent domain
            ttl_seconds: Badge TTL (default: 300)
            renew_before_seconds: Renew this many seconds before expiry (default: 60)
            check_interval_seconds: Check interval (default: 30)
            trust_level: Trust level for CA mode (1-4, default: 1)
            
        Yields:
            dict: KeeperEvent dicts with keys: type, badge_jti, subject, trust_level,
                expires_at, error, error_code, timestamp, token
            
        Example:
            # CA mode
            for event in client.badge.start_keeper(
                mode="ca",
                agent_id="my-agent-uuid",
                api_key=os.environ["CAPISCIO_API_KEY"],
            ):
                if event["type"] == "renewed":
                    print(f"Badge renewed: {event['badge_jti']}")
                elif event["type"] == "error":
                    print(f"Error: {event['error']}")
        """
        # Map mode string to proto enum
        mode_map = {
            "ca": badge_pb2.KeeperMode.KEEPER_MODE_CA,
            "self-sign": badge_pb2.KeeperMode.KEEPER_MODE_SELF_SIGN,
            "self_sign": badge_pb2.KeeperMode.KEEPER_MODE_SELF_SIGN,
        }
        pb_mode = mode_map.get(mode.lower(), badge_pb2.KeeperMode.KEEPER_MODE_CA)
        
        # Map trust level int to proto enum
        trust_level_map = {
            0: badge_pb2.TrustLevel.TRUST_LEVEL_SELF_SIGNED,
            1: badge_pb2.TrustLevel.TRUST_LEVEL_DV,
            2: badge_pb2.TrustLevel.TRUST_LEVEL_OV,
            3: badge_pb2.TrustLevel.TRUST_LEVEL_EV,
            4: badge_pb2.TrustLevel.TRUST_LEVEL_CV,
        }
        pb_trust_level = trust_level_map.get(
            trust_level, badge_pb2.TrustLevel.TRUST_LEVEL_DV
        )
        
        request = badge_pb2.StartKeeperRequest(
            mode=pb_mode,
            agent_id=agent_id,
            ca_url=ca_url,
            api_key=api_key,
            output_file=output_file,
            ttl_seconds=ttl_seconds,
            renew_before_seconds=renew_before_seconds,
            check_interval_seconds=check_interval_seconds,
            private_key_path=private_key_path,
            domain=domain,
            trust_level=pb_trust_level,
        )
        
        # Stream events from keeper
        for event in self._stub.StartKeeper(request):
            yield _keeper_event_to_dict(event)

    def create_dv_order(
        self,
        domain: str,
        challenge_type: str,
        jwk: str,
        ca_url: str = "",
    ) -> tuple[bool, Optional[dict], Optional[str]]:
        """Create a Domain Validated badge order (RFC-002 v1.2).
        
        Args:
            domain: Domain to validate
            challenge_type: Challenge type ('http-01' or 'dns-01')
            jwk: Public key in JWK format (JSON string)
            ca_url: CA URL (default: https://registry.capisc.io)
            
        Returns:
            Tuple of (success, order_dict, error_message)
            order_dict contains: order_id, domain, challenge_type, 
                               challenge_token, status, validation_url, 
                               dns_record, expires_at
            
        Example:
            import json
            
            # Load public key
            with open("public.jwk") as f:
                jwk = json.dumps(json.load(f))
            
            success, order, error = client.badge.create_dv_order(
                domain="example.com",
                challenge_type="http-01",
                jwk=jwk,
            )
            if success:
                print(f"Order ID: {order['order_id']}")
                print(f"Validation URL: {order['validation_url']}")
        """
        request = badge_pb2.CreateDVOrderRequest(
            domain=domain,
            challenge_type=challenge_type,
            jwk=jwk,
            ca_url=ca_url,
        )
        
        response = self._stub.CreateDVOrder(request)
        
        if not response.success:
            return False, None, response.error
        
        from datetime import datetime, timezone
        
        order = {
            "order_id": response.order_id,
            "domain": response.domain,
            "challenge_type": response.challenge_type,
            "challenge_token": response.challenge_token,
            "status": response.status,
            "validation_url": response.validation_url,
            "dns_record": response.dns_record,
            "expires_at": datetime.fromtimestamp(response.expires_at, timezone.utc).isoformat() if response.expires_at else "",
        }
        return True, order, None

    def get_dv_order(
        self,
        order_id: str,
        ca_url: str = "",
    ) -> tuple[bool, Optional[dict], Optional[str]]:
        """Get the status of a DV badge order (RFC-002 v1.2).
        
        Args:
            order_id: Order ID from create_dv_order
            ca_url: CA URL (default: https://registry.capisc.io)
            
        Returns:
            Tuple of (success, order_dict, error_message)
            order_dict contains: order_id, domain, challenge_type, 
                               challenge_token, status, validation_url,
                               dns_record, expires_at, finalized_at (optional)
            
        Example:
            success, order, error = client.badge.get_dv_order(
                order_id="550e8400-e29b-41d4-a716-446655440000",
            )
            if success:
                print(f"Status: {order['status']}")
                if order.get('finalized_at'):
                    print(f"Finalized at: {order['finalized_at']}")
        """
        request = badge_pb2.GetDVOrderRequest(
            order_id=order_id,
            ca_url=ca_url,
        )
        
        response = self._stub.GetDVOrder(request)
        
        if not response.success:
            return False, None, response.error
        
        from datetime import datetime, timezone
        
        order = {
            "order_id": response.order_id,
            "domain": response.domain,
            "challenge_type": response.challenge_type,
            "challenge_token": response.challenge_token,
            "status": response.status,
            "validation_url": response.validation_url,
            "dns_record": response.dns_record,
            "expires_at": datetime.fromtimestamp(response.expires_at, timezone.utc).isoformat() if response.expires_at else "",
        }
        
        if response.finalized_at:
            order["finalized_at"] = datetime.fromtimestamp(response.finalized_at, timezone.utc).isoformat()
        
        return True, order, None

    def finalize_dv_order(
        self,
        order_id: str,
        ca_url: str = "",
    ) -> tuple[bool, Optional[dict], Optional[str]]:
        """Finalize a DV badge order and receive a grant (RFC-002 v1.2).
        
        Args:
            order_id: Order ID from create_dv_order
            ca_url: CA URL (default: https://registry.capisc.io)
            
        Returns:
            Tuple of (success, grant_dict, error_message)
            grant_dict contains: grant (JWT), expires_at
            
        Example:
            success, grant, error = client.badge.finalize_dv_order(
                order_id="550e8400-e29b-41d4-a716-446655440000",
            )
            if success:
                print(f"Grant JWT: {grant['grant']}")
                print(f"Expires at: {grant['expires_at']}")
                
                # Save grant for later use
                with open("grant.jwt", "w") as f:
                    f.write(grant['grant'])
        """
        request = badge_pb2.FinalizeDVOrderRequest(
            order_id=order_id,
            ca_url=ca_url,
        )
        
        response = self._stub.FinalizeDVOrder(request)
        
        if not response.success:
            return False, None, response.error
        
        from datetime import datetime, timezone
        
        grant = {
            "grant": response.grant,
            "expires_at": datetime.fromtimestamp(response.expires_at, timezone.utc).isoformat() if response.expires_at else "",
        }
        return True, grant, None


def _keeper_event_to_dict(event) -> dict:
    """Convert KeeperEvent proto to dict."""
    event_type_map = {
        badge_pb2.KeeperEventType.KEEPER_EVENT_STARTED: "started",
        badge_pb2.KeeperEventType.KEEPER_EVENT_RENEWED: "renewed",
        badge_pb2.KeeperEventType.KEEPER_EVENT_ERROR: "error",
        badge_pb2.KeeperEventType.KEEPER_EVENT_STOPPED: "stopped",
    }
    return {
        "type": event_type_map.get(event.type, "unknown"),
        "badge_jti": event.badge_jti,
        "subject": event.subject,
        "trust_level": _trust_level_to_string(event.trust_level),
        "expires_at": event.expires_at,
        "error": event.error,
        "error_code": event.error_code,
        "timestamp": event.timestamp,
        "token": event.token,
    }


def _trust_level_to_string(trust_level) -> str:
    """Convert TrustLevel proto enum to string."""
    level_map = {
        badge_pb2.TrustLevel.TRUST_LEVEL_SELF_SIGNED: "0",
        badge_pb2.TrustLevel.TRUST_LEVEL_DV: "1",
        badge_pb2.TrustLevel.TRUST_LEVEL_OV: "2",
        badge_pb2.TrustLevel.TRUST_LEVEL_EV: "3",
        badge_pb2.TrustLevel.TRUST_LEVEL_CV: "4",
    }
    return level_map.get(trust_level, "")


class DIDClient:
    """Client wrapper for DIDService."""
    
    def __init__(self, stub: did_pb2_grpc.DIDServiceStub) -> None:
        self._stub = stub
    
    def parse(self, did: str) -> tuple[Optional[dict], Optional[str]]:
        """Parse a did:web identifier.
        
        Args:
            did: DID string to parse
            
        Returns:
            Tuple of (parsed_did, error_message)
        """
        request = did_pb2.ParseDIDRequest(did=did)
        response = self._stub.Parse(request)
        
        if response.error_message:
            return None, response.error_message
        
        parsed = {
            "raw": response.did.raw,
            "method": response.did.method,
            "domain": response.did.domain,
            "path": list(response.did.path),
        }
        return parsed, None
    
    def new_agent_did(self, domain: str, agent_id: str) -> tuple[str, Optional[str]]:
        """Create a new agent DID.
        
        Args:
            domain: Domain for the DID
            agent_id: Agent identifier
            
        Returns:
            Tuple of (did, error_message)
        """
        request = did_pb2.NewAgentDIDRequest(domain=domain, agent_id=agent_id)
        response = self._stub.NewAgentDID(request)
        error = response.error_message if response.error_message else None
        return response.did, error
    
    def new_capiscio_agent_did(self, agent_id: str) -> tuple[str, Optional[str]]:
        """Create a CapiscIO registry agent DID.
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            Tuple of (did, error_message)
        """
        request = did_pb2.NewCapiscIOAgentDIDRequest(agent_id=agent_id)
        response = self._stub.NewCapiscIOAgentDID(request)
        error = response.error_message if response.error_message else None
        return response.did, error
    
    def document_url(self, did: str) -> tuple[str, Optional[str]]:
        """Get the document URL for a DID.
        
        Args:
            did: DID string
            
        Returns:
            Tuple of (url, error_message)
        """
        request = did_pb2.DocumentURLRequest(did=did)
        response = self._stub.DocumentURL(request)
        error = response.error_message if response.error_message else None
        return response.url, error
    
    def is_agent_did(self, did: str) -> tuple[bool, str]:
        """Check if a DID is an agent DID.
        
        Args:
            did: DID string
            
        Returns:
            Tuple of (is_agent_did, agent_id)
        """
        request = did_pb2.IsAgentDIDRequest(did=did)
        response = self._stub.IsAgentDID(request)
        return response.is_agent_did, response.agent_id


class TrustStoreClient:
    """Client wrapper for TrustStoreService."""
    
    def __init__(self, stub: trust_pb2_grpc.TrustStoreServiceStub) -> None:
        self._stub = stub
    
    def add_key(self, did: str, public_key: bytes, format: str = "JWK") -> tuple[str, Optional[str]]:
        """Add a trusted public key."""
        # TODO: Implement when Go service is complete
        raise NotImplementedError("TrustStoreService not yet implemented")
    
    def is_trusted(self, did: str) -> bool:
        """Check if a DID is trusted."""
        request = trust_pb2.IsTrustedRequest(did=did)
        response = self._stub.IsTrusted(request)
        return response.is_trusted


class RevocationClient:
    """Client wrapper for RevocationService."""
    
    def __init__(self, stub: revocation_pb2_grpc.RevocationServiceStub) -> None:
        self._stub = stub
    
    def is_revoked(self, subject: str) -> bool:
        """Check if a subject is revoked."""
        request = revocation_pb2.IsRevokedRequest(subject=subject)
        response = self._stub.IsRevoked(request)
        return response.is_revoked


class ScoringClient:
    """Client wrapper for ScoringService."""
    
    def __init__(self, stub: scoring_pb2_grpc.ScoringServiceStub) -> None:
        self._stub = stub
    
    def score_agent_card(self, agent_card_json: str) -> tuple[Optional[dict], Optional[str]]:
        """Score an agent card.
        
        Args:
            agent_card_json: Agent card as JSON string
            
        Returns:
            Tuple of (scoring_result_dict, error_message)
        """
        request = scoring_pb2.ScoreAgentCardRequest(agent_card_json=agent_card_json)
        response = self._stub.ScoreAgentCard(request)
        
        if response.error_message:
            return None, response.error_message
        
        if not response.result:
            return None, "No result returned"
        
        # Convert protobuf result to dict
        result = response.result
        return {
            "overall_score": result.overall_score,
            "rating": result.rating,
            "categories": [
                {
                    "category": cat.category,
                    "score": cat.score,
                    "rules_passed": cat.rules_passed,
                    "rules_failed": cat.rules_failed,
                }
                for cat in result.categories
            ],
            "rule_results": [
                {
                    "rule_id": r.rule_id,
                    "passed": r.passed,
                    "message": r.message,
                    "details": dict(r.details),
                }
                for r in result.rule_results
            ],
            "validation": {
                "valid": result.validation.valid if result.validation else True,
                "issues": [
                    {
                        "code": i.code,
                        "message": i.message,
                        "severity": i.severity,
                        "field": i.field,
                    }
                    for i in (result.validation.issues if result.validation else [])
                ],
            },
            "scored_at": result.scored_at.value if result.scored_at else None,
            "rule_set_id": result.rule_set_id,
            "rule_set_version": result.rule_set_version,
        }, None
    
    def validate_rule(self, rule_id: str, agent_card_json: str) -> tuple[Optional[dict], Optional[str]]:
        """Validate a single rule against an agent card.
        
        Args:
            rule_id: ID of the rule to validate
            agent_card_json: Agent card as JSON string
            
        Returns:
            Tuple of (rule_result_dict, error_message)
        """
        request = scoring_pb2.ValidateRuleRequest(
            rule_id=rule_id,
            agent_card_json=agent_card_json,
        )
        response = self._stub.ValidateRule(request)
        
        if response.error_message:
            return None, response.error_message
        
        if not response.result:
            return None, "No result returned"
        
        return {
            "rule_id": response.result.rule_id,
            "passed": response.result.passed,
            "message": response.result.message,
            "details": dict(response.result.details),
        }, None
    
    def list_rule_sets(self) -> tuple[list[dict], Optional[str]]:
        """List available rule sets.
        
        Returns:
            Tuple of (list_of_rule_sets, error_message)
        """
        request = scoring_pb2.ListRuleSetsRequest()
        response = self._stub.ListRuleSets(request)
        
        rule_sets = []
        for rs in response.rule_sets:
            rule_sets.append({
                "id": rs.id,
                "name": rs.name,
                "version": rs.version,
                "description": rs.description,
                "rules": [
                    {
                        "id": r.id,
                        "name": r.name,
                        "description": r.description,
                        "category": r.category,
                        "severity": r.severity,
                        "weight": r.weight,
                    }
                    for r in rs.rules
                ],
            })
        
        return rule_sets, None
    
    def get_rule_set(self, rule_set_id: str) -> tuple[Optional[dict], Optional[str]]:
        """Get details of a specific rule set.
        
        Args:
            rule_set_id: ID of the rule set
            
        Returns:
            Tuple of (rule_set_dict, error_message)
        """
        request = scoring_pb2.GetRuleSetRequest(id=rule_set_id)
        response = self._stub.GetRuleSet(request)
        
        if response.error_message:
            return None, response.error_message
        
        if not response.rule_set:
            return None, "No rule set returned"
        
        rs = response.rule_set
        return {
            "id": rs.id,
            "name": rs.name,
            "version": rs.version,
            "description": rs.description,
            "rules": [
                {
                    "id": r.id,
                    "name": r.name,
                    "description": r.description,
                    "category": r.category,
                    "severity": r.severity,
                    "weight": r.weight,
                }
                for r in rs.rules
            ],
        }, None
    
    def aggregate_scores(
        self, 
        results: list[dict], 
        method: str = "average"
    ) -> tuple[Optional[dict], Optional[str]]:
        """Aggregate multiple scoring results.
        
        Args:
            results: List of scoring result dicts with 'overall_score' key
            method: Aggregation method ('average', 'min', 'max')
            
        Returns:
            Tuple of (aggregate_result, error_message)
        """
        # Convert dicts to protobuf messages
        pb_results = []
        for r in results:
            pb_results.append(scoring_pb2.ScoringResult(
                overall_score=r.get("overall_score", 0),
            ))
        
        request = scoring_pb2.AggregateScoresRequest(
            results=pb_results,
            aggregation_method=method,
        )
        response = self._stub.AggregateScores(request)
        
        return {
            "aggregate_score": response.aggregate_score,
            "aggregate_rating": response.aggregate_rating,
            "category_aggregates": dict(response.category_aggregates),
        }, None


class SimpleGuardClient:
    """Client wrapper for SimpleGuardService."""
    
    def __init__(self, stub: simpleguard_pb2_grpc.SimpleGuardServiceStub) -> None:
        self._stub = stub
    
    def sign(self, payload: bytes, key_id: str) -> tuple[bytes, Optional[str]]:
        """Sign a message (raw signature).
        
        Args:
            payload: Message bytes to sign
            key_id: Key ID to use for signing
            
        Returns:
            Tuple of (signature_bytes, error_message)
        """
        request = simpleguard_pb2.SignRequest(payload=payload, key_id=key_id)
        response = self._stub.Sign(request)
        error = response.error_message if response.error_message else None
        return response.signature, error
    
    def verify(
        self, payload: bytes, signature: bytes, expected_signer: str = ""
    ) -> tuple[bool, str, Optional[str]]:
        """Verify a signed message.
        
        Args:
            payload: Original message bytes
            signature: Signature bytes to verify
            expected_signer: Optional expected signer key ID
            
        Returns:
            Tuple of (valid, key_id, error_message)
        """
        request = simpleguard_pb2.VerifyRequest(
            payload=payload,
            signature=signature,
            expected_signer=expected_signer,
        )
        response = self._stub.Verify(request)
        error = response.error_message if response.error_message else None
        return response.valid, response.key_id, error
    
    def sign_attached(
        self,
        payload: bytes,
        key_id: str,
        headers: Optional[dict] = None,
    ) -> tuple[str, Optional[str]]:
        """Sign with attached payload (creates JWS).
        
        Args:
            payload: Payload bytes
            key_id: Key ID to use
            headers: Optional additional JWS headers
            
        Returns:
            Tuple of (jws_token, error_message)
        """
        request = simpleguard_pb2.SignAttachedRequest(
            payload=payload,
            key_id=key_id,
            headers=headers or {},
        )
        response = self._stub.SignAttached(request)
        error = response.error_message if response.error_message else None
        return response.jws, error
    
    def verify_attached(
        self,
        jws: str,
        body: Optional[bytes] = None,
    ) -> tuple[bool, Optional[bytes], str, Optional[str]]:
        """Verify JWS with optional body hash check.
        
        Args:
            jws: JWS compact token
            body: Optional body bytes to verify against 'bh' claim
            
        Returns:
            Tuple of (valid, payload, key_id, error_message)
        """
        request = simpleguard_pb2.VerifyAttachedRequest(
            jws=jws,
            detached_payload=body or b"",
        )
        response = self._stub.VerifyAttached(request)
        error = response.error_message if response.error_message else None
        payload = response.payload if response.payload else None
        return response.valid, payload, response.key_id, error
    
    def generate_key_pair(
        self, key_id: str = "", metadata: Optional[dict] = None
    ) -> tuple[Optional[dict], Optional[str]]:
        """Generate a new Ed25519 key pair.
        
        Args:
            key_id: Optional specific key ID
            metadata: Optional metadata to associate with key
            
        Returns:
            Tuple of (key_info, error_message)
            key_info contains: key_id, public_key_pem, private_key_pem, did_key
        """
        request = simpleguard_pb2.GenerateKeyPairRequest(
            algorithm=trust_pb2.KEY_ALGORITHM_ED25519,
            key_id=key_id,
            metadata=metadata or {},
        )
        response = self._stub.GenerateKeyPair(request)
        error = response.error_message if response.error_message else None
        if error:
            return None, error
        return {
            "key_id": response.key_id,
            "public_key_pem": response.public_key_pem,
            "private_key_pem": response.private_key_pem,
            "did_key": response.did_key,  # did:key URI (RFC-002 §6.1)
        }, None
    
    def load_key(self, file_path: str) -> tuple[Optional[dict], Optional[str]]:
        """Load key from PEM file.
        
        Args:
            file_path: Path to PEM file
            
        Returns:
            Tuple of (key_info, error_message)
        """
        request = simpleguard_pb2.LoadKeyRequest(file_path=file_path)
        response = self._stub.LoadKey(request)
        error = response.error_message if response.error_message else None
        if error:
            return None, error
        return {
            "key_id": response.key_id,
            "has_private_key": response.has_private_key,
        }, None
    
    def export_key(
        self, key_id: str, file_path: str, include_private: bool = False
    ) -> tuple[bool, Optional[str]]:
        """Export key to PEM file.
        
        Args:
            key_id: Key to export
            file_path: Destination path
            include_private: Whether to include private key
            
        Returns:
            Tuple of (success, error_message)
        """
        request = simpleguard_pb2.ExportKeyRequest(
            key_id=key_id,
            file_path=file_path,
            include_private=include_private,
        )
        response = self._stub.ExportKey(request)
        error = response.error_message if response.error_message else None
        return error is None, error
    
    def get_key_info(self, key_id: str) -> tuple[Optional[dict], Optional[str]]:
        """Get info about a loaded key.
        
        Args:
            key_id: Key to query
            
        Returns:
            Tuple of (key_info, error_message)
        """
        request = simpleguard_pb2.GetKeyInfoRequest(key_id=key_id)
        response = self._stub.GetKeyInfo(request)
        error = response.error_message if response.error_message else None
        if error:
            return None, error
        return {
            "key_id": response.key_id,
            "has_private_key": response.has_private_key,
            "public_key_pem": response.public_key_pem,
        }, None
    
    def init(
        self,
        api_key: str = "",
        agent_id: str = "",
        server_url: str = "",
        output_dir: str = "",
        force: bool = False,
        metadata: Optional[dict] = None,
    ) -> tuple[Optional[dict], Optional[str]]:
        """Initialize agent identity - Let's Encrypt style one-call setup.
        
        Generates key pair, derives DID, registers with server, and creates agent card.
        All cryptographic operations are performed by capiscio-core Go library.
        
        Args:
            api_key: API key for server authentication
            agent_id: Agent UUID to register DID for
            server_url: CapiscIO server URL (default: https://api.capisc.io)
            output_dir: Directory for generated files (default: .capiscio)
            force: Overwrite existing files
            metadata: Additional metadata for agent card
            
        Returns:
            Tuple of (init_result, error_message)
            init_result contains: did, agent_id, private_key_path, public_key_path,
                                 agent_card_path, agent_card_json, registered
        """
        request = simpleguard_pb2.InitRequest(
            api_key=api_key,
            agent_id=agent_id,
            server_url=server_url,
            output_dir=output_dir,
            force=force,
            metadata=metadata or {},
        )
        response = self._stub.Init(request)
        error = response.error_message if response.error_message else None
        if error:
            return None, error
        return {
            "did": response.did,
            "agent_id": response.agent_id,
            "private_key_path": response.private_key_path,
            "public_key_path": response.public_key_path,
            "agent_card_path": response.agent_card_path,
            "agent_card_json": response.agent_card_json,
            "registered": response.registered,
        }, None


class MCPClient:
    """Client wrapper for MCPService (RFC-006 Tool Authority + RFC-007 Server Identity).
    
    This client provides access to MCP security operations including:
    - Tool access evaluation (RFC-006 §6.2-6.4)
    - Server identity verification (RFC-007 §7.2)
    - Server identity parsing from HTTP/JSON-RPC transports
    
    Example:
        from capiscio_sdk._rpc.client import CapiscioRPCClient
        
        client = CapiscioRPCClient()
        client.connect()
        
        # Evaluate tool access with a badge
        result = client.mcp.evaluate_tool_access(
            tool_name="write_file",
            params_hash="abc123",
            server_origin="https://files.example.com",
            badge_jws=badge_token,
        )
        
        if result["decision"] == "allow":
            print(f"Tool access granted for {result['agent_did']}")
        else:
            print(f"Access denied: {result['deny_reason']}")
            
        # Verify server identity
        server_result = client.mcp.verify_server_identity(
            server_did="did:web:example.com:mcp:files",
            server_badge=server_badge,
            transport_origin="https://files.example.com",
        )
    """
    
    def __init__(self, stub: mcp_pb2_grpc.MCPServiceStub) -> None:
        self._stub = stub
    
    def evaluate_tool_access(
        self,
        tool_name: str,
        params_hash: str = "",
        server_origin: str = "",
        *,
        badge_jws: Optional[str] = None,
        api_key: Optional[str] = None,
        policy_version: str = "",
        trusted_issuers: Optional[list[str]] = None,
        min_trust_level: int = 0,
        accept_level_zero: bool = False,
        allowed_tools: Optional[list[str]] = None,
    ) -> dict:
        """Evaluate tool access request (RFC-006 §6.2-6.4).
        
        Evaluates whether a caller (identified by badge or API key) is
        authorized to invoke a specific tool. Returns both a decision
        and evidence record atomically.
        
        Args:
            tool_name: Name of the tool being invoked
            params_hash: Hash of the tool parameters (for audit)
            server_origin: Origin of the MCP server handling the request
            badge_jws: Caller's badge JWT (for badged access)
            api_key: Caller's API key (for API key access)
            policy_version: Optional policy version to use
            trusted_issuers: List of trusted badge issuers
            min_trust_level: Minimum required trust level (0-4)
            accept_level_zero: Accept self-signed (level 0) badges
            allowed_tools: Explicit list of allowed tools (if set, tool_name must match)
            
        Returns:
            Dict with:
                decision: "allow" or "deny"
                deny_reason: Reason if denied (e.g., "badge_missing", "trust_insufficient")
                deny_detail: Detailed error message if denied
                agent_did: DID of the authenticated agent (if authenticated)
                badge_jti: Badge JTI (if badge was used)
                auth_level: Authentication level ("anonymous", "api_key", "badge")
                trust_level: Agent's trust level (0-4)
                evidence_json: RFC-006 §7 evidence record as JSON
                evidence_id: Unique evidence record ID
                timestamp: Evaluation timestamp (ISO format)
                
        Example:
            # Evaluate with badge
            result = client.mcp.evaluate_tool_access(
                tool_name="write_file",
                params_hash=hashlib.sha256(json.dumps(params).encode()).hexdigest(),
                server_origin="https://files.example.com",
                badge_jws=badge_token,
                min_trust_level=2,  # Require OV or higher
            )
            
            if result["decision"] == "allow":
                # Proceed with tool execution
                pass
            else:
                raise PermissionError(result["deny_detail"])
        """
        # Build config
        config = mcp_pb2.EvaluateConfig(
            trusted_issuers=trusted_issuers or [],
            min_trust_level=min_trust_level,
            accept_level_zero=accept_level_zero,
            allowed_tools=allowed_tools or [],
        )
        
        # Build request with caller credential
        request = mcp_pb2.EvaluateToolAccessRequest(
            tool_name=tool_name,
            params_hash=params_hash,
            server_origin=server_origin,
            policy_version=policy_version,
            config=config,
        )
        
        # Set credential (badge or api_key, mutually exclusive)
        if badge_jws:
            request.badge_jws = badge_jws
        elif api_key:
            request.api_key = api_key
        
        response = self._stub.EvaluateToolAccess(request)
        
        # Map enums to strings
        decision_map = {
            mcp_pb2.MCP_DECISION_UNSPECIFIED: "unspecified",
            mcp_pb2.MCP_DECISION_ALLOW: "allow",
            mcp_pb2.MCP_DECISION_DENY: "deny",
        }
        
        deny_reason_map = {
            mcp_pb2.MCP_DENY_REASON_UNSPECIFIED: "",
            mcp_pb2.MCP_DENY_REASON_BADGE_MISSING: "badge_missing",
            mcp_pb2.MCP_DENY_REASON_BADGE_INVALID: "badge_invalid",
            mcp_pb2.MCP_DENY_REASON_BADGE_EXPIRED: "badge_expired",
            mcp_pb2.MCP_DENY_REASON_BADGE_REVOKED: "badge_revoked",
            mcp_pb2.MCP_DENY_REASON_TRUST_INSUFFICIENT: "trust_insufficient",
            mcp_pb2.MCP_DENY_REASON_TOOL_NOT_ALLOWED: "tool_not_allowed",
            mcp_pb2.MCP_DENY_REASON_ISSUER_UNTRUSTED: "issuer_untrusted",
            mcp_pb2.MCP_DENY_REASON_POLICY_DENIED: "policy_denied",
        }
        
        auth_level_map = {
            mcp_pb2.MCP_AUTH_LEVEL_UNSPECIFIED: "unspecified",
            mcp_pb2.MCP_AUTH_LEVEL_ANONYMOUS: "anonymous",
            mcp_pb2.MCP_AUTH_LEVEL_API_KEY: "api_key",
            mcp_pb2.MCP_AUTH_LEVEL_BADGE: "badge",
        }
        
        # Format timestamp
        timestamp_str = ""
        if response.timestamp:
            from datetime import datetime, timezone
            timestamp_str = datetime.fromtimestamp(
                response.timestamp.seconds + response.timestamp.nanos / 1e9,
                timezone.utc
            ).isoformat()
        
        return {
            "decision": decision_map.get(response.decision, "unspecified"),
            "deny_reason": deny_reason_map.get(response.deny_reason, ""),
            "deny_detail": response.deny_detail,
            "agent_did": response.agent_did,
            "badge_jti": response.badge_jti,
            "auth_level": auth_level_map.get(response.auth_level, "unspecified"),
            "trust_level": response.trust_level,
            "evidence_json": response.evidence_json,
            "evidence_id": response.evidence_id,
            "timestamp": timestamp_str,
        }
    
    def verify_server_identity(
        self,
        server_did: str,
        server_badge: str = "",
        transport_origin: str = "",
        endpoint_path: str = "",
        *,
        trusted_issuers: Optional[list[str]] = None,
        min_trust_level: int = 0,
        accept_level_zero: bool = False,
        offline_mode: bool = False,
        skip_origin_binding: bool = False,
    ) -> dict:
        """Verify MCP server identity (RFC-007 §7.2).
        
        Verifies a server's disclosed identity (DID + badge) and checks
        that it matches the transport origin. Returns the verification
        state and any errors.
        
        Args:
            server_did: Server's DID (did:web:... or did:key:...)
            server_badge: Server's badge JWT (optional for level 0)
            transport_origin: Origin from the transport (e.g., "https://files.example.com")
            endpoint_path: Endpoint path being accessed
            trusted_issuers: List of trusted badge issuers
            min_trust_level: Minimum required trust level (0-4)
            accept_level_zero: Accept self-signed (level 0) servers
            offline_mode: Skip online validation (use cache only)
            skip_origin_binding: Skip transport origin binding check (RFC-007 §5.3)
            
        Returns:
            Dict with:
                state: Server state ("verified_principal", "declared_principal", "unverified_origin")
                trust_level: Server's trust level (0-4)
                server_did: Verified server DID
                badge_jti: Server badge JTI (if badge was provided)
                error_code: Error code if verification failed
                error_detail: Detailed error message
                
        Example:
            # Verify server before trusting tool results
            result = client.mcp.verify_server_identity(
                server_did="did:web:files.example.com:mcp:files",
                server_badge=server_badge_token,
                transport_origin="https://files.example.com",
                min_trust_level=1,  # Require at least DV
            )
            
            if result["state"] == "verified_principal":
                print(f"Server verified at trust level {result['trust_level']}")
            else:
                print(f"Server verification failed: {result['error_detail']}")
        """
        # Build config
        config = mcp_pb2.MCPVerifyConfig(
            trusted_issuers=trusted_issuers or [],
            min_trust_level=min_trust_level,
            accept_level_zero=accept_level_zero,
            offline_mode=offline_mode,
            skip_origin_binding=skip_origin_binding,
        )
        
        request = mcp_pb2.VerifyServerIdentityRequest(
            server_did=server_did,
            server_badge=server_badge,
            transport_origin=transport_origin,
            endpoint_path=endpoint_path,
            config=config,
        )
        
        response = self._stub.VerifyServerIdentity(request)
        
        # Map enums to strings
        state_map = {
            mcp_pb2.MCP_SERVER_STATE_UNSPECIFIED: "unspecified",
            mcp_pb2.MCP_SERVER_STATE_VERIFIED_PRINCIPAL: "verified_principal",
            mcp_pb2.MCP_SERVER_STATE_DECLARED_PRINCIPAL: "declared_principal",
            mcp_pb2.MCP_SERVER_STATE_UNVERIFIED_ORIGIN: "unverified_origin",
        }
        
        error_code_map = {
            mcp_pb2.MCP_SERVER_ERROR_NONE: "",
            mcp_pb2.MCP_SERVER_ERROR_DID_INVALID: "did_invalid",
            mcp_pb2.MCP_SERVER_ERROR_BADGE_INVALID: "badge_invalid",
            mcp_pb2.MCP_SERVER_ERROR_BADGE_EXPIRED: "badge_expired",
            mcp_pb2.MCP_SERVER_ERROR_BADGE_REVOKED: "badge_revoked",
            mcp_pb2.MCP_SERVER_ERROR_TRUST_INSUFFICIENT: "trust_insufficient",
            mcp_pb2.MCP_SERVER_ERROR_ORIGIN_MISMATCH: "origin_mismatch",
            mcp_pb2.MCP_SERVER_ERROR_PATH_MISMATCH: "path_mismatch",
            mcp_pb2.MCP_SERVER_ERROR_ISSUER_UNTRUSTED: "issuer_untrusted",
        }
        
        return {
            "state": state_map.get(response.state, "unspecified"),
            "trust_level": response.trust_level,
            "server_did": response.server_did,
            "badge_jti": response.badge_jti,
            "error_code": error_code_map.get(response.error_code, ""),
            "error_detail": response.error_detail,
        }
    
    def parse_server_identity_http(
        self,
        capiscio_server_did: str = "",
        capiscio_server_badge: str = "",
    ) -> dict:
        """Parse server identity from HTTP headers (RFC-007 §5.2).
        
        Extracts server identity from HTTP headers. Use this before
        verify_server_identity() to extract the DID and badge.
        
        Args:
            capiscio_server_did: Value of Capiscio-Server-DID header
            capiscio_server_badge: Value of Capiscio-Server-Badge header
            
        Returns:
            Dict with:
                server_did: Extracted server DID
                server_badge: Extracted server badge JWT
                identity_present: Whether identity was present
                
        Example:
            # Extract from HTTP headers
            headers = response.headers
            identity = client.mcp.parse_server_identity_http(
                capiscio_server_did=headers.get("Capiscio-Server-DID", ""),
                capiscio_server_badge=headers.get("Capiscio-Server-Badge", ""),
            )
            
            if identity["identity_present"]:
                # Verify the extracted identity
                result = client.mcp.verify_server_identity(
                    server_did=identity["server_did"],
                    server_badge=identity["server_badge"],
                    transport_origin="https://files.example.com",
                )
        """
        http_headers = mcp_pb2.MCPHttpHeaders(
            capiscio_server_did=capiscio_server_did,
            capiscio_server_badge=capiscio_server_badge,
        )
        
        request = mcp_pb2.ParseServerIdentityRequest(http_headers=http_headers)
        response = self._stub.ParseServerIdentity(request)
        
        return {
            "server_did": response.server_did,
            "server_badge": response.server_badge,
            "identity_present": response.identity_present,
        }
    
    def parse_server_identity_jsonrpc(self, meta_json: str) -> dict:
        """Parse server identity from JSON-RPC _meta (RFC-007 §5.3).
        
        Extracts server identity from JSON-RPC _meta field. Use this
        for stdio transport or any JSON-RPC based MCP connection.
        
        Args:
            meta_json: JSON string of the _meta object containing
                       "serverDid" and "serverBadge" fields
            
        Returns:
            Dict with:
                server_did: Extracted server DID
                server_badge: Extracted server badge JWT
                identity_present: Whether identity was present
                
        Example:
            # Extract from JSON-RPC response
            meta = response.get("_meta", {})
            identity = client.mcp.parse_server_identity_jsonrpc(
                meta_json=json.dumps(meta)
            )
            
            if identity["identity_present"]:
                # Verify the extracted identity
                result = client.mcp.verify_server_identity(
                    server_did=identity["server_did"],
                    server_badge=identity["server_badge"],
                    transport_origin="",  # N/A for stdio
                )
        """
        jsonrpc_meta = mcp_pb2.MCPJsonRpcMeta(meta_json=meta_json)
        
        request = mcp_pb2.ParseServerIdentityRequest(jsonrpc_meta=jsonrpc_meta)
        response = self._stub.ParseServerIdentity(request)
        
        return {
            "server_did": response.server_did,
            "server_badge": response.server_badge,
            "identity_present": response.identity_present,
        }
    
    def health(self, client_version: str = "") -> dict:
        """Check MCP service health and version compatibility.
        
        Args:
            client_version: Client's version for compatibility check
            
        Returns:
            Dict with:
                healthy: Whether service is healthy
                core_version: capiscio-core version
                proto_version: Proto/gRPC version
                version_compatible: Whether versions are compatible
        """
        request = mcp_pb2.MCPHealthRequest(client_version=client_version)
        response = self._stub.Health(request)
        
        return {
            "healthy": response.healthy,
            "core_version": response.core_version,
            "proto_version": response.proto_version,
            "version_compatible": response.version_compatible,
        }


class RegistryClient:
    """Client wrapper for RegistryService."""
    
    def __init__(self, stub: registry_pb2_grpc.RegistryServiceStub) -> None:
        self._stub = stub
    
    def ping(self) -> dict:
        """Ping the registry."""
        request = registry_pb2.PingRequest()
        response = self._stub.Ping(request)
        return {
            "status": response.status,
            "version": response.version,
            "server_time": response.server_time.value if response.server_time else None,
        }
    
    def get_agent(self, did: str) -> tuple[Optional[dict], Optional[str]]:
        """Get an agent by DID."""
        request = registry_pb2.GetAgentRequest(did=did)
        response = self._stub.GetAgent(request)
        
        if response.error_message:
            return None, response.error_message
        
        # TODO: Convert response.agent to dict
        return None, "not yet implemented"


def _claims_to_dict(claims) -> dict:
    """Convert protobuf BadgeClaims to dict."""
    if claims is None:
        return {}
    
    # Map proto enum to human-readable trust level string
    # Note: UNSPECIFIED (0) defaults to "1" (DV) for compatibility
    trust_level_map = {
        0: "1",  # TRUST_LEVEL_UNSPECIFIED -> default to DV (1)
        1: "0",  # TRUST_LEVEL_SELF_SIGNED (Level 0)
        2: "1",  # TRUST_LEVEL_DV (Level 1)
        3: "2",  # TRUST_LEVEL_OV (Level 2)
        4: "3",  # TRUST_LEVEL_EV (Level 3)
        5: "4",  # TRUST_LEVEL_CV (Level 4)
    }
    
    return {
        "jti": claims.jti,
        "iss": claims.iss,
        "sub": claims.sub,
        "iat": claims.iat,
        "exp": claims.exp,
        "aud": list(claims.aud),
        "trust_level": trust_level_map.get(claims.trust_level, str(claims.trust_level)),
        "domain": claims.domain,
        "agent_name": claims.agent_name,
    }
