"""gRPC client wrapper for capiscio-core."""

from typing import Optional

import grpc

from capiscio_sdk._rpc.process import ProcessManager, get_process_manager

# Import generated stubs
from capiscio_sdk._rpc.gen.capiscio.v1 import badge_pb2, badge_pb2_grpc
from capiscio_sdk._rpc.gen.capiscio.v1 import did_pb2, did_pb2_grpc
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
        self._trust_stub: Optional[trust_pb2_grpc.TrustStoreServiceStub] = None
        self._revocation_stub: Optional[revocation_pb2_grpc.RevocationServiceStub] = None
        self._scoring_stub: Optional[scoring_pb2_grpc.ScoringServiceStub] = None
        self._simpleguard_stub: Optional[simpleguard_pb2_grpc.SimpleGuardServiceStub] = None
        self._registry_stub: Optional[registry_pb2_grpc.RegistryServiceStub] = None
        
        # Service wrappers
        self._badge: Optional["BadgeClient"] = None
        self._did: Optional["DIDClient"] = None
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
        self._trust_stub = trust_pb2_grpc.TrustStoreServiceStub(self._channel)
        self._revocation_stub = revocation_pb2_grpc.RevocationServiceStub(self._channel)
        self._scoring_stub = scoring_pb2_grpc.ScoringServiceStub(self._channel)
        self._simpleguard_stub = simpleguard_pb2_grpc.SimpleGuardServiceStub(self._channel)
        self._registry_stub = registry_pb2_grpc.RegistryServiceStub(self._channel)
        
        # Initialize service wrappers
        self._badge = BadgeClient(self._badge_stub)
        self._did = DIDClient(self._did_stub)
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
        """Score an agent card."""
        request = scoring_pb2.ScoreAgentCardRequest(agent_card_json=agent_card_json)
        response = self._stub.ScoreAgentCard(request)
        
        if response.error_message:
            return None, response.error_message
        
        # TODO: Convert response.result to dict
        return None, "not yet implemented"


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
    return {
        "jti": claims.jti,
        "iss": claims.iss,
        "sub": claims.sub,
        "iat": claims.iat,
        "exp": claims.exp,
        "aud": list(claims.aud),
        "trust_level": claims.trust_level,
        "domain": claims.domain,
        "agent_name": claims.agent_name,
    }
