"""SimpleGuard - Zero-config security for A2A agents.

This module provides signing and verification of A2A messages using
the capiscio-core Go library via gRPC. All cryptographic operations
are delegated to the Go core for consistency across SDKs.
"""
import os
import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any, Union

from .errors import ConfigurationError, VerificationError
from ._rpc.client import CapiscioRPCClient

logger = logging.getLogger(__name__)


class SimpleGuard:
    """
    Zero-config security middleware for A2A agents.
    
    SimpleGuard handles message signing and verification using Ed25519
    keys. All cryptographic operations are performed by the capiscio-core
    Go library via gRPC, ensuring consistent behavior across all SDKs.
    
    Example:
        >>> guard = SimpleGuard(dev_mode=True)
        >>> token = guard.sign_outbound({"sub": "test"}, body=b"hello")
        >>> claims = guard.verify_inbound(token, body=b"hello")
        
        # With explicit agent_id:
        >>> guard = SimpleGuard(agent_id="did:web:example.com:agents:myagent")
        
        # In dev mode, did:key is auto-generated:
        >>> guard = SimpleGuard(dev_mode=True)
        >>> print(guard.agent_id)  # did:key:z6Mk...
    """

    def __init__(
        self, 
        base_dir: Optional[Union[str, Path]] = None, 
        dev_mode: bool = False,
        rpc_address: Optional[str] = None,
        agent_id: Optional[str] = None,
        badge_token: Optional[str] = None,
    ) -> None:
        """
        Initialize SimpleGuard.

        Args:
            base_dir: Starting directory to search for config (defaults to cwd).
            dev_mode: If True, auto-generates keys with did:key identity (RFC-002 §6.1).
            rpc_address: gRPC server address. If None, auto-starts local server.
            agent_id: Explicit agent DID. If None:
                - In dev_mode: Auto-generates did:key from keypair
                - Otherwise: Loaded from agent-card.json
            badge_token: Pre-obtained badge token to use for identity. When set,
                make_headers() will use this token instead of signing.
        """
        self.dev_mode = dev_mode
        self._explicit_agent_id = agent_id
        self._badge_token = badge_token
        
        # 1. Safety Check
        if self.dev_mode and os.getenv("CAPISCIO_ENV") == "prod":
            logger.critical(
                "CRITICAL: SimpleGuard initialized in dev_mode=True but CAPISCIO_ENV=prod. "
                "This is insecure! Disable dev_mode in production."
            )

        # 2. Resolve base_dir
        self.project_root = self._resolve_project_root(base_dir)
        self.keys_dir = self.project_root / "capiscio_keys"
        self.trusted_dir = self.keys_dir / "trusted"
        self.agent_card_path = self.project_root / "agent-card.json"
        
        # 3. Connect to gRPC server
        self._client = CapiscioRPCClient(address=rpc_address)
        self._client.connect()
        
        # 4. Load or generate agent identity
        self.agent_id: str
        self.signing_kid: str
        self._load_or_generate_card()
        
        # 5. Load or generate keys via gRPC (may update agent_id with did:key)
        self._load_or_generate_keys()
        
        # 6. Load trust store
        self._setup_trust_store()

    def sign_outbound(self, payload: Dict[str, Any], body: Optional[bytes] = None) -> str:
        """
        Sign a payload for outbound transmission.

        Args:
            payload: The JSON payload to sign.
            body: Optional HTTP body bytes to bind to the signature.

        Returns:
            Compact JWS string.
        """
        # Inject issuer if missing
        if "iss" not in payload:
            payload["iss"] = self.agent_id
        
        # Use body for binding if provided
        body_bytes = body or b""
        
        # Sign via gRPC - use SignAttached which handles timestamps and body hash
        jws, error = self._client.simpleguard.sign_attached(
            payload=body_bytes,  # This gets hashed into 'bh' claim
            key_id=self.signing_kid,
            headers={"iss": self.agent_id},
        )
        
        if error:
            raise ConfigurationError(f"Failed to sign payload: {error}")
        
        return jws

    def verify_inbound(self, jws: str, body: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Verify an inbound JWS.

        Args:
            jws: The compact JWS string.
            body: Optional HTTP body bytes to verify against 'bh' claim.

        Returns:
            The verified payload.

        Raises:
            VerificationError: If signature is invalid, key is untrusted, or integrity check fails.
        """
        valid, payload_bytes, key_id, error = self._client.simpleguard.verify_attached(
            jws=jws,
            body=body,
        )
        
        if error:
            logger.warning(f'{{"event": "agent_call_denied", "reason": "{error}"}}')
            raise VerificationError(error)
        
        if not valid:
            raise VerificationError("Verification failed")
        
        # Parse payload
        try:
            payload = json.loads(payload_bytes) if payload_bytes else {}
        except json.JSONDecodeError:
            payload = {}
        
        iss = payload.get("iss", "unknown")
        logger.info(f'{{"event": "agent_call_allowed", "iss": "{iss}", "kid": "{key_id}"}}')
        
        return payload

    def make_headers(self, payload: Dict[str, Any], body: Optional[bytes] = None) -> Dict[str, str]:
        """
        Generate headers containing the Badge (RFC-002 §9.1).
        
        If a badge_token was provided at construction, it will be used.
        Otherwise, signs the payload to create a token.
        
        Args:
            payload: The JSON payload to sign (ignored if using badge_token).
            body: Optional HTTP body bytes to bind to the signature.
            
        Returns:
            Dict with X-Capiscio-Badge header.
        """
        if self._badge_token:
            return {"X-Capiscio-Badge": self._badge_token}
        
        token = self.sign_outbound(payload, body=body)
        return {"X-Capiscio-Badge": token}
    
    def set_badge_token(self, token: str) -> None:
        """
        Update the badge token used for outbound requests.
        
        This is typically called by the badge keeper when a new token is obtained.
        
        Args:
            token: The new badge token (compact JWS).
        """
        self._badge_token = token
        logger.debug(f"Updated badge token for agent {self.agent_id}")

    def close(self) -> None:
        """Close the gRPC connection."""
        if self._client:
            self._client.close()

    def __enter__(self) -> "SimpleGuard":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def _resolve_project_root(self, base_dir: Optional[Union[str, Path]]) -> Path:
        """Walk up the directory tree to find agent-card.json or stop at root."""
        current = Path(base_dir or os.getcwd()).resolve()
        
        search_path = current
        while search_path != search_path.parent:
            if (search_path / "agent-card.json").exists():
                return search_path
            search_path = search_path.parent
        
        return current

    def _load_or_generate_card(self) -> None:
        """Load agent-card.json or generate a minimal one in dev_mode."""
        # If explicit agent_id was provided, use it
        if self._explicit_agent_id:
            self.agent_id = self._explicit_agent_id
            self.signing_kid = "key-0"  # Will be updated when keys are generated/loaded
            logger.info(f"Using explicit agent_id: {self.agent_id}")
            return
            
        if self.agent_card_path.exists():
            try:
                with open(self.agent_card_path, "r") as f:
                    data = json.load(f)
                    self.agent_id = data.get("agent_id")
                    keys = data.get("public_keys", [])
                    if not keys:
                        raise ConfigurationError("agent-card.json missing 'public_keys'.")
                    self.signing_kid = keys[0].get("kid")
                    
                    if not self.agent_id or not self.signing_kid:
                        raise ConfigurationError("agent-card.json missing 'agent_id' or 'public_keys[0].kid'.")
            except Exception as e:
                raise ConfigurationError(f"Failed to load agent-card.json: {e}")
        elif self.dev_mode:
            logger.info("Dev Mode: Will generate did:key identity from keypair")
            # Placeholder - will be updated with did:key after key generation
            self.agent_id = "local-dev-agent"  # Temporary, replaced in _load_or_generate_keys
            self.signing_kid = "local-dev-key"
        else:
            raise ConfigurationError(f"agent-card.json not found at {self.project_root}")

    def _load_or_generate_keys(self) -> None:
        """Load keys or generate them in dev_mode via gRPC.
        
        In dev_mode, if no explicit agent_id was provided, updates self.agent_id
        with the did:key derived from the generated keypair (RFC-002 §6.1).
        """
        private_key_path = self.keys_dir / "private.pem"
        public_key_path = self.keys_dir / "public.pem"
        
        if not self.keys_dir.exists():
            if self.dev_mode:
                self.keys_dir.mkdir(parents=True, exist_ok=True)
                self.trusted_dir.mkdir(parents=True, exist_ok=True)
            else:
                raise ConfigurationError(f"capiscio_keys directory not found at {self.keys_dir}")

        if private_key_path.exists():
            # Load existing key via gRPC
            key_info, error = self._client.simpleguard.load_key(str(private_key_path))
            if error:
                raise ConfigurationError(f"Failed to load private.pem: {error}")
            # Update signing kid to match the loaded key
            self.signing_kid = key_info["key_id"]
            logger.info(f"Loaded key: {self.signing_kid}")
        elif self.dev_mode:
            logger.info("Dev Mode: Generating Ed25519 keypair via gRPC")
            
            # Generate via gRPC
            key_info, error = self._client.simpleguard.generate_key_pair(
                key_id=self.signing_kid,
            )
            if error:
                raise ConfigurationError(f"Failed to generate keypair: {error}")
            
            # Update agent_id with did:key if not explicitly set (RFC-002 §6.1)
            did_key = key_info.get("did_key")
            if did_key and not self._explicit_agent_id:
                self.agent_id = did_key
                logger.info(f"Dev Mode: Using did:key identity: {self.agent_id}")
            
            # Save private key
            with open(private_key_path, "w") as f:
                f.write(key_info["private_key_pem"])
            
            # Save public key
            with open(public_key_path, "w") as f:
                f.write(key_info["public_key_pem"])
            
            # Update agent-card.json with JWK
            self._update_agent_card_with_pem(key_info["public_key_pem"])
        else:
            raise ConfigurationError(f"private.pem not found at {private_key_path}")

    def _update_agent_card_with_pem(self, public_key_pem: str) -> None:
        """Helper to write agent-card.json with the generated key."""
        # For simplicity, just create a minimal card
        # In production, would convert PEM to JWK
        card_data = {
            "agent_id": self.agent_id,
            "public_keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": self.signing_kid,
                "use": "sig",
                # Note: x would need to be extracted from PEM
            }],
            "protocolVersion": "0.3.0",
            "name": "Local Dev Agent",
            "description": "Auto-generated by SimpleGuard",
            "url": "http://localhost:8000",
            "version": "0.1.0",
            "provider": {
                "organization": "Local Dev"
            }
        }
        
        with open(self.agent_card_path, "w") as f:
            json.dump(card_data, f, indent=2)
        logger.info(f"Created agent-card.json at {self.agent_card_path}")

    def _setup_trust_store(self) -> None:
        """Ensure trust store exists and add self-trust in dev_mode."""
        if not self.trusted_dir.exists() and self.dev_mode:
            self.trusted_dir.mkdir(parents=True, exist_ok=True)
            
        if self.dev_mode:
            # Self-Trust: Load public key into gRPC server's trust store
            public_key_path = self.keys_dir / "public.pem"
            self_trust_path = self.trusted_dir / f"{self.signing_kid}.pem"
            
            if public_key_path.exists() and not self_trust_path.exists():
                import shutil
                shutil.copy(public_key_path, self_trust_path)
                logger.info(f"Dev Mode: Added self-trust for kid {self.signing_kid}")
            
            # Also load into gRPC server
            if self_trust_path.exists():
                self._client.simpleguard.load_key(str(self_trust_path))
