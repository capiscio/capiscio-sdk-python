"""FastAPI integration for Capiscio SimpleGuard."""
from typing import Callable, Awaitable, Any, Dict, List, Optional, TYPE_CHECKING
try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
    from starlette.types import ASGIApp
except ImportError:
    raise ImportError("FastAPI/Starlette is required for this integration. Install with 'pip install fastapi'.")

from ..simple_guard import SimpleGuard
from ..errors import VerificationError
import time
import logging

if TYPE_CHECKING:
    from ..config import SecurityConfig

logger = logging.getLogger(__name__)

class CapiscioMiddleware(BaseHTTPMiddleware):
    """
    Middleware to enforce A2A identity verification on incoming requests.
    
    Args:
        app: The ASGI application.
        guard: SimpleGuard instance for verification.
        exclude_paths: List of paths to skip verification (e.g., ["/health", "/.well-known/agent-card.json"]).
        config: Optional SecurityConfig to control enforcement behavior.
    
    Security behavior:
        - If config is None, defaults to strict blocking mode
        - fail_mode takes precedence: "log"/"monitor" always allow through (regardless of require_signatures)
        - When fail_mode="block" and require_signatures=False, missing badges are allowed
        - When fail_mode="block" and require_signatures=True, badges are enforced
    """
    def __init__(
        self, 
        app: ASGIApp, 
        guard: SimpleGuard, 
        exclude_paths: Optional[List[str]] = None,
        *,  # Force config to be keyword-only
        config: Optional["SecurityConfig"] = None
    ) -> None:
        super().__init__(app)
        self.guard = guard
        self.config = config
        self.exclude_paths = exclude_paths or []
        
        # Default to strict mode if no config
        self.require_signatures = config.downstream.require_signatures if config is not None else True
        self.fail_mode = config.fail_mode if config is not None else "block"
        
        logger.info(f"CapiscioMiddleware initialized: exclude_paths={self.exclude_paths}, require_signatures={self.require_signatures}, fail_mode={self.fail_mode}")

    async def dispatch(
        self, 
        request: Request, 
        call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Allow CORS preflight
        if request.method == "OPTIONS":
            return await call_next(request)
        
        # Skip verification for excluded paths
        path = request.url.path
        logger.debug(f"CapiscioMiddleware: path={path!r}, exclude_paths={self.exclude_paths}, match={path in self.exclude_paths}")
        if path in self.exclude_paths:
            logger.debug(f"CapiscioMiddleware: SKIPPING verification for {path}")
            return await call_next(request)

        # RFC-002 §9.1: X-Capiscio-Badge header
        auth_header = request.headers.get("X-Capiscio-Badge")
        
        # Handle missing badge based on config
        if not auth_header:
            if not self.require_signatures:
                # No badge required - allow through but mark as unverified
                request.state.agent = None
                request.state.agent_id = None
                return await call_next(request)
            
            # Badge required but missing
            if self.fail_mode in ("log", "monitor"):
                logger.warning(f"Missing X-Capiscio-Badge header for {request.url.path} ({self.fail_mode} mode)")
                request.state.agent = None
                request.state.agent_id = None
                return await call_next(request)
            else:  # block
                return JSONResponse(
                    {"error": "Missing X-Capiscio-Badge header. This endpoint is protected by CapiscIO."}, 
                    status_code=401
                )

        start_time = time.perf_counter()
        try:
            # Read the body for integrity check
            body_bytes = await request.body()
            
            # Verify the JWS with body
            payload = self.guard.verify_inbound(auth_header, body=body_bytes)
            
            # Reset the receive channel so downstream can read the body
            async def receive() -> Dict[str, Any]:
                return {"type": "http.request", "body": body_bytes, "more_body": False}
            request._receive = receive
            
            # Inject claims into request.state
            request.state.agent = payload
            request.state.agent_id = payload.get("iss")
            
        except VerificationError as e:
            if self.fail_mode in ("log", "monitor"):
                logger.warning(f"Badge verification failed: {e} ({self.fail_mode} mode)")
                request.state.agent = None
                request.state.agent_id = None
                # Reset receive so downstream can read body (body_bytes was consumed above)
                async def receive() -> Dict[str, Any]:
                    return {"type": "http.request", "body": body_bytes, "more_body": False}
                request._receive = receive
                return await call_next(request)
            else:  # block
                return JSONResponse({"error": f"Access Denied: {str(e)}"}, status_code=403)
        
        verification_duration = (time.perf_counter() - start_time) * 1000

        response = await call_next(request)
        
        # Add Server-Timing header (standard for performance metrics)
        # Syntax: metric_name;dur=123.4;desc="Description"
        response.headers["Server-Timing"] = f"capiscio-auth;dur={verification_duration:.3f};desc=\"CapiscIO Verification\""
        
        return response
