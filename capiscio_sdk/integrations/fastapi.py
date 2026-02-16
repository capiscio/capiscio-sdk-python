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
        config: Optional SecurityConfig to control enforcement behavior.
        exclude_paths: List of paths to skip verification (e.g., ["/health", "/.well-known/agent-card.json"]).
    
    Security behavior controlled by SecurityConfig:
        - config.downstream.require_signatures: If False, allow requests without badges
        - config.fail_mode: "block" returns 401/403, "monitor" logs and allows, "log" just logs
    """
    def __init__(
        self, 
        app: ASGIApp, 
        guard: SimpleGuard, 
        config: Optional["SecurityConfig"] = None,
        exclude_paths: Optional[List[str]] = None
    ) -> None:
        super().__init__(app)
        self.guard = guard
        self.config = config
        self.exclude_paths = exclude_paths or []
        
        # Default to strict mode if no config
        self.require_signatures = config.downstream.require_signatures if config is not None else True
        self.fail_mode = config.fail_mode if config is not None else "block"

    async def dispatch(
        self, 
        request: Request, 
        call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Allow CORS preflight
        if request.method == "OPTIONS":
            return await call_next(request)
        
        # Skip verification for excluded paths
        if request.url.path in self.exclude_paths:
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
                return await call_next(request)
            else:  # block
                return JSONResponse({"error": f"Access Denied: {str(e)}"}, status_code=403)
        
        verification_duration = (time.perf_counter() - start_time) * 1000

        response = await call_next(request)
        
        # Add Server-Timing header (standard for performance metrics)
        # Syntax: metric_name;dur=123.4;desc="Description"
        response.headers["Server-Timing"] = f"capiscio-auth;dur={verification_duration:.3f};desc=\"CapiscIO Verification\""
        
        return response
