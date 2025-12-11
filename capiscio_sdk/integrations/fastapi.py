"""FastAPI integration for Capiscio SimpleGuard."""
from typing import Callable, Awaitable, Any, Dict
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

class CapiscioMiddleware(BaseHTTPMiddleware):
    """
    Middleware to enforce A2A identity verification on incoming requests.
    """
    def __init__(self, app: ASGIApp, guard: SimpleGuard) -> None:
        super().__init__(app)
        self.guard = guard

    async def dispatch(
        self, 
        request: Request, 
        call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Allow health checks or public endpoints if needed
        # For now, we assume everything under /agent/ needs protection
        # But let's just check for the header.
        
        if request.method == "OPTIONS":
            return await call_next(request)

        # RFC-002 §9.1: X-Capiscio-Badge header
        auth_header = request.headers.get("X-Capiscio-Badge")
        
        # If no header, we might let it pass but mark as unverified?
        # The mandate says: "Returns 401 (missing) or 403 (invalid)."
        if not auth_header:
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
            return JSONResponse({"error": f"Access Denied: {str(e)}"}, status_code=403)
        
        verification_duration = (time.perf_counter() - start_time) * 1000

        response = await call_next(request)
        
        # Add Server-Timing header (standard for performance metrics)
        # Syntax: metric_name;dur=123.4;desc="Description"
        response.headers["Server-Timing"] = f"capiscio-auth;dur={verification_duration:.3f};desc=\"CapiscIO Verification\""
        
        return response
