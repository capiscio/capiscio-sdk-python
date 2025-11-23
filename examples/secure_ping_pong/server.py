import uvicorn
from fastapi import FastAPI, Request
from capiscio_sdk.simple_guard import SimpleGuard
from capiscio_sdk.integrations.fastapi import CapiscioMiddleware

# 1. Initialize Guard (Zero Config in Dev Mode)
# This will auto-generate agent-card.json and keys in the current directory
guard = SimpleGuard(dev_mode=True)

app = FastAPI()

# 2. Add Security Middleware
app.add_middleware(CapiscioMiddleware, guard=guard)

@app.post("/ping")
async def ping(request: Request):
    # The middleware has already verified the identity
    caller_id = request.state.agent_id
    return {
        "status": "secure",
        "message": "pong", 
        "verified_caller": caller_id
    }

if __name__ == "__main__":
    print("\n=== CapiscIO Secure Server ===")
    print(f"Agent ID: {guard.agent_id}")
    print(f"Trust Store: {guard.trusted_dir}")
    print("Starting server on port 8000...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
