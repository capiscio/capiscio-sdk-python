#!/usr/bin/env python3
"""Debug script to trace trust_level through RPC."""

import capiscio_sdk._rpc.gen.capiscio.v1.badge_pb2 as badge_pb2 
from capiscio_sdk._rpc.client import CapiscioRPCClient

# Badge we know is valid
badge = 'eyJhbGciOiJFZERTQSJ9.eyJqdGkiOiJhYjg3ZWJmNi05Yjc0LTQ3ZGUtYmU1MS03ZjQwNTNmZmZiZGYiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAiLCJzdWIiOiJkaWQ6d2ViOnJlZ2lzdHJ5LmNhcGlzYy5pbzphZ2VudHM6ZDVkZDNiZjYtNTI0Yi00OWI4LTk3YTEtMGNjYTczOTNhMWNmIiwiaWF0IjoxNzY4MTAyOTc0LCJleHAiOjE3NjgxMDMyNzQsImlhbCI6IjAiLCJ2YyI6eyJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiQWdlbnRJZGVudGl0eSJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJkb21haW4iOiJ0ZXN0LmV4YW1wbGUuY29tIiwibGV2ZWwiOiIxIn19fQ.gWs7seqqYXJ7UDVTzVo8xak9ew1gxYcSQHqNpyw_pO0oiNuGLJsZj8KH0jns8gkDC0LaOMHlwxyNwfmM1ikcAg'

# Create client and connect
client = CapiscioRPCClient()
client.connect()

print("=== Parse badge ===")
claims, error = client.badge.parse_badge(badge)
print(f"Parse error: {error}")
print(f"Parse trust_level: {claims.get('trust_level') if claims else None}")

print("\n=== Verify badge ===")
valid, claims, warnings, error = client.badge.verify_badge_with_options(
    token=badge,
    accept_self_signed=False,
    skip_revocation=True,
    skip_agent_status=True,
)
print(f"Valid: {valid}")
print(f"Error: {error}")
print(f"Warnings: {warnings}")
print(f"Claims: {claims}")
if claims:
    print(f"Verify trust_level: {claims.get('trust_level')}")
