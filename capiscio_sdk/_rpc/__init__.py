# CapiscIO RPC Client Package
# This module provides the gRPC client wrapper for communicating with capiscio-core.

from capiscio_sdk._rpc.client import CapiscioRPCClient
from capiscio_sdk._rpc.process import ProcessManager

__all__ = ["CapiscioRPCClient", "ProcessManager"]
