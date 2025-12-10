"""Process manager for the capiscio-core gRPC server."""

import atexit
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

# Default socket path
DEFAULT_SOCKET_DIR = Path.home() / ".capiscio"
DEFAULT_SOCKET_PATH = DEFAULT_SOCKET_DIR / "rpc.sock"


class ProcessManager:
    """Manages the capiscio-core gRPC server process.
    
    This class handles:
    - Finding the capiscio binary
    - Starting the gRPC server process
    - Managing the process lifecycle
    - Cleanup on exit
    
    Usage:
        manager = ProcessManager()
        manager.ensure_running()
        # ... use gRPC client ...
        manager.stop()  # Optional, will auto-stop on exit
    """
    
    _instance: Optional["ProcessManager"] = None
    _process: Optional[subprocess.Popen] = None
    _socket_path: Optional[Path] = None
    _tcp_address: Optional[str] = None
    
    def __new__(cls) -> "ProcessManager":
        """Singleton pattern - only one process manager per Python process."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self) -> None:
        if self._initialized:
            return
        self._initialized = True
        self._binary_path: Optional[Path] = None
        self._started = False
        
        # Register cleanup on exit
        atexit.register(self.stop)
    
    @property
    def address(self) -> str:
        """Get the address to connect to (unix socket or tcp)."""
        if self._tcp_address:
            return self._tcp_address
        if self._socket_path:
            return f"unix://{self._socket_path}"
        return f"unix://{DEFAULT_SOCKET_PATH}"
    
    @property
    def is_running(self) -> bool:
        """Check if the server process is running."""
        if self._process is None:
            return False
        return self._process.poll() is None
    
    def find_binary(self) -> Optional[Path]:
        """Find the capiscio binary.
        
        Search order:
        1. CAPISCIO_BINARY environment variable
        2. capiscio-core/bin/capiscio relative to SDK
        3. System PATH
        """
        # Check environment variable
        env_path = os.environ.get("CAPISCIO_BINARY")
        if env_path:
            path = Path(env_path)
            if path.exists() and path.is_file():
                return path
        
        # Check relative to this file (development mode)
        # SDK is at capiscio-sdk-python/capiscio_sdk/_rpc/
        # Binary is at capiscio-core/bin/capiscio
        sdk_root = Path(__file__).parent.parent.parent.parent
        workspace_root = sdk_root.parent
        dev_binary = workspace_root / "capiscio-core" / "bin" / "capiscio"
        if dev_binary.exists():
            return dev_binary
        
        # Check system PATH
        which_result = shutil.which("capiscio")
        if which_result:
            return Path(which_result)
        
        return None
    
    def ensure_running(
        self,
        socket_path: Optional[Path] = None,
        tcp_address: Optional[str] = None,
        timeout: float = 5.0,
    ) -> str:
        """Ensure the gRPC server is running.
        
        Args:
            socket_path: Path for Unix socket (default: ~/.capiscio/rpc.sock)
            tcp_address: TCP address to use instead of socket (e.g., "localhost:50051")
            timeout: Seconds to wait for server to start
            
        Returns:
            The address to connect to
            
        Raises:
            RuntimeError: If binary not found or server fails to start
        """
        # If using external server (TCP), just return the address
        if tcp_address:
            self._tcp_address = tcp_address
            return tcp_address
        
        # Check if already running
        if self.is_running:
            return self.address
        
        # Find binary
        binary = self.find_binary()
        if binary is None:
            raise RuntimeError(
                "capiscio binary not found. Please either:\n"
                "  1. Set CAPISCIO_BINARY environment variable\n"
                "  2. Install capiscio-core and add to PATH\n"
                "  3. Build capiscio-core locally"
            )
        self._binary_path = binary
        
        # Set up socket path
        self._socket_path = socket_path or DEFAULT_SOCKET_PATH
        
        # Ensure socket directory exists
        self._socket_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Remove stale socket
        if self._socket_path.exists():
            self._socket_path.unlink()
        
        # Start the server
        cmd = [str(binary), "rpc", "--socket", str(self._socket_path)]
        
        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,  # Don't forward signals
            )
        except Exception as e:
            raise RuntimeError(f"Failed to start capiscio server: {e}") from e
        
        # Wait for socket to appear
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self._socket_path.exists():
                self._started = True
                return self.address
            
            # Check if process died
            if self._process.poll() is not None:
                stdout, stderr = self._process.communicate()
                raise RuntimeError(
                    f"capiscio server exited unexpectedly:\n"
                    f"stdout: {stdout.decode()}\n"
                    f"stderr: {stderr.decode()}"
                )
            
            time.sleep(0.1)
        
        # Timeout - kill process and raise
        self.stop()
        raise RuntimeError(
            f"capiscio server did not start within {timeout}s. "
            f"Socket not found at {self._socket_path}"
        )
    
    def stop(self) -> None:
        """Stop the gRPC server process."""
        if self._process is None:
            return
        
        if self._process.poll() is None:
            # Process still running, terminate gracefully
            try:
                self._process.terminate()
                self._process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                # Force kill
                self._process.kill()
                self._process.wait()
        
        self._process = None
        self._started = False
        
        # Clean up socket
        if self._socket_path and self._socket_path.exists():
            try:
                self._socket_path.unlink()
            except OSError:
                pass
    
    def restart(self) -> str:
        """Restart the gRPC server."""
        self.stop()
        return self.ensure_running(
            socket_path=self._socket_path,
            tcp_address=self._tcp_address,
        )


# Global instance for convenience
_manager: Optional[ProcessManager] = None


def get_process_manager() -> ProcessManager:
    """Get the global ProcessManager instance."""
    global _manager
    if _manager is None:
        _manager = ProcessManager()
    return _manager
