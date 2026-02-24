"""Process manager for the capiscio-core gRPC server."""

import atexit
import logging
import os
import platform
import shutil
import stat
import subprocess
import time
from pathlib import Path
from typing import Optional, Tuple

import httpx

logger = logging.getLogger(__name__)

# Default socket path
DEFAULT_SOCKET_DIR = Path.home() / ".capiscio"
DEFAULT_SOCKET_PATH = DEFAULT_SOCKET_DIR / "rpc.sock"

# Binary download configuration
CORE_VERSION = "2.4.0"
GITHUB_REPO = "capiscio/capiscio-core"
CACHE_DIR = DEFAULT_SOCKET_DIR / "bin"


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
        if hasattr(self, '_initialized') and self._initialized:
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
        2. capiscio-core/bin/capiscio relative to SDK (development)
        3. System PATH
        4. Downloaded binary in ~/.capiscio/bin/
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
        sdk_root = Path(__file__).parent.parent.parent
        workspace_root = sdk_root.parent
        dev_binary = workspace_root / "capiscio-core" / "bin" / "capiscio"
        if dev_binary.exists():
            return dev_binary
        
        # Check system PATH
        which_result = shutil.which("capiscio")
        if which_result:
            return Path(which_result)
        
        # Check previously downloaded binary
        cached = self._get_cached_binary_path()
        if cached.exists():
            return cached
        
        return None

    @staticmethod
    def _get_platform_info() -> Tuple[str, str]:
        """Determine OS and architecture for binary download."""
        system = platform.system().lower()
        machine = platform.machine().lower()

        if system == "darwin":
            os_name = "darwin"
        elif system == "linux":
            os_name = "linux"
        elif system == "windows":
            os_name = "windows"
        else:
            raise RuntimeError(f"Unsupported operating system: {system}")

        if machine in ("x86_64", "amd64"):
            arch_name = "amd64"
        elif machine in ("arm64", "aarch64"):
            arch_name = "arm64"
        else:
            raise RuntimeError(f"Unsupported architecture: {machine}")

        return os_name, arch_name

    @staticmethod
    def _get_cached_binary_path() -> Path:
        """Get the path where the downloaded binary would be cached."""
        os_name, arch_name = ProcessManager._get_platform_info()
        ext = ".exe" if os_name == "windows" else ""
        filename = f"capiscio-{os_name}-{arch_name}{ext}"
        return CACHE_DIR / CORE_VERSION / filename

    def _download_binary(self) -> Path:
        """Download the capiscio-core binary for the current platform.
        
        Downloads from GitHub releases to ~/.capiscio/bin/<version>/.
        Returns the path to the executable.
        """
        os_name, arch_name = self._get_platform_info()
        target_path = self._get_cached_binary_path()

        if target_path.exists():
            return target_path

        ext = ".exe" if os_name == "windows" else ""
        filename = f"capiscio-{os_name}-{arch_name}{ext}"
        url = f"https://github.com/{GITHUB_REPO}/releases/download/v{CORE_VERSION}/{filename}"

        logger.info("Downloading capiscio-core v%s for %s/%s...", CORE_VERSION, os_name, arch_name)

        target_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            # TODO: Add checksum verification for supply-chain security.
            # Should verify SHA256 hash before marking binary as executable.
            with httpx.stream("GET", url, follow_redirects=True, timeout=60.0) as resp:
                resp.raise_for_status()
                with open(target_path, "wb") as f:
                    for chunk in resp.iter_bytes(chunk_size=8192):
                        f.write(chunk)

            # Make executable
            st = os.stat(target_path)
            os.chmod(target_path, st.st_mode | stat.S_IEXEC)

            logger.info("Installed capiscio-core v%s at %s", CORE_VERSION, target_path)
            return target_path

        except Exception as e:
            if target_path.exists():
                target_path.unlink()
            raise RuntimeError(
                f"Failed to download capiscio-core from {url}: {e}\n"
                "You can also set CAPISCIO_BINARY to point to an existing binary."
            ) from e
    
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
            binary = self._download_binary()
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
                # Socket may have been cleaned up by another process
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
