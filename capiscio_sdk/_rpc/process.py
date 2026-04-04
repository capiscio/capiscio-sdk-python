"""Process manager for the capiscio-core gRPC server."""

import atexit
import hashlib
import logging
import os
import platform
import shutil
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional, Tuple

import httpx

logger = logging.getLogger(__name__)

# Default socket path — use PID-specific path to avoid contention
# with orphaned capiscio-core processes from previous runs.
DEFAULT_SOCKET_DIR = Path.home() / ".capiscio"


def _default_socket_path() -> Path:
    """Compute PID-specific socket path lazily at runtime.

    This must NOT be computed at import time because forked child processes
    would inherit the parent's PID-based path and contend on the same socket.
    """
    return DEFAULT_SOCKET_DIR / f"rpc-{os.getpid()}.sock"


def _cleanup_stale_sockets() -> None:
    """Remove rpc-*.sock files whose PID is no longer running."""
    try:
        for sock in DEFAULT_SOCKET_DIR.glob("rpc-*.sock"):
            try:
                pid_str = sock.stem.split("-", 1)[1]
                pid = int(pid_str)
                os.kill(pid, 0)  # Check if PID exists
            except (ValueError, IndexError):
                sock.unlink(missing_ok=True)
            except ProcessLookupError:
                # PID doesn't exist — stale socket
                logger.debug("Removing stale socket %s", sock)
                sock.unlink(missing_ok=True)
            except PermissionError:
                pass  # PID exists but owned by another user
    except OSError:
        pass

# Binary download configuration
CORE_VERSION = "2.5.0"
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
        return f"unix://{_default_socket_path()}"
    
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

    def ensure_cached(self) -> Path:
        """Ensure the capiscio-core binary is downloaded and cached.

        Returns the path to the cached binary. If the binary is already
        present in the versioned cache directory, the download is skipped.

        This is the public API for pre-caching the binary without starting
        the gRPC process (used by the ``capiscio-warmup`` CLI).
        """
        cached = self._get_cached_binary_path()
        if cached.exists():
            return cached
        return self._download_binary()

    def _download_binary(self) -> Path:
        """Download the capiscio-core binary for the current platform.
        
        Downloads from GitHub releases to ~/.capiscio/bin/<version>/.
        Verifies SHA-256 checksum against published checksums.txt.
        Retries up to 3 times with exponential backoff.
        Returns the path to the executable.
        """
        os_name, arch_name = self._get_platform_info()
        target_path = self._get_cached_binary_path()

        if target_path.exists():
            return target_path

        url = f"https://github.com/{GITHUB_REPO}/releases/download/v{CORE_VERSION}/{target_path.name}"

        sys.stderr.write(
            f"capiscio-core v{CORE_VERSION} not found. "
            f"Downloading for {os_name}/{arch_name}...\n"
        )
        sys.stderr.flush()
        logger.info("Downloading capiscio-core v%s for %s/%s...", CORE_VERSION, os_name, arch_name)

        target_path.parent.mkdir(parents=True, exist_ok=True)
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                with httpx.stream("GET", url, follow_redirects=True, timeout=60.0) as resp:
                    resp.raise_for_status()
                    with open(target_path, "wb") as f:
                        for chunk in resp.iter_bytes(chunk_size=8192):
                            f.write(chunk)

                # Verify checksum integrity BEFORE making executable
                require_checksum = os.environ.get("CAPISCIO_REQUIRE_CHECKSUM", "").lower() in ("1", "true", "yes")
                expected_hash = self._fetch_expected_checksum(CORE_VERSION, target_path.name)
                if expected_hash is not None:
                    if not self._verify_checksum(target_path, expected_hash):
                        target_path.unlink()
                        raise RuntimeError(
                            f"Binary integrity check failed for {target_path.name}. "
                            "The downloaded file does not match the published checksum. "
                            "This may indicate a tampered or corrupted download."
                        )
                    logger.info("Checksum verified for %s", target_path.name)
                elif require_checksum:
                    target_path.unlink()
                    raise RuntimeError(
                        f"Checksum verification required (CAPISCIO_REQUIRE_CHECKSUM=true) "
                        f"but checksums.txt is not available for v{CORE_VERSION}. "
                        "Cannot verify binary integrity."
                    )
                else:
                    logger.warning(
                        "Could not verify binary integrity (checksums.txt not available). "
                        "Set CAPISCIO_REQUIRE_CHECKSUM=true to enforce verification."
                    )

                # Make executable only after checksum passes
                st = os.stat(target_path)
                os.chmod(target_path, st.st_mode | stat.S_IEXEC)

                sys.stderr.write(f"Installed capiscio-core v{CORE_VERSION} at {target_path}\n")
                sys.stderr.flush()
                logger.info("Installed capiscio-core v%s at %s", CORE_VERSION, target_path)
                return target_path

            except Exception as e:
                if target_path.exists():
                    target_path.unlink()
                if attempt < max_attempts:
                    delay = 2 ** (attempt - 1)
                    logger.warning(
                        "Download attempt %d/%d failed: %s. Retrying in %ds...",
                        attempt, max_attempts, e, delay,
                    )
                    time.sleep(delay)
                else:
                    raise RuntimeError(
                        f"Failed to download capiscio-core from {url} "
                        f"after {max_attempts} attempts: {e}\n"
                        "You can also set CAPISCIO_BINARY to point to an existing binary."
                    ) from e
        # unreachable, but keeps type checker happy
        raise RuntimeError("Download failed")

    @staticmethod
    def _fetch_expected_checksum(version: str, filename: str) -> Optional[str]:
        """Fetch the expected SHA-256 checksum from the release checksums.txt."""
        url = f"https://github.com/{GITHUB_REPO}/releases/download/v{version}/checksums.txt"
        try:
            resp = httpx.get(url, follow_redirects=True, timeout=30.0)
            resp.raise_for_status()
            for line in resp.text.strip().splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[1] == filename:
                    return parts[0]
            logger.warning("Binary %s not found in checksums.txt", filename)
            return None
        except httpx.HTTPError as e:
            logger.warning("Could not fetch checksums.txt: %s", e)
            return None

    @staticmethod
    def _verify_checksum(file_path: Path, expected_hash: str) -> bool:
        """Verify SHA-256 checksum of a downloaded file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        actual = sha256.hexdigest()
        if actual != expected_hash:
            logger.error("Checksum mismatch: expected %s, got %s", expected_hash, actual)
            return False
        return True
    
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
        
        # Windows doesn't support Unix sockets — use TCP instead
        if sys.platform == "win32":
            return self._start_tcp(binary, timeout)
        else:
            return self._start_unix_socket(binary, socket_path, timeout)

    def _start_tcp(self, binary: Path, timeout: float) -> str:
        """Start the gRPC server with a TCP listener (used on Windows)."""
        port = self._find_free_port()
        addr = f"localhost:{port}"
        cmd = [str(binary), "rpc", "--address", addr]

        try:
            popen_kwargs = {
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
            }
            if sys.platform == "win32":
                popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                popen_kwargs["start_new_session"] = True
            self._process = subprocess.Popen(cmd, **popen_kwargs)
        except Exception as e:
            raise RuntimeError(f"Failed to start capiscio server: {e}") from e

        self._tcp_address = addr
        self._wait_grpc_ready(addr, timeout)
        self._drain_pipes()
        self._started = True
        return self.address

    def _start_unix_socket(
        self, binary: Path, socket_path: Optional[Path], timeout: float
    ) -> str:
        """Start the gRPC server with a Unix socket listener."""
        # Set up socket path
        self._socket_path = socket_path or _default_socket_path()
        
        # Ensure socket directory exists
        self._socket_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Clean up stale sockets from previous runs
        _cleanup_stale_sockets()
        
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
        
        # Wait for socket file to appear
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self._socket_path.exists():
                break
            
            # Check if process died
            if self._process.poll() is not None:
                stdout, stderr = self._process.communicate()
                self.stop()
                raise RuntimeError(
                    f"capiscio server exited unexpectedly:\n"
                    f"stdout: {stdout.decode(errors='replace') if stdout else ''}\n"
                    f"stderr: {stderr.decode(errors='replace') if stderr else ''}"
                )
            
            time.sleep(0.1)
        else:
            # Timeout - kill process and raise
            self.stop()
            raise RuntimeError(
                f"capiscio server did not start within {timeout}s. "
                f"Socket not found at {self._socket_path}"
            )
        
        # Socket exists — verify gRPC is actually accepting connections
        remaining = timeout - (time.time() - start_time)
        addr = f"unix://{self._socket_path}"
        self._wait_grpc_ready(addr, remaining)
        self._drain_pipes()
        self._started = True
        return self.address

    @staticmethod
    def _find_free_port() -> int:
        """Find a free TCP port by binding to port 0."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            return s.getsockname()[1]

    def _drain_pipes(self) -> None:
        """Close piped stdout/stderr to prevent OS buffer fill on long-lived processes."""
        if self._process is not None:
            if self._process.stdout:
                self._process.stdout.close()
            if self._process.stderr:
                self._process.stderr.close()

    def _wait_grpc_ready(self, addr: str, remaining: float) -> None:
        """Wait for the gRPC server to accept connections."""
        if remaining <= 0:
            return
        import grpc
        deadline = time.time() + remaining
        while time.time() < deadline:
            # Check if process died
            if self._process is not None and self._process.poll() is not None:
                stdout, stderr = self._process.communicate()
                self.stop()
                raise RuntimeError(
                    f"capiscio server exited unexpectedly:\n"
                    f"stdout: {stdout.decode(errors='replace') if stdout else ''}\n"
                    f"stderr: {stderr.decode(errors='replace') if stderr else ''}"
                )
            time_left = deadline - time.time()
            if time_left <= 0:
                break
            channel = grpc.insecure_channel(addr)
            try:
                grpc.channel_ready_future(channel).result(timeout=min(1.0, time_left))
                return
            except grpc.FutureTimeoutError:
                time.sleep(0.1)
            except Exception:
                time.sleep(0.1)
            finally:
                channel.close()
        self.stop()
        raise RuntimeError(
            f"capiscio server gRPC not ready within timeout at {addr}"
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
