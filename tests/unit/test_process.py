"""Unit tests for capiscio_sdk._rpc.process module."""

import os
import platform
import pytest
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

from capiscio_sdk._rpc.process import ProcessManager, CORE_VERSION, CACHE_DIR


class TestProcessManager:
    """Tests for ProcessManager class."""

    def test_get_platform_info_darwin_x86_64(self):
        """Test platform detection for macOS x86_64."""
        with patch("capiscio_sdk._rpc.process.platform.system", return_value="Darwin"):
            with patch("capiscio_sdk._rpc.process.platform.machine", return_value="x86_64"):
                os_name, arch_name = ProcessManager._get_platform_info()
                assert os_name == "darwin"
                assert arch_name == "amd64"

    def test_get_platform_info_darwin_arm64(self):
        """Test platform detection for macOS ARM64."""
        with patch("capiscio_sdk._rpc.process.platform.system", return_value="Darwin"):
            with patch("capiscio_sdk._rpc.process.platform.machine", return_value="arm64"):
                os_name, arch_name = ProcessManager._get_platform_info()
                assert os_name == "darwin"
                assert arch_name == "arm64"

    def test_get_platform_info_linux_x86_64(self):
        """Test platform detection for Linux x86_64."""
        with patch("capiscio_sdk._rpc.process.platform.system", return_value="Linux"):
            with patch("capiscio_sdk._rpc.process.platform.machine", return_value="x86_64"):
                os_name, arch_name = ProcessManager._get_platform_info()
                assert os_name == "linux"
                assert arch_name == "amd64"

    def test_get_platform_info_linux_aarch64(self):
        """Test platform detection for Linux ARM64."""
        with patch("capiscio_sdk._rpc.process.platform.system", return_value="Linux"):
            with patch("capiscio_sdk._rpc.process.platform.machine", return_value="aarch64"):
                os_name, arch_name = ProcessManager._get_platform_info()
                assert os_name == "linux"
                assert arch_name == "arm64"

    def test_get_platform_info_windows_amd64(self):
        """Test platform detection for Windows x86_64."""
        with patch("capiscio_sdk._rpc.process.platform.system", return_value="Windows"):
            with patch("capiscio_sdk._rpc.process.platform.machine", return_value="amd64"):
                os_name, arch_name = ProcessManager._get_platform_info()
                assert os_name == "windows"
                assert arch_name == "amd64"

    def test_get_platform_info_unsupported_os(self):
        """Test platform detection with unsupported OS."""
        with patch("capiscio_sdk._rpc.process.platform.system", return_value="FreeBSD"):
            with patch("capiscio_sdk._rpc.process.platform.machine", return_value="x86_64"):
                with pytest.raises(RuntimeError, match="Unsupported operating system"):
                    ProcessManager._get_platform_info()

    def test_get_platform_info_unsupported_arch(self):
        """Test platform detection with unsupported architecture."""
        with patch("capiscio_sdk._rpc.process.platform.system", return_value="Linux"):
            with patch("capiscio_sdk._rpc.process.platform.machine", return_value="mips"):
                with pytest.raises(RuntimeError, match="Unsupported architecture"):
                    ProcessManager._get_platform_info()

    def test_get_cached_binary_path(self):
        """Test cached binary path generation."""
        with patch("capiscio_sdk._rpc.process.platform.system", return_value="Linux"):
            with patch("capiscio_sdk._rpc.process.platform.machine", return_value="x86_64"):
                path = ProcessManager._get_cached_binary_path()
                expected = CACHE_DIR / CORE_VERSION / "capiscio-linux-amd64"
                assert path == expected

    def test_get_cached_binary_path_windows(self):
        """Test cached binary path generation for Windows."""
        with patch("capiscio_sdk._rpc.process.platform.system", return_value="Windows"):
            with patch("capiscio_sdk._rpc.process.platform.machine", return_value="x86_64"):
                path = ProcessManager._get_cached_binary_path()
                expected = CACHE_DIR / CORE_VERSION / "capiscio-windows-amd64.exe"
                assert path == expected

    def test_find_binary_env_var(self):
        """Test find_binary checks CAPISCIO_BINARY environment variable."""
        pm = ProcessManager()
        test_path = "/usr/local/bin/custom-capiscio"
        
        # We can't fully test this without the file existing, but we can verify
        # the env var is checked by ensuring non-existent path returns None
        with patch.dict(os.environ, {"CAPISCIO_BINARY": test_path}):
            # Mock ALL Path.exists() calls to return False so it doesn't find dev binary
            # but then the env var path also returns False
            with patch.object(Path, "exists", return_value=False):
                with patch("shutil.which", return_value=None):
                    result = pm.find_binary()
                    # With env var path not existing and dev binary not existing,
                    # should return None
                    assert result is None

    def test_find_binary_system_path(self):
        """Test find_binary finds binary in system PATH."""
        pm = ProcessManager()
        
        with patch.dict(os.environ, {}, clear=True):
            with patch("shutil.which", return_value="/usr/local/bin/capiscio-core"):
                result = pm.find_binary()
                assert result == Path("/usr/local/bin/capiscio-core")

    def test_find_binary_cached(self):
        """Test find_binary finds previously downloaded binary."""
        pm = ProcessManager()
        
        with patch.dict(os.environ, {}, clear=True):
            with patch("shutil.which", return_value=None):
                with patch.object(ProcessManager, "_get_cached_binary_path") as mock_cached:
                    mock_path = MagicMock()
                    mock_path.exists.return_value = True
                    mock_cached.return_value = mock_path
                    
                    result = pm.find_binary()
                    assert result == mock_path

    def test_find_binary_not_found(self):
        """Test find_binary returns None when binary not found."""
        pm = ProcessManager()
        
        with patch.dict(os.environ, {}, clear=True):
            with patch("shutil.which", return_value=None):
                with patch.object(ProcessManager, "_get_cached_binary_path") as mock_cached:
                    mock_path = MagicMock()
                    mock_path.exists.return_value = False
                    mock_cached.return_value = mock_path
                    
                    result = pm.find_binary()
                    assert result is None

    @patch("httpx.stream")
    @patch("os.chmod")
    @patch("os.stat")
    def test_download_binary_success(self, mock_stat, mock_chmod, mock_stream):
        """Test successful binary download."""
        pm = ProcessManager()
        
        # Mock platform detection
        with patch("capiscio_sdk._rpc.process.platform.system", return_value="Linux"):
            with patch("capiscio_sdk._rpc.process.platform.machine", return_value="x86_64"):
                # Mock cached path doesn't exist
                with patch.object(ProcessManager, "_get_cached_binary_path") as mock_cached:
                    mock_path = MagicMock()
                    mock_path.exists.return_value = False
                    mock_path.parent = MagicMock()
                    mock_cached.return_value = mock_path
                    
                    # Mock HTTP response
                    mock_response = MagicMock()
                    mock_response.status_code = 200
                    mock_response.iter_bytes.return_value = [b"binary", b"data"]
                    mock_stream.return_value.__enter__.return_value = mock_response
                    
                    # Mock file operations
                    m_open = mock_open()
                    with patch("builtins.open", m_open):
                        result = pm._download_binary()
                    
                    # Verify download was attempted
                    mock_stream.assert_called_once()
                    assert result == mock_path

    @patch("httpx.stream")
    def test_download_binary_already_cached(self, mock_stream):
        """Test download skips if binary already cached."""
        pm = ProcessManager()
        
        with patch("capiscio_sdk._rpc.process.platform.system", return_value="Linux"):
            with patch("capiscio_sdk._rpc.process.platform.machine", return_value="x86_64"):
                with patch.object(ProcessManager, "_get_cached_binary_path") as mock_cached:
                    mock_path = MagicMock()
                    mock_path.exists.return_value = True
                    mock_cached.return_value = mock_path
                    
                    result = pm._download_binary()
                    
                    # Should not attempt download
                    mock_stream.assert_not_called()
                    assert result == mock_path

    @patch("capiscio_sdk._rpc.process.time.sleep")
    @patch("httpx.stream")
    def test_download_binary_http_error(self, mock_stream, mock_sleep):
        """Test download handles HTTP errors with retries."""
        pm = ProcessManager()
        
        with patch("capiscio_sdk._rpc.process.platform.system", return_value="Linux"):
            with patch("capiscio_sdk._rpc.process.platform.machine", return_value="x86_64"):
                with patch.object(ProcessManager, "_get_cached_binary_path") as mock_cached:
                    mock_path = MagicMock()
                    # exists() called: once before loop, then once per attempt for cleanup
                    mock_path.exists.return_value = False
                    mock_path.parent = MagicMock()
                    mock_cached.return_value = mock_path
                    
                    # Mock HTTP error
                    mock_response = MagicMock()
                    mock_response.raise_for_status.side_effect = Exception("404 Not Found")
                    mock_stream.return_value.__enter__.return_value = mock_response
                    
                    with pytest.raises(RuntimeError, match="Failed to download capiscio-core"):
                        pm._download_binary()

    def test_binary_download_triggered_when_not_found(self):
        """Test that _download_binary method exists and is callable."""
        pm = ProcessManager()
        
        # Just verify the method exists and can be mocked for integration
        assert hasattr(pm, "_download_binary")
        assert callable(pm._download_binary)

    def test_find_free_port(self):
        """Test that _find_free_port returns a valid port number."""
        port = ProcessManager._find_free_port()
        assert isinstance(port, int)
        assert 1 <= port <= 65535

    def test_ensure_running_delegates_to_tcp_on_windows(self):
        """Test ensure_running uses TCP when sys.platform is win32."""
        pm = ProcessManager()
        mock_binary = MagicMock()

        with patch.object(pm, "find_binary", return_value=mock_binary):
            with patch("capiscio_sdk._rpc.process.sys.platform", "win32"):
                with patch.object(pm, "_start_tcp", return_value="localhost:9999") as mock_tcp:
                    result = pm.ensure_running()
                    mock_tcp.assert_called_once_with(mock_binary, 5.0)
                    assert result == "localhost:9999"

    def test_ensure_running_delegates_to_unix_socket_on_posix(self):
        """Test ensure_running uses Unix socket when not on Windows."""
        pm = ProcessManager()
        mock_binary = MagicMock()

        with patch.object(pm, "find_binary", return_value=mock_binary):
            with patch("capiscio_sdk._rpc.process.sys.platform", "darwin"):
                with patch.object(
                    pm, "_start_unix_socket", return_value="unix:///tmp/test.sock"
                ) as mock_unix:
                    result = pm.ensure_running()
                    mock_unix.assert_called_once_with(mock_binary, None, 5.0)
                    assert result == "unix:///tmp/test.sock"

    def test_start_tcp_spawns_with_address_flag(self):
        """Test _start_tcp spawns the binary with --address flag."""
        pm = ProcessManager()
        mock_binary = Path("/tmp/capiscio")

        with patch.object(ProcessManager, "_find_free_port", return_value=54321):
            with patch("subprocess.Popen") as mock_popen:
                mock_proc = MagicMock()
                mock_proc.poll.return_value = None
                mock_popen.return_value = mock_proc

                with patch.object(pm, "_wait_grpc_ready"):
                    pm._start_tcp(mock_binary, timeout=5.0)

                # Verify it used --address, not --socket
                call_args = mock_popen.call_args
                cmd = call_args[0][0]
                assert cmd == ["/tmp/capiscio", "rpc", "--address", "localhost:54321"]
                assert pm._tcp_address == "localhost:54321"

    def test_start_tcp_uses_platform_appropriate_process_isolation(self):
        """Test _start_tcp uses correct process isolation per platform."""
        pm = ProcessManager()
        mock_binary = Path("/tmp/capiscio")

        with patch.object(ProcessManager, "_find_free_port", return_value=12345):
            with patch("subprocess.Popen") as mock_popen:
                mock_proc = MagicMock()
                mock_proc.poll.return_value = None
                mock_popen.return_value = mock_proc

                with patch.object(pm, "_wait_grpc_ready"):
                    pm._start_tcp(mock_binary, timeout=5.0)

                call_kwargs = mock_popen.call_args[1]
                if sys.platform == "win32":
                    import subprocess
                    assert call_kwargs["creationflags"] == subprocess.CREATE_NEW_PROCESS_GROUP
                else:
                    assert call_kwargs["start_new_session"] is True

    def test_address_property_returns_tcp_when_set(self):
        """Test address property returns TCP address when set."""
        pm = ProcessManager()
        pm._tcp_address = "localhost:50051"
        assert pm.address == "localhost:50051"

    def test_address_property_returns_unix_by_default(self):
        """Test address property returns Unix socket by default."""
        pm = ProcessManager()
        pm._tcp_address = None
        pm._socket_path = None
        from capiscio_sdk._rpc.process import _default_socket_path
        assert pm.address == f"unix://{_default_socket_path()}"


class TestChecksumVerification:
    """Tests for binary checksum verification paths."""

    @patch("httpx.get")
    def test_fetch_expected_checksum_success(self, mock_get):
        """Test _fetch_expected_checksum returns hash when file is found."""
        mock_resp = MagicMock()
        mock_resp.text = (
            "abc123def456  capiscio-linux-amd64\n"
            "789xyz000111  capiscio-darwin-arm64\n"
        )
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = ProcessManager._fetch_expected_checksum("2.5.0", "capiscio-linux-amd64")
        assert result == "abc123def456"

    @patch("httpx.get")
    def test_fetch_expected_checksum_file_not_in_list(self, mock_get):
        """Test _fetch_expected_checksum returns None when filename not in checksums."""
        mock_resp = MagicMock()
        mock_resp.text = "abc123  capiscio-linux-amd64\n"
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = ProcessManager._fetch_expected_checksum("2.5.0", "capiscio-darwin-arm64")
        assert result is None

    @patch("httpx.get")
    def test_fetch_expected_checksum_http_error(self, mock_get):
        """Test _fetch_expected_checksum returns None on HTTP error."""
        import httpx as httpx_mod
        mock_get.side_effect = httpx_mod.HTTPError("connection failed")

        result = ProcessManager._fetch_expected_checksum("2.5.0", "capiscio-linux-amd64")
        assert result is None

    @patch("httpx.get")
    @patch("httpx.stream")
    @patch("os.chmod")
    @patch("os.stat")
    def test_download_binary_checksum_match(self, mock_stat, mock_chmod, mock_stream, mock_get):
        """Test successful download with matching checksum."""
        pm = ProcessManager()

        with patch("capiscio_sdk._rpc.process.platform.system", return_value="Linux"):
            with patch("capiscio_sdk._rpc.process.platform.machine", return_value="x86_64"):
                with patch.object(ProcessManager, "_get_cached_binary_path") as mock_cached:
                    mock_path = MagicMock(spec=Path)
                    mock_path.exists.return_value = False
                    mock_path.parent = MagicMock()
                    mock_path.name = "capiscio-linux-amd64"
                    mock_cached.return_value = mock_path

                    # Mock stream download
                    mock_response = MagicMock()
                    mock_response.iter_bytes.return_value = [b"binary_data"]
                    mock_stream.return_value.__enter__.return_value = mock_response

                    # Mock checksum fetch (returns a hash)
                    mock_get_resp = MagicMock()
                    mock_get_resp.text = "fakehash123  capiscio-linux-amd64\n"
                    mock_get_resp.raise_for_status = MagicMock()
                    mock_get.return_value = mock_get_resp

                    # Mock verify_checksum to return True
                    with patch.object(ProcessManager, "_verify_checksum", return_value=True):
                        m_open = mock_open()
                        with patch("builtins.open", m_open):
                            result = pm._download_binary()

                    assert result == mock_path
                    # chmod should be called (checksum passed)
                    mock_chmod.assert_called_once()

    @patch("httpx.get")
    @patch("httpx.stream")
    def test_download_binary_checksum_mismatch_deletes_file(self, mock_stream, mock_get):
        """Test that checksum mismatch deletes the file and raises."""
        pm = ProcessManager()

        with patch("capiscio_sdk._rpc.process.platform.system", return_value="Linux"):
            with patch("capiscio_sdk._rpc.process.platform.machine", return_value="x86_64"):
                with patch.object(ProcessManager, "_get_cached_binary_path") as mock_cached:
                    mock_path = MagicMock(spec=Path)
                    mock_path.exists.return_value = False
                    mock_path.parent = MagicMock()
                    mock_path.name = "capiscio-linux-amd64"
                    mock_cached.return_value = mock_path

                    mock_response = MagicMock()
                    mock_response.iter_bytes.return_value = [b"bad_data"]
                    mock_stream.return_value.__enter__.return_value = mock_response

                    mock_get_resp = MagicMock()
                    mock_get_resp.text = "expected_hash  capiscio-linux-amd64\n"
                    mock_get_resp.raise_for_status = MagicMock()
                    mock_get.return_value = mock_get_resp

                    with patch.object(ProcessManager, "_verify_checksum", return_value=False):
                        m_open = mock_open()
                        with patch("builtins.open", m_open):
                            with pytest.raises(RuntimeError, match="integrity check failed"):
                                pm._download_binary()

                    # File should have been deleted
                    mock_path.unlink.assert_called()

    @patch("httpx.get")
    @patch("httpx.stream")
    def test_download_binary_require_checksum_no_checksums_available(self, mock_stream, mock_get):
        """Test CAPISCIO_REQUIRE_CHECKSUM fails when checksums.txt unavailable."""
        import httpx as httpx_mod
        pm = ProcessManager()

        with patch("capiscio_sdk._rpc.process.platform.system", return_value="Linux"):
            with patch("capiscio_sdk._rpc.process.platform.machine", return_value="x86_64"):
                with patch.object(ProcessManager, "_get_cached_binary_path") as mock_cached:
                    mock_path = MagicMock(spec=Path)
                    mock_path.exists.return_value = False
                    mock_path.parent = MagicMock()
                    mock_path.name = "capiscio-linux-amd64"
                    mock_cached.return_value = mock_path

                    mock_response = MagicMock()
                    mock_response.iter_bytes.return_value = [b"data"]
                    mock_stream.return_value.__enter__.return_value = mock_response

                    # checksums.txt fetch fails
                    mock_get.side_effect = httpx_mod.HTTPError("404")

                    with patch.dict(os.environ, {"CAPISCIO_REQUIRE_CHECKSUM": "true"}):
                        m_open = mock_open()
                        with patch("builtins.open", m_open):
                            with pytest.raises(RuntimeError, match="Checksum verification required"):
                                pm._download_binary()

                    mock_path.unlink.assert_called()

    @patch("httpx.get")
    @patch("httpx.stream")
    @patch("os.chmod")
    @patch("os.stat")
    def test_download_binary_checksums_unavailable_without_require(
        self, mock_stat, mock_chmod, mock_stream, mock_get
    ):
        """Test download proceeds with warning when checksums unavailable and not required."""
        import httpx as httpx_mod
        pm = ProcessManager()

        with patch("capiscio_sdk._rpc.process.platform.system", return_value="Linux"):
            with patch("capiscio_sdk._rpc.process.platform.machine", return_value="x86_64"):
                with patch.object(ProcessManager, "_get_cached_binary_path") as mock_cached:
                    mock_path = MagicMock(spec=Path)
                    mock_path.exists.return_value = False
                    mock_path.parent = MagicMock()
                    mock_path.name = "capiscio-linux-amd64"
                    mock_cached.return_value = mock_path

                    mock_response = MagicMock()
                    mock_response.iter_bytes.return_value = [b"data"]
                    mock_stream.return_value.__enter__.return_value = mock_response

                    # checksums.txt not available
                    mock_get.side_effect = httpx_mod.HTTPError("404")

                    with patch.dict(os.environ, {}, clear=False):
                        # Ensure CAPISCIO_REQUIRE_CHECKSUM is not set
                        os.environ.pop("CAPISCIO_REQUIRE_CHECKSUM", None)
                        m_open = mock_open()
                        with patch("builtins.open", m_open):
                            result = pm._download_binary()

                    # Should succeed despite no checksum
                    assert result == mock_path
                    mock_chmod.assert_called_once()

    @patch("httpx.get")
    @patch("httpx.stream")
    @patch("os.chmod")
    @patch("os.stat")
    def test_download_binary_chmod_after_checksum(self, mock_stat, mock_chmod, mock_stream, mock_get):
        """Test that chmod happens AFTER checksum verification, not before."""
        pm = ProcessManager()
        call_order = []

        with patch("capiscio_sdk._rpc.process.platform.system", return_value="Linux"):
            with patch("capiscio_sdk._rpc.process.platform.machine", return_value="x86_64"):
                with patch.object(ProcessManager, "_get_cached_binary_path") as mock_cached:
                    mock_path = MagicMock(spec=Path)
                    mock_path.exists.return_value = False
                    mock_path.parent = MagicMock()
                    mock_path.name = "capiscio-linux-amd64"
                    mock_cached.return_value = mock_path

                    mock_response = MagicMock()
                    mock_response.iter_bytes.return_value = [b"data"]
                    mock_stream.return_value.__enter__.return_value = mock_response

                    mock_get_resp = MagicMock()
                    mock_get_resp.text = "fakehash  capiscio-linux-amd64\n"
                    mock_get_resp.raise_for_status = MagicMock()
                    mock_get.return_value = mock_get_resp

                    def track_verify(*a, **kw):
                        call_order.append("verify")
                        return True

                    def track_chmod(*a, **kw):
                        call_order.append("chmod")

                    mock_chmod.side_effect = track_chmod

                    with patch.object(ProcessManager, "_verify_checksum", side_effect=track_verify):
                        m_open = mock_open()
                        with patch("builtins.open", m_open):
                            pm._download_binary()

                    assert call_order == ["verify", "chmod"], (
                        f"Expected verify before chmod, got: {call_order}"
                    )
