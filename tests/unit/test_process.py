"""Unit tests for capiscio_sdk._rpc.process module."""

import os
import platform
import pytest
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
        """Test find_binary uses CAPISCIO_BINARY environment variable."""
        pm = ProcessManager()
        test_path = "/usr/local/bin/custom-capiscio"
        
        with patch.dict(os.environ, {"CAPISCIO_BINARY": test_path}):
            with patch("pathlib.Path.exists", return_value=True):
                result = pm.find_binary()
                assert result == Path(test_path)

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

    @patch("httpx.stream")
    def test_download_binary_http_error(self, mock_stream):
        """Test download handles HTTP errors."""
        pm = ProcessManager()
        
        with patch("capiscio_sdk._rpc.process.platform.system", return_value="Linux"):
            with patch("capiscio_sdk._rpc.process.platform.machine", return_value="x86_64"):
                with patch.object(ProcessManager, "_get_cached_binary_path") as mock_cached:
                    mock_path = MagicMock()
                    mock_path.exists.side_effect = [False, False]  # Not exists before download, not exists after cleanup
                    mock_path.parent = MagicMock()
                    mock_cached.return_value = mock_path
                    
                    # Mock HTTP error
                    mock_response = MagicMock()
                    mock_response.raise_for_status.side_effect = Exception("404 Not Found")
                    mock_stream.return_value.__enter__.return_value = mock_response
                    
                    with pytest.raises(RuntimeError, match="Failed to download capiscio-core"):
                        pm._download_binary()

    def test_ensure_running_downloads_if_not_found(self):
        """Test ensure_running downloads binary if not found."""
        pm = ProcessManager()
        
        with patch.object(pm, "find_binary", return_value=None):
            with patch.object(pm, "_download_binary") as mock_download:
                mock_download.return_value = Path("/tmp/capiscio-core")
                with patch.object(pm, "start"):
                    with patch.object(pm, "is_running", return_value=True):
                        pm.ensure_running()
                        
                        mock_download.assert_called_once()
