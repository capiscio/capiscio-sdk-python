"""Tests for the warmup CLI module."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from capiscio_sdk.warmup import main


class TestWarmup:
    def test_already_cached(self, tmp_path):
        """When binary is already cached, prints 'Already cached' and returns 0."""
        fake_binary = tmp_path / "capiscio"
        fake_binary.write_text("#!/bin/sh\necho v2.4.0")
        fake_binary.chmod(0o755)

        with patch("capiscio_sdk.warmup.ProcessManager") as MockPM:
            instance = MockPM.return_value
            instance._get_platform_info.return_value = ("darwin", "arm64")
            instance.find_binary.return_value = fake_binary
            with patch("capiscio_sdk.warmup.subprocess") as mock_sub:
                mock_sub.run.return_value = MagicMock(returncode=0, stdout="v2.4.0", stderr="")
                mock_sub.TimeoutExpired = TimeoutError
                result = main()

        assert result == 0
        instance._download_binary.assert_not_called()

    def test_download_needed(self, tmp_path):
        """When binary is not cached, downloads it and returns 0."""
        fake_binary = tmp_path / "capiscio"
        fake_binary.write_text("#!/bin/sh\necho v2.4.0")
        fake_binary.chmod(0o755)

        with patch("capiscio_sdk.warmup.ProcessManager") as MockPM:
            instance = MockPM.return_value
            instance._get_platform_info.return_value = ("linux", "amd64")
            instance.find_binary.return_value = None
            instance._download_binary.return_value = fake_binary
            with patch("capiscio_sdk.warmup.subprocess") as mock_sub:
                mock_sub.run.return_value = MagicMock(returncode=0, stdout="v2.4.0", stderr="")
                mock_sub.TimeoutExpired = TimeoutError
                result = main()

        assert result == 0
        instance._download_binary.assert_called_once()

    def test_binary_verification_failure(self, tmp_path):
        """When binary --version returns non-zero, returns 1."""
        fake_binary = tmp_path / "capiscio"
        fake_binary.write_text("")
        fake_binary.chmod(0o755)

        with patch("capiscio_sdk.warmup.ProcessManager") as MockPM:
            instance = MockPM.return_value
            instance._get_platform_info.return_value = ("darwin", "arm64")
            instance.find_binary.return_value = fake_binary
            with patch("capiscio_sdk.warmup.subprocess") as mock_sub:
                mock_sub.run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
                mock_sub.TimeoutExpired = TimeoutError
                result = main()

        assert result == 1

    def test_binary_not_found_error(self, tmp_path):
        """When binary doesn't exist at the returned path, returns 1."""
        fake_binary = tmp_path / "nonexistent"

        with patch("capiscio_sdk.warmup.ProcessManager") as MockPM:
            instance = MockPM.return_value
            instance._get_platform_info.return_value = ("darwin", "arm64")
            instance.find_binary.return_value = fake_binary
            with patch("capiscio_sdk.warmup.subprocess") as mock_sub:
                mock_sub.run.side_effect = FileNotFoundError("not found")
                mock_sub.TimeoutExpired = TimeoutError
                result = main()

        assert result == 1

    def test_version_timeout_still_ok(self, tmp_path):
        """When --version times out, still returns 0 (binary exists)."""
        import subprocess as real_subprocess

        fake_binary = tmp_path / "capiscio"
        fake_binary.write_text("")
        fake_binary.chmod(0o755)

        with patch("capiscio_sdk.warmup.ProcessManager") as MockPM:
            instance = MockPM.return_value
            instance._get_platform_info.return_value = ("darwin", "arm64")
            instance.find_binary.return_value = fake_binary
            with patch("capiscio_sdk.warmup.subprocess") as mock_sub:
                mock_sub.run.side_effect = real_subprocess.TimeoutExpired("cmd", 10)
                mock_sub.TimeoutExpired = real_subprocess.TimeoutExpired
                result = main()

        assert result == 0
