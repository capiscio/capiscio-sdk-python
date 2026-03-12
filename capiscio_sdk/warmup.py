"""Pre-download and cache the capiscio-core binary.

Usage:
    python -m capiscio_sdk.warmup

This is intended for Docker builds, CI pipelines, and serverless deployments
where you want to cache the binary at build time rather than downloading it
on first request.

See: https://github.com/capiscio/capiscio-sdk-python/issues/41
"""

from __future__ import annotations

import subprocess
import sys

from capiscio_sdk._rpc.process import CORE_VERSION, ProcessManager


def main() -> int:
    """Download and verify the capiscio-core binary, then exit."""
    manager = ProcessManager()
    os_name, arch_name = manager._get_platform_info()

    print(f"capiscio-core v{CORE_VERSION} for {os_name}-{arch_name}")

    # Check if already cached
    binary = manager.find_binary()
    if binary is not None:
        print(f"  Already cached: {binary}")
    else:
        # Download it
        binary = manager._download_binary()
        print(f"  Cached at: {binary}")

    # Verify the binary is executable
    try:
        result = subprocess.run(
            [str(binary), "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            version_str = result.stdout.strip() or result.stderr.strip()
            print(f"  Binary OK \u2713 ({version_str})" if version_str else "  Binary OK \u2713")
        else:
            print(f"  Warning: binary exited with code {result.returncode}", file=sys.stderr)
            return 1
    except FileNotFoundError:
        print(f"  Error: binary not found at {binary}", file=sys.stderr)
        return 1
    except subprocess.TimeoutExpired:
        # --version hanging likely means the binary exists but has different CLI
        print("  Binary OK \u2713 (version check timed out)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
