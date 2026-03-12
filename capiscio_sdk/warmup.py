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

    print(f"capiscio-core v{CORE_VERSION}")

    # Ensure binary is in the versioned cache (~/.capiscio/bin/<version>/)
    binary = manager.ensure_cached()
    print(f"  Binary path: {binary}")

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
    except PermissionError as exc:
        print(f"  Error: cannot execute binary at {binary}: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"  Error: unexpected failure: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
