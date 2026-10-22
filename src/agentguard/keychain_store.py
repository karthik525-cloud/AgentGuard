
"""macOS Keychain storage for AgentGuard signing keys."""

import subprocess


DEFAULT_SERVICE = "AgentGuard.SigningKey"
DEFAULT_ACCOUNT = "agentguard-connector"


def store_key(
    secret_key: bytes,
    service: str = DEFAULT_SERVICE,
    account: str = DEFAULT_ACCOUNT,
) -> None:
    """Store a signing key in the user's default macOS Keychain."""
    if not isinstance(secret_key, bytes) or len(secret_key) < 32:
        raise ValueError("secret_key must contain at least 32 bytes")

    result = subprocess.run(
        [
            "/usr/bin/security",
            "add-generic-password",
            "-U",
            "-a", account,
            "-s", service,
            "-w", secret_key.hex(),
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "Could not store the key in macOS Keychain: "
            + result.stderr.strip()
        )


def load_key(
    service: str = DEFAULT_SERVICE,
    account: str = DEFAULT_ACCOUNT,
) -> bytes:
    """Load a signing key from the user's default macOS Keychain."""
    result = subprocess.run(
        [
            "/usr/bin/security",
            "find-generic-password",
            "-a", account,
            "-s", service,
            "-w",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "Could not load the key from macOS Keychain. Store a key first."
        )

    try:
        secret_key = bytes.fromhex(result.stdout.strip())
    except ValueError as exc:
        raise RuntimeError("Stored Keychain value is not valid hex.") from exc

    if len(secret_key) < 32:
        raise RuntimeError("Stored signing key is too short.")

    return secret_key


def delete_key(
    service: str = DEFAULT_SERVICE,
    account: str = DEFAULT_ACCOUNT,
) -> None:
    """Delete a signing key from the user's default macOS Keychain."""
    result = subprocess.run(
        [
            "/usr/bin/security",
            "delete-generic-password",
            "-a", account,
            "-s", service,
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "Could not delete the Keychain item: " + result.stderr.strip()
        )
