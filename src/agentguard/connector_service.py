"""Authenticated local Unix-domain socket connector service for AgentGuard."""

import argparse
import json
import math
import os
import socket
import sqlite3
import stat
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, FrozenSet

from .keychain_store import DEFAULT_ACCOUNT, DEFAULT_SERVICE, load_key
from .trusted_connector import read_and_sign_booking

MAX_REQUEST_BYTES = 1024
DEFAULT_REQUEST_TIMEOUT_SECONDS = 5.0
_XUCRED = struct.Struct("=IIh2x16I")
_SOL_LOCAL = 0


class PeerAuthenticationError(RuntimeError):
    """Raised when a Unix-domain peer cannot be authenticated safely."""


class ServiceConfigurationError(RuntimeError):
    """Raised when the local connector service is not safely configured."""


@dataclass(frozen=True)
class PeerCredentials:
    """Effective macOS credentials captured when a peer connects."""

    uid: int
    gids: FrozenSet[int]


@dataclass(frozen=True)
class ConnectorServiceConfig:
    """Trusted server-side configuration; clients cannot override these values."""

    db_path: Path
    allowed_action_ids: FrozenSet[str]
    approved_uid: int
    approved_gid: int
    keychain_service: str = DEFAULT_SERVICE
    keychain_account: str = DEFAULT_ACCOUNT
    request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS


def _parse_darwin_peer_credentials(raw: bytes) -> PeerCredentials:
    """Decode Darwin's documented ``struct xucred`` representation."""
    if len(raw) != _XUCRED.size:
        raise PeerAuthenticationError("Peer credentials had an unexpected size.")

    version, uid, group_count, *groups = _XUCRED.unpack(raw)
    if version != 0 or group_count < 0 or group_count > len(groups):
        raise PeerAuthenticationError("Peer credentials were invalid.")

    return PeerCredentials(uid=uid, gids=frozenset(groups[:group_count]))


def get_peer_credentials(connection: socket.socket) -> PeerCredentials:
    """Return Darwin peer credentials or fail closed on unsupported platforms."""
    if sys.platform != "darwin" or not hasattr(socket, "LOCAL_PEERCRED"):
        raise PeerAuthenticationError("Peer credentials are unavailable.")

    try:
        raw = connection.getsockopt(
            _SOL_LOCAL,
            socket.LOCAL_PEERCRED,
            _XUCRED.size,
        )
    except OSError as exc:
        raise PeerAuthenticationError("Could not obtain peer credentials.") from exc

    return _parse_darwin_peer_credentials(raw)


def _validate_config(config: ConnectorServiceConfig) -> None:
    if not isinstance(config.allowed_action_ids, frozenset):
        raise ServiceConfigurationError("Authorization policy must be immutable.")
    if not config.allowed_action_ids:
        raise ServiceConfigurationError("Authorization policy is empty.")
    if any(
        not isinstance(action_id, str)
        or not action_id.strip()
        or action_id != action_id.strip()
        or len(action_id) > 200
        for action_id in config.allowed_action_ids
    ):
        raise ServiceConfigurationError("Authorization policy is invalid.")
    if (
        not isinstance(config.approved_uid, int)
        or isinstance(config.approved_uid, bool)
        or not isinstance(config.approved_gid, int)
        or isinstance(config.approved_gid, bool)
        or config.approved_uid < 0
        or config.approved_gid < 0
    ):
        raise ServiceConfigurationError("Approved peer identity is invalid.")
    if (
        not isinstance(config.request_timeout_seconds, (int, float))
        or isinstance(config.request_timeout_seconds, bool)
        or not math.isfinite(config.request_timeout_seconds)
        or config.request_timeout_seconds <= 0
    ):
        raise ServiceConfigurationError("Request timeout must be a positive duration.")


def _ensure_service_directory(directory: Path) -> None:
    try:
        details = os.lstat(directory)
    except FileNotFoundError:
        directory.mkdir(mode=0o700)
        details = os.lstat(directory)

    if (
        not stat.S_ISDIR(details.st_mode)
        or stat.S_ISLNK(details.st_mode)
        or details.st_uid != os.geteuid()
        or details.st_mode & 0o077
    ):
        raise ServiceConfigurationError(
            "Socket directory must be service-owned and mode 0700."
        )

    os.chmod(directory, 0o700)


def _remove_stale_socket(socket_path: Path) -> None:
    try:
        details = os.lstat(socket_path)
    except FileNotFoundError:
        return

    if not stat.S_ISSOCK(details.st_mode) or details.st_uid != os.geteuid():
        raise ServiceConfigurationError(
            "Refusing to replace a non-service socket path."
        )

    socket_path.unlink()


def create_unix_server(socket_path: str | Path) -> socket.socket:
    """Create a service-owned Unix socket without replacing arbitrary files."""
    path = Path(socket_path)
    _ensure_service_directory(path.parent)
    _remove_stale_socket(path)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(path))
        os.chmod(path, 0o600)
        server.listen()
    except BaseException:
        server.close()
        raise
    return server


def _read_request(connection: socket.socket) -> bytes:
    request = bytearray()
    while len(request) <= MAX_REQUEST_BYTES:
        chunk = connection.recv(MAX_REQUEST_BYTES + 1 - len(request))
        if not chunk:
            break
        request.extend(chunk)
        if b"\n" in chunk:
            break

    if not request:
        raise ValueError("Request is empty")
    if len(request) > MAX_REQUEST_BYTES:
        raise ValueError("Request exceeds the size limit")
    if b"\n" in request:
        line, trailing = bytes(request).split(b"\n", 1)
        if trailing:
            raise ValueError("Request must contain one JSON object")
        return line
    return bytes(request)


def _validate_request(
    request_bytes: bytes,
    config: ConnectorServiceConfig,
) -> str:
    try:
        request = json.loads(request_bytes)
    except json.JSONDecodeError as exc:
        raise ValueError("Request contains invalid JSON.") from exc

    if not isinstance(request, dict):
        raise ValueError("Request must be a JSON object")
    if set(request) != {"action_id"}:
        raise ValueError("Request must contain only the action_id field")

    action_id = request.get("action_id")
    if (
        not isinstance(action_id, str)
        or not action_id
        or action_id != action_id.strip()
        or len(action_id) > 200
    ):
        raise ValueError(
            "action_id must be a non-empty string of at most 200 characters"
        )
    if action_id not in config.allowed_action_ids:
        raise PermissionError("Request is not authorized for this action.")
    return action_id


def _send(connection: socket.socket, payload: dict[str, object]) -> None:
    connection.sendall(json.dumps(payload).encode("utf-8") + b"\n")


def _send_error(connection: socket.socket, message: str) -> None:
    """Best-effort error response for a peer that may have already disconnected."""
    try:
        _send(connection, {"error": message})
    except OSError:
        pass


def handle_connection(
    connection: socket.socket,
    config: ConnectorServiceConfig,
    *,
    peer_credential_loader: Callable[[socket.socket], PeerCredentials] = get_peer_credentials,
    key_loader: Callable[..., bytes] = load_key,
) -> None:
    """Authenticate a peer before reading, parsing, or signing its request."""
    try:
        credentials = peer_credential_loader(connection)
        if (
            credentials.uid != config.approved_uid
            or config.approved_gid not in credentials.gids
        ):
            raise PeerAuthenticationError("Peer is not authorized.")
    except Exception:
        _send_error(connection, "Peer authentication failed.")
        return

    try:
        connection.settimeout(config.request_timeout_seconds)
        action_id = _validate_request(_read_request(connection), config)
    except socket.timeout:
        _send_error(connection, "Request timed out.")
        return
    except PermissionError:
        _send_error(connection, "Request is not authorized for this action.")
        return
    except ValueError as exc:
        _send_error(connection, str(exc))
        return
    except (TypeError, OSError):
        _send_error(connection, "Request could not be processed.")
        return

    try:
        secret_key = key_loader(
            service=config.keychain_service,
            account=config.keychain_account,
        )
    except Exception:
        _send_error(connection, "Could not load signing key from Keychain.")
        return

    try:
        envelope = read_and_sign_booking(
            config.db_path,
            action_id,
            secret_key,
            allowed_action_ids=config.allowed_action_ids,
        )
    except (OSError, sqlite3.Error, ValueError, TypeError):
        _send_error(connection, "Could not read booking evidence.")
        return

    _send(connection, {"found": envelope is not None, "envelope": envelope})


def serve_once(
    socket_path: str | Path,
    config: ConnectorServiceConfig,
    *,
    peer_credential_loader: Callable[[socket.socket], PeerCredentials] = get_peer_credentials,
    key_loader: Callable[..., bytes] = load_key,
) -> None:
    """Serve one authenticated request; intended for controlled integration use."""
    _validate_config(config)
    server = create_unix_server(socket_path)
    try:
        connection, _ = server.accept()
        with connection:
            handle_connection(
                connection,
                config,
                peer_credential_loader=peer_credential_loader,
                key_loader=key_loader,
            )
    finally:
        server.close()
        _remove_stale_socket(Path(socket_path))


def serve_forever(socket_path: str | Path, config: ConnectorServiceConfig) -> None:
    """Run the authenticated local service until interrupted by its supervisor."""
    _validate_config(config)
    server = create_unix_server(socket_path)
    try:
        while True:
            connection, _ = server.accept()
            with connection:
                handle_connection(connection, config)
    finally:
        server.close()
        _remove_stale_socket(Path(socket_path))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the authenticated AgentGuard local connector service."
    )
    parser.add_argument("--socket", required=True, type=Path)
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--allow-action", action="append", required=True)
    parser.add_argument("--approved-uid", required=True, type=int)
    parser.add_argument("--approved-gid", required=True, type=int)
    parser.add_argument("--keychain-service", default=DEFAULT_SERVICE)
    parser.add_argument("--keychain-account", default=DEFAULT_ACCOUNT)
    args = parser.parse_args()

    config = ConnectorServiceConfig(
        db_path=args.db,
        allowed_action_ids=frozenset(args.allow_action),
        approved_uid=args.approved_uid,
        approved_gid=args.approved_gid,
        keychain_service=args.keychain_service,
        keychain_account=args.keychain_account,
    )
    try:
        serve_forever(args.socket, config)
    except (OSError, ServiceConfigurationError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
