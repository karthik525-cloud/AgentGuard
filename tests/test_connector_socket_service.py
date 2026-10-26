import json
import os
import socket
import stat
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

from agentguard import record_booking, verify_signed_evidence
from agentguard.connector_service import (
    MAX_REQUEST_BYTES,
    ConnectorServiceConfig,
    PeerAuthenticationError,
    PeerCredentials,
    ServiceConfigurationError,
    _remove_stale_socket,
    create_unix_server,
    get_peer_credentials,
    handle_connection,
    serve_once,
)


class ConnectorSocketServiceTests(unittest.TestCase):
    def setUp(self):
        self.key = b"connector-socket-test-key-at-least-32-bytes"
        self.temp_dir = tempfile.TemporaryDirectory(dir="/tmp")
        self.base_path = Path(self.temp_dir.name)
        self.db_path = self.base_path / "bookings.db"
        record_booking(
            self.db_path,
            "booking-service-1",
            "record-service-1",
            "confirmed",
        )
        self.config = ConnectorServiceConfig(
            db_path=self.db_path,
            allowed_action_ids=frozenset({"booking-service-1"}),
            approved_uid=4242,
            approved_gid=4343,
            keychain_service="AgentGuard.Test.Service",
            keychain_account="agentguard-test-account",
        )
        self.approved_peer = PeerCredentials(
            uid=self.config.approved_uid,
            gids=frozenset({self.config.approved_gid}),
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def require_pathname_socket_support(self):
        probe = self.base_path / "socket-probe"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(probe))
        except PermissionError:
            self.skipTest(
                "This execution environment blocks pathname AF_UNIX socket binding."
            )
        finally:
            listener.close()
            if probe.exists():
                probe.unlink()

    def request(
        self,
        payload,
        *,
        peer_credential_loader=None,
        key_loader=None,
    ):
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        errors = []
        peer_loader = peer_credential_loader or Mock(
            return_value=self.approved_peer
        )
        key_loader = key_loader or Mock(return_value=self.key)

        def serve():
            try:
                handle_connection(
                    server,
                    self.config,
                    peer_credential_loader=peer_loader,
                    key_loader=key_loader,
                )
            except BaseException as exc:
                errors.append(exc)
            finally:
                server.close()

        try:
            if payload is not None:
                client.sendall(payload)
            client.shutdown(socket.SHUT_WR)
            thread = threading.Thread(target=serve)
            thread.start()
            response = client.recv(4096)
        finally:
            client.close()

        thread.join(timeout=2)
        self.assertFalse(thread.is_alive(), "service thread did not finish")
        if errors:
            raise errors[0]
        return json.loads(response.decode("utf-8")), peer_loader, key_loader

    def test_real_darwin_peer_credentials_include_current_identity(self):
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            credentials = get_peer_credentials(server)
        finally:
            server.close()
            client.close()

        self.assertEqual(credentials.uid, os.geteuid())
        self.assertIn(os.getegid(), credentials.gids)

    def test_authorized_peer_receives_signed_evidence_from_fixed_config(self):
        key_loader = Mock(return_value=self.key)
        response, _, _ = self.request(
            b'{"action_id":"booking-service-1"}\n',
            key_loader=key_loader,
        )

        self.assertTrue(response["found"])
        self.assertTrue(verify_signed_evidence(response["envelope"], self.key))
        key_loader.assert_called_once_with(
            service=self.config.keychain_service,
            account=self.config.keychain_account,
        )

    def test_unauthorized_peer_cannot_trigger_key_load_or_signing(self):
        denied_peer = PeerCredentials(uid=9999, gids=frozenset({4343}))
        key_loader = Mock(return_value=self.key)

        with patch("agentguard.connector_service.read_and_sign_booking") as sign:
            response, _, _ = self.request(
                b'{"action_id":"booking-service-1"}\n',
                peer_credential_loader=Mock(return_value=denied_peer),
                key_loader=key_loader,
            )

        self.assertEqual(response, {"error": "Peer authentication failed."})
        key_loader.assert_not_called()
        sign.assert_not_called()

    def test_credential_lookup_failure_is_rejected_before_request_processing(self):
        key_loader = Mock(return_value=self.key)
        peer_loader = Mock(side_effect=PeerAuthenticationError("unavailable"))

        with patch("agentguard.connector_service.read_and_sign_booking") as sign:
            response, _, _ = self.request(
                b'{"action_id":"booking-service-1"}\n',
                peer_credential_loader=peer_loader,
                key_loader=key_loader,
            )

        self.assertEqual(response, {"error": "Peer authentication failed."})
        key_loader.assert_not_called()
        sign.assert_not_called()

    def test_keychain_load_failure_returns_error_without_signing(self):
        key_loader = Mock(side_effect=RuntimeError("denied"))

        with patch("agentguard.connector_service.read_and_sign_booking") as sign:
            response, _, _ = self.request(
                b'{"action_id":"booking-service-1"}\n',
                key_loader=key_loader,
            )

        self.assertEqual(
            response,
            {"error": "Could not load signing key from Keychain."},
        )
        sign.assert_not_called()

    def test_empty_request_is_rejected_without_signing(self):
        with patch("agentguard.connector_service.read_and_sign_booking") as sign:
            response, _, _ = self.request(None)

        self.assertEqual(response, {"error": "Request is empty"})
        sign.assert_not_called()

    def test_empty_or_invalid_server_allowlist_fails_before_socket_creation(self):
        configurations = (
            (frozenset(), "Authorization policy is empty."),
            (frozenset({"   "}), "Authorization policy is invalid."),
        )

        for allowed_action_ids, message in configurations:
            with self.subTest(allowed_action_ids=allowed_action_ids), patch(
                "agentguard.connector_service.create_unix_server"
            ) as create_server:
                config = replace(
                    self.config,
                    allowed_action_ids=allowed_action_ids,
                )

                with self.assertRaisesRegex(ServiceConfigurationError, message):
                    serve_once(self.base_path / "not-used.sock", config)

                create_server.assert_not_called()

    def test_oversized_multibyte_request_is_rejected_by_byte_limit(self):
        payload = "é".encode("utf-8") * 513

        with patch("agentguard.connector_service.read_and_sign_booking") as sign:
            response, _, _ = self.request(payload)

        self.assertEqual(response, {"error": "Request exceeds the size limit"})
        sign.assert_not_called()

    def test_invalid_action_ids_are_rejected_without_signing(self):
        requests = (
            b'{"action_id":"' + b"a" * 201 + b'"}\n',
            b'{"action_id":" booking-service-1 "}\n',
        )

        for payload in requests:
            with self.subTest(payload=payload[:30]), patch(
                "agentguard.connector_service.read_and_sign_booking"
            ) as sign:
                response, _, _ = self.request(payload)

            self.assertEqual(
                response,
                {
                    "error": (
                        "action_id must be a non-empty string of at most 200 "
                        "characters"
                    )
                },
            )
            sign.assert_not_called()

    def test_valid_request_without_trailing_newline_is_accepted(self):
        response, _, _ = self.request(
            b'{"action_id":"booking-service-1"}'
        )

        self.assertTrue(response["found"])
        self.assertTrue(verify_signed_evidence(response["envelope"], self.key))

    def test_malformed_and_oversized_requests_are_rejected(self):
        requests = (
            (b"{not-json}\n", "Request contains invalid JSON."),
            (b'["booking-service-1"]\n', "Request must be a JSON object"),
            (
                b'{"action_id":"booking-service-1","db_path":"other"}\n',
                "Request must contain only the action_id field",
            ),
            (b"x" * (MAX_REQUEST_BYTES + 1), "Request exceeds the size limit"),
        )

        for payload, message in requests:
            with self.subTest(payload=payload[:20]):
                with patch("agentguard.connector_service.read_and_sign_booking") as sign:
                    response, _, _ = self.request(payload)
                self.assertEqual(response, {"error": message})
                sign.assert_not_called()

    def test_client_cannot_select_server_configuration(self):
        payload = json.dumps({
            "action_id": "booking-service-1",
            "db_path": "/untrusted.db",
            "keychain_service": "untrusted",
            "allowed_action_ids": ["other-action"],
        }).encode("utf-8")

        with patch("agentguard.connector_service.read_and_sign_booking") as sign:
            response, _, _ = self.request(payload)

        self.assertEqual(
            response,
            {"error": "Request must contain only the action_id field"},
        )
        sign.assert_not_called()

    def test_action_allowlist_is_enforced_server_side(self):
        with patch("agentguard.connector_service.read_and_sign_booking") as sign:
            response, _, _ = self.request(
                b'{"action_id":"booking-not-allowed"}\n'
            )

        self.assertEqual(
            response,
            {"error": "Request is not authorized for this action."},
        )
        sign.assert_not_called()

    def test_service_socket_and_directory_permissions_are_restrictive(self):
        self.require_pathname_socket_support()
        socket_path = self.base_path / "service" / "connector.sock"
        server = create_unix_server(socket_path)
        try:
            self.assertEqual(stat.S_IMODE(socket_path.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(socket_path.stat().st_mode), 0o600)
        finally:
            server.close()
            _remove_stale_socket(socket_path)

    def test_stale_regular_file_is_not_deleted_or_replaced(self):
        directory = self.base_path / "service"
        directory.mkdir(mode=0o700)
        socket_path = directory / "connector.sock"
        socket_path.write_text("do not remove", encoding="utf-8")

        with self.assertRaises(ServiceConfigurationError):
            create_unix_server(socket_path)

        self.assertTrue(socket_path.is_file())
        self.assertEqual(socket_path.read_text(encoding="utf-8"), "do not remove")

    def test_serve_once_accepts_authenticated_socket_client(self):
        self.require_pathname_socket_support()
        socket_path = self.base_path / "service" / "connector.sock"
        errors = []

        def serve():
            try:
                serve_once(
                    socket_path,
                    self.config,
                    peer_credential_loader=Mock(return_value=self.approved_peer),
                    key_loader=Mock(return_value=self.key),
                )
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=serve)
        thread.start()
        for _ in range(100):
            if socket_path.exists():
                break
            time.sleep(0.01)
        self.assertTrue(socket_path.exists(), "service socket was not created")

        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.connect(str(socket_path))
            client.sendall(b'{"action_id":"booking-service-1"}\n')
            client.shutdown(socket.SHUT_WR)
            response = json.loads(client.recv(4096).decode("utf-8"))
        finally:
            client.close()

        thread.join(timeout=2)
        self.assertFalse(thread.is_alive(), "service thread did not finish")
        self.assertFalse(errors)
        self.assertTrue(response["found"])
        self.assertTrue(verify_signed_evidence(response["envelope"], self.key))
        self.assertFalse(socket_path.exists(), "stale socket path was not removed")


if __name__ == "__main__":
    unittest.main()
