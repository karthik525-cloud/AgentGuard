import subprocess
import unittest
from unittest.mock import patch

from agentguard.keychain_store import (
    delete_key,
    load_key,
    store_key,
)


class KeychainStoreTests(unittest.TestCase):
    def test_store_key_uses_security_tool_with_requested_item(self):
        key = b"a" * 32
        completed = subprocess.CompletedProcess([], 0, "", "")

        with patch(
            "agentguard.keychain_store.subprocess.run",
            return_value=completed,
        ) as run:
            store_key(key, service="test-service", account="test-account")

        run.assert_called_once_with(
            [
                "/usr/bin/security",
                "add-generic-password",
                "-U",
                "-a", "test-account",
                "-s", "test-service",
                "-w", key.hex(),
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_load_key_reads_security_tool_output(self):
        key = b"b" * 32
        completed = subprocess.CompletedProcess([], 0, key.hex(), "")

        with patch(
            "agentguard.keychain_store.subprocess.run",
            return_value=completed,
        ) as run:
            loaded = load_key(service="test-service", account="test-account")

        self.assertEqual(loaded, key)
        run.assert_called_once_with(
            [
                "/usr/bin/security",
                "find-generic-password",
                "-a", "test-account",
                "-s", "test-service",
                "-w",
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_load_key_rejects_invalid_or_short_keychain_values(self):
        for output in ("not-hex", (b"c" * 31).hex()):
            with self.subTest(output=output), patch(
                "agentguard.keychain_store.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, output, ""),
            ):
                with self.assertRaises(RuntimeError):
                    load_key()

    def test_keychain_tool_errors_do_not_expose_stderr(self):
        completed = subprocess.CompletedProcess([], 1, "", "sensitive diagnostic")

        for operation, expected_message in (
            (
                lambda: store_key(b"a" * 32, "test-service", "test-account"),
                "Could not store the key in macOS Keychain.",
            ),
            (
                lambda: delete_key("test-service", "test-account"),
                "Could not delete the Keychain item.",
            ),
        ):
            with self.subTest(expected_message=expected_message), patch(
                "agentguard.keychain_store.subprocess.run",
                return_value=completed,
            ):
                with self.assertRaisesRegex(RuntimeError, expected_message) as error:
                    operation()
            self.assertNotIn("sensitive diagnostic", str(error.exception))

    def test_missing_keychain_utility_is_reported_without_os_error_details(self):
        with patch(
            "agentguard.keychain_store.subprocess.run",
            side_effect=FileNotFoundError("sensitive local path"),
        ):
            with self.assertRaisesRegex(RuntimeError, "utility is unavailable") as error:
                load_key()

        self.assertNotIn("sensitive local path", str(error.exception))


if __name__ == "__main__":
    unittest.main()
