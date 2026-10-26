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

    def test_delete_key_reports_security_tool_failure(self):
        completed = subprocess.CompletedProcess([], 1, "", "denied")

        with patch(
            "agentguard.keychain_store.subprocess.run",
            return_value=completed,
        ):
            with self.assertRaisesRegex(RuntimeError, "denied"):
                delete_key(service="test-service", account="test-account")


if __name__ == "__main__":
    unittest.main()
