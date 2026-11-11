import base64
import os
import stat
import tempfile
import unittest
from pathlib import Path

from datapack.pseudonym import ALGORITHM, Keyring, PseudonymError
from datapack.storage import save_json


class KeyringTests(unittest.TestCase):
    def _write(self, directory, payload):
        path = Path(directory) / "keys.json"
        save_json(path, payload)
        os.chmod(path, 0o600)
        return path

    def test_loads_base64_hex_and_utf8_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            raw = os.urandom(32)
            path = self._write(
                directory,
                {
                    "keys": {
                        "v1": {"algorithm": ALGORITHM, "secret": "base64:" + base64.b64encode(raw).decode()},
                        "v2": {"algorithm": ALGORITHM, "secret": "hex:" + raw.hex()},
                        "v3": {"algorithm": ALGORITHM, "secret": "utf8:" + ("k" * 32)},
                    }
                },
            )
            with Keyring(path) as keyring:
                self.assertEqual(keyring.key_for("v1"), raw)
                self.assertEqual(keyring.key_for("v2"), raw)
                self.assertEqual(keyring.versions(), ["v1", "v2", "v3"])
                with self.assertRaises(PseudonymError) as context:
                    keyring.key_for("v9")
                self.assertEqual(context.exception.code, "KEY_VERSION_UNKNOWN")

    def test_rejects_missing_and_malformed_files(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(PseudonymError) as context:
                Keyring(Path(directory) / "absent.json")
            self.assertEqual(context.exception.code, "KEY_FILE_MISSING")
            path = self._write(directory, {"keys": {}})
            with self.assertRaises(PseudonymError) as context:
                Keyring(path)
            self.assertEqual(context.exception.code, "KEY_FILE_FORMAT")

    def test_rejects_short_keys_and_unknown_algorithm(self):
        with tempfile.TemporaryDirectory() as directory:
            short_path = self._write(
                directory,
                {"keys": {"v1": {"algorithm": ALGORITHM, "secret": "hex:" + "ab" * 8}}},
            )
            with self.assertRaises(PseudonymError) as context:
                Keyring(short_path)
            self.assertEqual(context.exception.code, "KEY_TOO_SHORT")
            bad_path = self._write(
                directory,
                {"keys": {"v1": {"algorithm": "MD5", "secret": "hex:" + "ab" * 32}}},
            )
            with self.assertRaises(PseudonymError) as context:
                Keyring(bad_path)
            self.assertEqual(context.exception.code, "KEY_FILE_FORMAT")

    @unittest.skipUnless(os.name == "posix", "权限位检查仅适用于 POSIX")
    def test_rejects_group_or_world_readable_key_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                {"keys": {"v1": {"algorithm": ALGORITHM, "secret": "hex:" + "ab" * 32}}},
            )
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
            with self.assertRaises(PseudonymError) as context:
                Keyring(path)
            self.assertEqual(context.exception.code, "KEY_FILE_PERMISSIONS")


if __name__ == "__main__":
    unittest.main()
