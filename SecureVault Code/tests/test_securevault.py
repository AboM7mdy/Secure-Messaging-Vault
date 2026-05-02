import json
import tempfile
import unittest
from pathlib import Path

from crypto_utils import (
    AuthenticationError,
    EncryptedBundle,
    decrypt_bytes,
    decrypt_file,
    decrypt_text,
    derive_key,
    encrypt_bytes,
    encrypt_file,
    encrypt_text,
    tamper_payload,
)


class SecureVaultTests(unittest.TestCase):
    def test_key_derivation_is_stable_for_same_input(self):
        salt = b"1234567890abcdef"
        self.assertEqual(derive_key("Pass123!", salt), derive_key("Pass123!", salt))

    def test_encrypt_decrypt_text_roundtrip(self):
        payload = encrypt_text("CS320 project demo", "Pass123!")
        self.assertEqual(decrypt_text(payload, "Pass123!"), "CS320 project demo")

    def test_wrong_password_fails_for_text(self):
        payload = encrypt_text("Secret", "Correct#1")
        with self.assertRaises(AuthenticationError):
            decrypt_text(payload, "Wrong#1")

    def test_tampered_payload_fails(self):
        payload = encrypt_text("Secret", "Correct#1")
        modified = tamper_payload(payload)
        with self.assertRaises(AuthenticationError):
            decrypt_text(modified, "Correct#1")

    def test_encrypt_decrypt_bytes_roundtrip(self):
        bundle = encrypt_bytes(b"abc123", "Key!234")
        restored = decrypt_bytes(bundle, "Key!234")
        self.assertEqual(restored, b"abc123")

    def test_encrypted_bundle_json_contains_expected_fields(self):
        payload = json.loads(encrypt_text("hello", "Pass123!"))
        self.assertIn("algorithm", payload)
        self.assertIn("salt", payload)
        self.assertIn("iv", payload)
        self.assertIn("ciphertext", payload)

    def test_file_encryption_and_recovery(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            source = tmp / "notes.txt"
            source.write_text("local test file", encoding="utf-8")
            encrypted = tmp / "notes.svault"
            output = tmp / "out"
            encrypt_file(source, encrypted, "Vault#321")
            restored = decrypt_file(encrypted, output, "Vault#321")
            self.assertEqual(restored.read_text(encoding="utf-8"), "local test file")

    def test_file_wrong_password_fails(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            source = tmp / "notes.txt"
            source.write_text("local test file", encoding="utf-8")
            encrypted = tmp / "notes.svault"
            output = tmp / "out"
            encrypt_file(source, encrypted, "Vault#321")
            with self.assertRaises(AuthenticationError):
                decrypt_file(encrypted, output, "WrongPass")

    def test_empty_password_is_rejected(self):
        with self.assertRaises(ValueError):
            encrypt_text("hello", "")

    def test_randomized_payloads_are_different(self):
        first = encrypt_text("same text", "Same#123")
        second = encrypt_text("same text", "Same#123")
        self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main(verbosity=2)
