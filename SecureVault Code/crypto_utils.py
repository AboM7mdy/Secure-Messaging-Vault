import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 200_000
SALT_SIZE = 16
IV_SIZE = 16
KEY_SIZE = 32  # AES-256


class SecureVaultError(Exception):
    pass


class AuthenticationError(SecureVaultError):
    pass


@dataclass
class EncryptedBundle:
    salt_b64: str
    iv_b64: str
    ciphertext_b64: str

    def to_json(self) -> str:
        return json.dumps(
            {
                "algorithm": "AES-256-CBC",
                "kdf": "PBKDF2-HMAC-SHA256",
                "iterations": PBKDF2_ITERATIONS,
                "salt": self.salt_b64,
                "iv": self.iv_b64,
                "ciphertext": self.ciphertext_b64,
            },
            indent=2,
        )

    @staticmethod
    def from_json(data: str) -> "EncryptedBundle":
        payload = json.loads(data)
        return EncryptedBundle(
            salt_b64=payload["salt"],
            iv_b64=payload["iv"],
            ciphertext_b64=payload["ciphertext"],
        )


def derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("Password must not be empty.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def _pkcs7_pad(data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()



def _pkcs7_unpad(data: bytes) -> bytes:
    unpadder = padding.PKCS7(128).unpadder()
    try:
        return unpadder.update(data) + unpadder.finalize()
    except ValueError as exc:
        raise AuthenticationError("Decryption failed. Password is incorrect or the data was modified.") from exc



def encrypt_bytes(data: bytes, password: str) -> EncryptedBundle:
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(_pkcs7_pad(data)) + encryptor.finalize()
    return EncryptedBundle(
        salt_b64=base64.b64encode(salt).decode("ascii"),
        iv_b64=base64.b64encode(iv).decode("ascii"),
        ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
    )



def decrypt_bytes(bundle: EncryptedBundle, password: str) -> bytes:
    salt = base64.b64decode(bundle.salt_b64)
    iv = base64.b64decode(bundle.iv_b64)
    ciphertext = base64.b64decode(bundle.ciphertext_b64)
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
    return _pkcs7_unpad(plaintext_padded)



def encrypt_text(plaintext: str, password: str) -> str:
    bundle = encrypt_bytes(plaintext.encode("utf-8"), password)
    return bundle.to_json()



def decrypt_text(payload: str, password: str) -> str:
    bundle = EncryptedBundle.from_json(payload)
    return decrypt_bytes(bundle, password).decode("utf-8")



def encrypt_file(input_path: str | Path, output_path: str | Path, password: str) -> None:
    input_path = Path(input_path)
    output_path = Path(output_path)
    bundle = encrypt_bytes(input_path.read_bytes(), password)
    payload = {
        "filename": input_path.name,
        "bundle": json.loads(bundle.to_json()),
    }
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")



def decrypt_file(input_path: str | Path, output_dir: str | Path, password: str) -> Path:
    input_path = Path(input_path)
    output_dir = Path(output_dir)
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    bundle = EncryptedBundle(
        salt_b64=payload["bundle"]["salt"],
        iv_b64=payload["bundle"]["iv"],
        ciphertext_b64=payload["bundle"]["ciphertext"],
    )
    data = decrypt_bytes(bundle, password)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / payload["filename"]
    output_file.write_bytes(data)
    return output_file



def tamper_payload(payload: str) -> str:
    data = json.loads(payload)
    raw = bytearray(base64.b64decode(data["ciphertext"]))
    if raw:
        raw[0] ^= 0x01
    data["ciphertext"] = base64.b64encode(bytes(raw)).decode("ascii")
    return json.dumps(data, indent=2)
