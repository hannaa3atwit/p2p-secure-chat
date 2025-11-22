import os
import hashlib
from cryptography.fernet import Fernet

KEY_FILE = "secret.key"

# Cache the key in memory so we can reuse it
_CURRENT_KEY: bytes | None = None


def _create_key_file(path: str) -> bytes:
    """
    Generate a new Fernet key and save it to `path`.
    Returns the generated key.
    """
    key = Fernet.generate_key()
    with open(path, "wb") as f:
        f.write(key)
    return key


def _load_key_file(path: str) -> bytes:
    """
    Load an existing Fernet key from `path`.
    """
    with open(path, "rb") as f:
        return f.read()


def _load_or_create_key() -> bytes:
    """
    Load the symmetric key from KEY_FILE if it exists,
    otherwise create a new one. Cache it in _CURRENT_KEY.
    """
    global _CURRENT_KEY

    if _CURRENT_KEY is not None:
        return _CURRENT_KEY

    if os.path.exists(KEY_FILE):
        key = _load_key_file(KEY_FILE)
        print("[+] Loaded existing encryption key.")
    else:
        key = _create_key_file(KEY_FILE)
        print("[+] Created new encryption key and saved to secret.key.")

    _CURRENT_KEY = key
    return key


def load_cipher() -> Fernet:
    """
    Return a Fernet cipher object bound to our symmetric key.
    """
    key = _load_or_create_key()
    return Fernet(key)


def get_key_fingerprint() -> str:
    """
    Return a short fingerprint of the current symmetric key.

    This is similar to how apps show a 'safety code' so users can
    verify they are using the same encryption key.

    We hash the key with SHA-256 and return the first 16 hex chars.
    """
    key = _load_or_create_key()
    h = hashlib.sha256(key).hexdigest()
    return h[:16]


def encrypt_message(cipher: Fernet, text: str) -> bytes:
    """
    Encrypt a UTF-8 string and return the ciphertext bytes.
    """
    data = text.encode("utf-8")
    token = cipher.encrypt(data)
    return token


def decrypt_message(cipher: Fernet, token: bytes) -> str:
    """
    Decrypt ciphertext bytes and return a UTF-8 string.
    """
    data = cipher.decrypt(token)
    return data.decode("utf-8")
