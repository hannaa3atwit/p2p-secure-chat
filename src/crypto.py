import os
from cryptography.fernet import Fernet

KEY_FILE = "secret.key"


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


def load_cipher() -> Fernet:
    """
    Load an existing symmetric key from KEY_FILE if it exists.
    Otherwise, generate a new key and save it.

    Returns a Fernet cipher object that can be used
    for encryption and decryption.
    """
    if os.path.exists(KEY_FILE):
        key = _load_key_file(KEY_FILE)
        print("[+] Loaded existing encryption key.")
    else:
        key = _create_key_file(KEY_FILE)
        print("[+] Created new encryption key and saved to secret.key.")

    return Fernet(key)


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
