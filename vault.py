# vault.py

import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

def derive_key(master_password: bytes, salt: bytes) -> bytes:
    """
    Derive a 32‐byte URL‐safe base64 key from master_password + salt.
    Returns the Fernet key (bytes).
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390_000,
    )
    raw_key = kdf.derive(master_password)
    return base64.urlsafe_b64encode(raw_key)


def encrypt_entry(key: bytes, plaintext: str) -> str:
    """
    Encrypt a service password (plaintext) using Fernet(key).
    Returns the token as a str.
    """
    f = Fernet(key)
    token = f.encrypt(plaintext.encode())
    return token.decode()


def decrypt_entry(key: bytes, token_str: str) -> str:
    """
    Decrypt a Fernet token_str back to plaintext.
    """
    f = Fernet(key)
    return f.decrypt(token_str.encode()).decode()
