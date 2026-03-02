# Copyright (C) 2026 Nikita Shkunnikov
# Licensed under GNU GPL v3, see <https://www.gnu.org>

import base64
import hashlib
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class CryptoManager:
    def __init__(self, iterations: int = 300000):
        self.iterations = iterations
        self.backend = default_backend()

    @staticmethod
    def generate_salt(length: int = 16) -> bytes:
        return os.urandom(length)

    def hash_master_password(self, master_password: str, salt: bytes) -> bytes:
        pw = master_password.encode('utf-8')
        dk = hashlib.pbkdf2_hmac('sha256', pw, salt, self.iterations, dklen=32)
        return dk

    def derive_key(self, master_password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.iterations,
            backend=self.backend
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode('utf-8')))
        return key

    @staticmethod
    def encrypt(plaintext: str, key: bytes) -> bytes:
        f = Fernet(key)
        token = f.encrypt(plaintext.encode('utf-8'))
        return token

    @staticmethod
    def decrypt(token: bytes, key: bytes) -> str:
        f = Fernet(key)
        pt = f.decrypt(token)
        return pt.decode('utf-8')
