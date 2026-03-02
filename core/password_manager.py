# Copyright (C) 2026 Nikita Shkunnikov
# Licensed under GNU GPL v3, see <https://www.gnu.org>


import hmac
from dataclasses import dataclass
from typing import Optional

from database.db import DBManager
from security.crypto_manager import CryptoManager


@dataclass
class PasswordEntry:
    id: Optional[int]
    title: str
    password_encrypted: bytes
    notes: Optional[str] = None


class PasswordManager:
    def __init__(self, db_path: str = "passwords.db"):
        self.crypto = CryptoManager()
        self.db_path = db_path
        self.salt_mp: Optional[bytes] = None
        self.salt_dk: Optional[bytes] = None
        self.derived_key: Optional[bytes] = None

    def _get_db(self):
        return DBManager(db_path=self.db_path)

    def setup_master_password(self, master_password: str):
        with self._get_db() as db:
            if db.is_master_password_set():
                raise RuntimeError("Мастер-пароль уже установлен.")
            salt_mp = self.crypto.generate_salt()
            self.salt_mp = salt_mp
            salt_dk = self.crypto.generate_salt()
            self.salt_dk = salt_dk
            master_hash = self.crypto.hash_master_password(master_password, salt_mp)
            db.set_master_password(salt_mp, salt_dk, master_hash)
            self.derived_key = self.crypto.derive_key(master_password, salt_dk)
        return True

    def verify_master_password(self, master_password: str) -> bool:
        with self._get_db() as db:
            salt_mp, salt_dk, stored_hash = db.get_master_password()
            if salt_mp is None:
                raise RuntimeError("Мастер-пароль не установлен.")
            calc = self.crypto.hash_master_password(master_password, salt_mp)
            if hmac.compare_digest(calc, stored_hash):
                self.salt_mp = salt_mp
                self.salt_dk = salt_dk
                self.derived_key = self.crypto.derive_key(master_password, salt_dk)
                return True
            return False

    def add_password(self, title: str, password_plain: str, notes: Optional[str] = None) -> int:
        if not self.derived_key:
            raise RuntimeError("Мастер-пароль не подтвержден.")

        token = self.crypto.encrypt(password_plain, self.derived_key)

        with self._get_db() as db:
            entry_id = db.add_entry(title, token, notes)

        return entry_id

    def list_passwords(self):
        with self._get_db() as db:
            raw_entries = db.get_entries()

        result = []
        for r in raw_entries:
            result.append(PasswordEntry(
                id=r["id"],
                title=r["title"],
                password_encrypted=r["password"],
                notes=r["notes"]
            ))
        return result

    def get_password_plain(self, entry_id: int):
        if not self.derived_key:
            raise RuntimeError("Мастер-пароль не подтвержден.")

        with self._get_db() as db:
            r = db.get_entry(entry_id)

        if not r:
            return None

        entry = PasswordEntry(id=r["id"], title=r["title"],
                              password_encrypted=r["password"], notes=r["notes"])

        return self.crypto.decrypt(entry.password_encrypted, self.derived_key), entry.notes

    def delete_password(self, entry_id: int):
        with self._get_db() as db:
            db.delete_entry(entry_id)

    def change_master_password(self, master_password: str) -> bool:
        if not self.derived_key:
            raise RuntimeError("Мастер-пароль не подтвержден.")
        try:
            salt_mp_new = self.crypto.generate_salt()
            salt_dk_new = self.crypto.generate_salt()
            master_hash_new = self.crypto.hash_master_password(master_password, salt_mp_new)
            derived_key_new = self.crypto.derive_key(master_password, salt_dk_new)

            dct = {}
            entries = self.list_passwords()
            for en in entries:
                dct[en.id] = self.crypto.encrypt(self.crypto.decrypt(en.password_encrypted, self.derived_key),
                                                 derived_key_new)

            with self._get_db() as db:
                result = db.overwriting_data(salt_mp_new, salt_dk_new, master_hash_new, dct)

            self.salt_mp = salt_mp_new
            self.salt_dk = salt_dk_new
            self.derived_key = derived_key_new
            return result

        except Exception as e:
            raise RuntimeError(f"Ошибка при смене мастер-пароля: {e}") from e
