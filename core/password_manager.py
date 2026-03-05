# Copyright (C) 2026 Nikita Shkunnikov
# Licensed under GNU GPL v3, see <https://www.gnu.org>


import hmac
import time
from dataclasses import dataclass
from typing import Optional

from database.db import DBManager
from security.crypto_manager import CryptoManager


@dataclass
class PasswordEntry:
    id: Optional[int]
    title: bytes
    password_encrypted: bytes
    notes_encrypted: Optional[bytes] = None


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

            time.sleep(0.5)

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

        password_token = self.crypto.encrypt(password_plain, self.derived_key)
        title_token = self.crypto.encrypt(title, self.derived_key)
        notes_token = self.crypto.encrypt(notes, self.derived_key) if notes else None

        with self._get_db() as db:
            entry_id = db.add_entry(title_token, password_token, notes_token)

        return entry_id

    def list_passwords(self, decrypt_title=False):
        if not self.derived_key:
            raise RuntimeError("Мастер-пароль не подтвержден.")

        with self._get_db() as db:
            raw_entries = db.get_entries()

        result = []
        for r in raw_entries:
            result.append(PasswordEntry(
                id=r["id"],
                title=self.crypto.decrypt(r["title"], self.derived_key) if decrypt_title else r["title"],
                password_encrypted=r["password"],
                notes_encrypted=r["notes"]
            ))
        return result

    def get_password_and_notes_plain(self, entry_id: int):
        if not self.derived_key:
            raise RuntimeError("Мастер-пароль не подтвержден.")

        with self._get_db() as db:
            r = db.get_entry(entry_id)

        if not r:
            return None

        entry = PasswordEntry(id=r["id"], title=r["title"],
                              password_encrypted=r["password"], notes_encrypted=r["notes"])

        return self.crypto.decrypt(entry.password_encrypted, self.derived_key), self.crypto.decrypt(
            entry.notes_encrypted, self.derived_key) if entry.notes_encrypted else None

    def delete_password(self, entry_id: int):
        if not self.derived_key:
            raise RuntimeError("Мастер-пароль не подтвержден.")
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

            entries = self.list_passwords()
            new_entries = []

            for en in entries:
                decrypt_title = self.crypto.decrypt(en.title, self.derived_key)
                decrypt_pass = self.crypto.decrypt(en.password_encrypted, self.derived_key)
                decrypt_notes = self.crypto.decrypt(en.notes_encrypted,
                                                    self.derived_key) if en.notes_encrypted else None

                new_entries.append(PasswordEntry(
                    id=en.id,
                    title=self.crypto.encrypt(decrypt_title, derived_key_new),
                    password_encrypted=self.crypto.encrypt(decrypt_pass, derived_key_new),
                    notes_encrypted=self.crypto.encrypt(decrypt_notes, derived_key_new) if decrypt_notes else None
                ))

            with self._get_db() as db:
                result = db.overwriting_data(salt_mp_new, salt_dk_new, master_hash_new, new_entries)

            self.salt_mp = salt_mp_new
            self.salt_dk = salt_dk_new
            self.derived_key = derived_key_new
            return result

        except Exception as e:
            raise RuntimeError(f"Ошибка при смене мастер-пароля: {e}") from e
