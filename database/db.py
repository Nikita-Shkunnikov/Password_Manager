# Copyright (C) 2026 Nikita Shkunnikov
# Licensed under GNU GPL v3, see <https://www.gnu.org>

import sqlite3
from typing import Optional, List, Dict, Any


class DBManager:
    def __init__(self, db_path: str = "passwords.db"):
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None
        self._connect()
        self._create_tables()

    def _connect(self):
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute('PRAGMA foreign_keys=ON')
        except sqlite3.Error as e:
            print(f"Ошибка подключения к базе данных: {e}")
            raise

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        if self.conn:
            self.conn.commit()
            self.conn.close()
            self.conn = None

    def _execute(self, sql: str, parameters: tuple = (), commit: bool = False, fetchone: bool = False,
                 fetchall: bool = False) -> Any:
        if not self.conn:
            raise RuntimeError("Соединение с базой данных не активно.")

        cursor = self.conn.cursor()
        try:
            cursor.execute(sql, parameters)
            if commit:
                self.conn.commit()
            if fetchone:
                return cursor.fetchone()
            if fetchall:
                return cursor.fetchall()
            return cursor.lastrowid if commit else None
        except sqlite3.Error as e:
            print(f"Ошибка выполнения SQL-запроса: {e}")
            self.conn.rollback()  # Откатываем транзакцию при ошибке
            raise

    def _create_tables(self):
        self._execute('''
            CREATE TABLE IF NOT EXISTS master_password (
                id INTEGER PRIMARY KEY,
                salt_mp BLOB NOT NULL,
                salt_dk BLOB NOT NULL,
                master_hash BLOB NOT NULL
            );
        ''', commit=True)

        self._execute('''
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title BLOB NOT NULL,
                password BLOB NOT NULL,
                notes BLOB
            );
        ''', commit=True)

    def is_master_password_set(self) -> bool:
        row = self._execute("SELECT COUNT(*) as cnt FROM master_password;", fetchone=True)
        return row["cnt"] > 0

    def set_master_password(self, salt_mp: bytes, salt_dk: bytes, master_hash: bytes):
        self._execute("DELETE FROM master_password;", commit=True)
        self._execute(
            "INSERT INTO master_password (salt_mp, salt_dk, master_hash) VALUES (?, ?, ?);",
            (salt_mp, salt_dk, master_hash),
            commit=True
        )

    def get_master_password(self) -> tuple[Optional[bytes], Optional[bytes], Optional[bytes]]:
        row = self._execute("SELECT salt_mp, salt_dk, master_hash FROM master_password LIMIT 1;", fetchone=True)
        if row:
            return row["salt_mp"], row["salt_dk"], row["master_hash"]
        return None, None, None

    def add_entry(self, title: bytes, password_encrypted: bytes, notes: Optional[bytes] = None) -> int:
        last_id = self._execute(
            "INSERT INTO entries (title, password, notes) VALUES (?, ?, ?);",
            (title, password_encrypted, notes),
            commit=True
        )
        return last_id

    def get_entries(self) -> List[Dict[str, Any]]:
        rows = self._execute("SELECT id, title, password, notes FROM entries ORDER BY id DESC;",
                             fetchall=True)
        return [dict(row) for row in rows]

    def get_entry(self, entry_id: int) -> Optional[Dict[str, Any]]:
        r = self._execute("SELECT id, title, password, notes FROM entries WHERE id = ?;", (entry_id,),
                          fetchone=True)
        if r:
            return dict(r)
        return None

    def delete_entry(self, entry_id: int):
        self._execute("DELETE FROM entries WHERE id = ?;", (entry_id,), commit=True)

    def overwriting_data(self, new_salt_mp: bytes, new_salt_dk: bytes, new_master_hash: bytes, new_entries: list):
        conn = self.conn
        cursor = conn.cursor()

        try:
            with conn:

                cursor.execute("DROP TABLE IF EXISTS entries_new")

                cursor.execute("""
                    CREATE TABLE entries_new (
                        id INTEGER PRIMARY KEY,
                        title BLOB NOT NULL,
                        password BLOB NOT NULL,
                        notes BLOB
                    )
                """)

                for entry in new_entries:
                    cursor.execute("""
                        INSERT INTO entries_new (id, title, password, notes)
                        VALUES (?, ?, ?, ?)
                    """, (
                        entry.id,
                        entry.title,
                        entry.password_encrypted,
                        entry.notes_encrypted
                    ))

                cursor.execute("SELECT COUNT(*) FROM entries")
                old_count = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM entries_new")
                new_count = cursor.fetchone()[0]

                if old_count != new_count:
                    raise RuntimeError("Не все записи были перешифрованы")

                cursor.execute("ALTER TABLE entries RENAME TO entries_old")
                cursor.execute("ALTER TABLE entries_new RENAME TO entries")
                cursor.execute("DROP TABLE entries_old")

                cursor.execute("""
                    UPDATE master_password
                    SET salt_mp = ?, salt_dk = ?, master_hash = ?
                """, (new_salt_mp, new_salt_dk, new_master_hash))
                if cursor.rowcount == 0:
                    raise RuntimeError("Запись мастер-пароля не найдена в базе!")

            return True

        except Exception as e:
            print(f"Ошибка при перезаписи данных: {e}")
            raise
