# Copyright (C) 2026 Nikita Shkunnikov
# Licensed under GNU GPL v3, see <https://www.gnu.org>

import string

import flet as ft

from core.password_manager import PasswordManager


class PasswordManagerUI:
    def __init__(self, page: ft.Page, pm: PasswordManager):
        self.page = page
        self.pm = pm

        self._build_icons()
        self._build_fields()
        self._build_layout()

        self.page.add(self.main_layout)

    def _build_icons(self):
        self.master_eye = ft.IconButton(
            icon="visibility_off",
            on_click=self._toggle_master_visibility
        )
        self.password_eye = ft.IconButton(
            icon="visibility_off",
            on_click=self._toggle_password_visibility
        )

    def _build_fields(self):
        self.txt_master = ft.TextField(
            label="Мастер-пароль",
            password=True,
            width=300,
            suffix=self.master_eye
        )

        self.lbl_status = ft.Text("Войдите в личный кабинет или зарегистрируйтесь.")

        self.txt_title = ft.TextField(label="Название", width=250)

        self.txt_password = ft.TextField(
            label="Пароль",
            password=True,
            width=250,
            suffix=self.password_eye
        )

        self.txt_notes = ft.TextField(
            label="Заметки",
            multiline=True,
            width=250,
            min_lines=2
        )

        self.btn_master = ft.ElevatedButton(
            "Вход / Регистрация",
            on_click=self.on_setup_or_verify
        )

        self.lst = ft.Column(scroll="auto", expand=True)

    def _build_layout(self):
        self.main_layout = ft.Column(
            [
                ft.Row([self.txt_master, self.btn_master]),
                self.lbl_status,
                ft.Divider(),

                ft.Text("Добавить запись:", size=18, weight="bold"),
                ft.Row(
                    [
                        self.txt_title,
                        self.txt_password,
                        self.txt_notes,
                        ft.ElevatedButton("Добавить", on_click=self.on_add),
                    ]
                ),

                ft.Divider(),
                ft.Text("Сохраненные записи:", size=18, weight="bold"),
                self.lst,
            ],
            expand=True,
        )

    def set_status(self, msg: str):
        self.lbl_status.value = msg
        self.page.update()

    def _toggle_master_visibility(self, e):
        self._toggle_visibility(self.txt_master, self.master_eye)

    def _toggle_password_visibility(self, e):
        self._toggle_visibility(self.txt_password, self.password_eye)

    def _toggle_visibility(self, field: ft.TextField, eye: ft.IconButton):
        field.password = not field.password
        eye.icon = "visibility_off" if field.password else "visibility"
        self.page.update()

    @staticmethod
    def check_password_complexity(password: str) -> tuple[bool, str]:
        if len(password) < 8:
            return False, "Пароль должен содержать не менее 8 символов."
        if not any(c.isalpha() for c in password):
            return False, "Пароль должен содержать минимум одну букву."
        if not any(c.isdigit() for c in password):
            return False, "Пароль должен содержать минимум одну цифру."
        if not any(c in string.punctuation for c in password):
            return False, "Пароль должен содержать минимум один символ."
        return True, "OK"

    def refresh_list(self):
        self.lst.controls.clear()

        for en in self.pm.list_passwords():
            self.lst.controls.append(
                ft.Row(
                    [
                        ft.Text(en.title, width=200),
                        ft.TextButton("👁 Посмотреть", on_click=lambda e, i=en.id: self.show_password(i)),
                        ft.TextButton("🗑 Удалить", on_click=lambda e, i=en.id: self.on_delete(i)),
                    ],
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                )
            )

        self.page.update()

    def on_setup_or_verify(self, e):
        mp = self.txt_master.value.strip()
        if not mp:
            return self.set_status("Пароль не может быть пустым.")

        try:
            if self.pm.verify_master_password(mp):
                self.btn_master.text = "Изменить"
                self.btn_master.on_click = self.change_master_password
                self.set_status("Доступ разрешён.")
                self.txt_master.value = ""
                self.refresh_list()
                return
            else:
                return self.set_status("Неправильный пароль.")

        except RuntimeError as ex:
            if "не установлен" not in str(ex):
                return self.set_status(f"Ошибка: {ex}")

            ok, msg = self.check_password_complexity(mp)
            if not ok:
                return self.set_status(msg)

            self.pm.setup_master_password(mp)
            self.btn_master.text = "Изменить"
            self.btn_master.on_click = self.change_master_password
            self.set_status("Мастер-пароль создан. Вы в личном кабинете.")
            self.txt_master.value = ""
            self.refresh_list()

    def change_master_password(self, e):
        mp = self.txt_master.value.strip()
        if not mp:
            return self.set_status("Пароль не может быть пустым.")

        ok, msg = self.check_password_complexity(mp)
        if not ok:
            return self.set_status(msg)
        try:
            if self.pm.change_master_password(mp):
                self.txt_master.value = ""
                self.set_status("Мастер-пароль изменён.")
        except RuntimeError as ex:
            self.set_status(f"Ошибка: {ex}")

    def on_add(self, e):
        if not self.pm.derived_key:
            return self.set_status("Сначала введите мастер-пароль.")

        title = self.txt_title.value.strip()
        password = self.txt_password.value.strip()
        notes = self.txt_notes.value.strip()

        if not title or not password:
            return self.set_status("Требуется ввести название и пароль.")

        self.pm.add_password(title, password, notes)

        self.txt_title.value = ""
        self.txt_password.value = ""
        self.txt_notes.value = ""

        self.set_status("Запись добавлена.")
        self.refresh_list()

    def show_password(self, entry_id):
        pwd, note = self.pm.get_password_plain(entry_id)

        dlg = ft.AlertDialog(
            modal=True,
            content=ft.Column(
                [
                    ft.Text("Пароль:", weight=ft.FontWeight.BOLD),
                    ft.Text(pwd, selectable=True),
                    ft.Divider(),
                    ft.Text(note or "Нет заметок", italic=True),
                ],
                tight=True,
            ),
            actions=[ft.TextButton("Скрыть", on_click=lambda e: self._close_dialog(dlg))],
        )

        self.page.overlay.append(dlg)
        dlg.open = True
        self.page.update()

    def _close_dialog(self, dlg):
        dlg.open = False
        self.page.update()
        self.page.overlay.remove(dlg)

    def on_delete(self, entry_id):
        self.pm.delete_password(entry_id)
        self.set_status("Запись удалена.")
        self.refresh_list()
