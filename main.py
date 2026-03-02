# Copyright (C) 2026 Nikita Shkunnikov
# Licensed under GNU GPL v3, see <https://www.gnu.org>

import flet as ft

from core.password_manager import PasswordManager
from ui.password_manager_ui import PasswordManagerUI


def main(page: ft.Page):
    # Задаем параметры страницы:
    page.title = "Password Manager"
    page.padding = 20

    page.window.width = 910
    page.window.height = 700

    page.window.resizable = True

    # Инициализируем менеджер паролей
    pm = PasswordManager(db_path="passwords.db")

    # Инициализируем класс UI, передавая ему страницу и менеджер паролей
    PasswordManagerUI(page, pm)

    # Обновляем страницу
    page.update()


if __name__ == "__main__":
    ft.app(target=main, view=ft.AppView.FLET_APP)

