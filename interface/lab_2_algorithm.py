import ttkbootstrap as ttk
from tkinter import messagebox, filedialog
from labs.lab_2 import MD5
from interface.gui_helpers import update_result_text
import os


def load_file(output_text_box):
    file_path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
    if not file_path:
        return  # Якщо файл не обрано, нічого не робимо

    if is_large_file(file_path) and not confirm_large_file():
        return  # Якщо користувач відмовився, виходимо
    handle_file_hashing(file_path, output_text_box)


def is_large_file(file_path, size_limit_mb=10):
    """Перевіряє, чи файл перевищує вказаний розмір."""
    file_size = os.path.getsize(file_path)  # Розмір файлу в байтах
    return file_size > size_limit_mb * 1024 * 1024


def confirm_large_file():
    """Запитує у користувача підтвердження на обробку великого файлу."""
    return messagebox.askyesno(
        "Попередження",
        "Файл перевищує 10 МБ. Хочете хешувати його? Це може зайняти деякий час."
    )


def handle_file_hashing(file_path, output_text_box):
    """Обчислює хеш файлу та оновлює текстове поле."""
    file_hash = hash_file(file_path)
    if file_hash:
        update_result_text(file_hash, output_text_box)
    else:
        messagebox.showerror("Помилка", "Не вдалося згенерувати хеш.")


def hash_file(file_path):
    """Обчислює MD5-хеш файлу."""
    with open(file_path, 'rb') as f:
        file_content = f.read()
        return MD5(file_content)


def check_file_integrity(file_path, hash_file_path):
    # Хешуємо обраний файл
    file_hash = hash_file(file_path)

    # Завантажуємо MD5 хеш з текстового файлу
    try:
        with open(hash_file_path, 'r') as f:
            saved_hash = f.read().strip()  # Отримуємо збережений хеш

        # Порівнюємо хеші
        if file_hash == saved_hash:
            messagebox.showinfo("Перевірка успішна", "Цілісність файлу підтверджено.")
        else:
            messagebox.showerror("Перевірка неуспішна", "Хеші не збігаються. Файл можливо змінено.")
    except FileNotFoundError:
        messagebox.showerror("Помилка", "Файл з хешем не знайдено.")


# Функція для вибору файлу і файлу з хешем та перевірки цілісності
def select_files_and_check_integrity():
    file_path = filedialog.askopenfilename(title="Виберіть файл для перевірки")
    hash_file_path = filedialog.askopenfilename(title="Виберіть файл з MD5 хешем")

    if file_path and hash_file_path:
        check_file_integrity(file_path, hash_file_path)
    else:
        messagebox.showwarning("Попередження", "Будь ласка, оберіть обидва файли.")


# Функція для хешування тексту
def hash_input(input_text_box, output_text_box):
    input_text = input_text_box.get("1.0", ttk.END)
    # Обрізаємо символи нового рядка з кінця
    if input_text.endswith('\n'):
        input_text = input_text[:-1]  # Видалити останній символ, якщо це '\n'
    input_bytes = input_text.encode('utf-8')  # Конвертуємо текст у байти
    hashed_value = MD5(input_bytes)  # Використовуємо вашу функцію хешування
    update_result_text(hashed_value, output_text_box)  # Передаємо output_text_box
