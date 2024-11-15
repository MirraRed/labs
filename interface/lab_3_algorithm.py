import ttkbootstrap as ttk
from tkinter import messagebox
from labs.lab_3 import RC5
from interface.gui_helpers import update_result_text, validate_password
import threading
import base64


# Функція для шифрування тексту в фоновому потоці
def encrypt_text(input_text_box, password_entry, window, output_text_box):
    # Запускаємо новий потік для шифрування
    threading.Thread(target=_encrypt_text_background, args=(input_text_box, password_entry, window, output_text_box)).start()

def _encrypt_text_background(input_text_box, password_entry, window, output_text_box):
    plaintext = input_text_box.get("1.0", ttk.END).strip()  # Отримуємо та обрізаємо текст
    password = password_entry.get().strip()  # Отримуємо пароль
    if not validate_password(password):
        return
    if not plaintext or not password:
        messagebox.showerror("Error", "Будь ласка, введіть текст та пароль.")
        return

    # Створення об'єкта RC5
    rc5 = RC5(password)
    encrypted_text = rc5.rc5_encrypt(plaintext.encode('utf-8'))
    encrypted_text_b64 = base64.b64encode(encrypted_text).decode('utf-8')

    # Оновлення результату на головному потоці
    window.after(0, lambda: update_result_text(encrypted_text_b64, output_text_box))

# Функція для дешифрування тексту в фоновому потоці
def decrypt_text(decrypt_input_text_box, password_entry, window, decrypted_output_text_box):
    # Запускаємо новий потік для дешифрування
    threading.Thread(target=_decrypt_text_background, args=(decrypt_input_text_box, password_entry, window, decrypted_output_text_box)).start()

def _decrypt_text_background(decrypt_input_text_box, password_entry, window, decrypted_output_text_box):
    encrypted_text_b64 = decrypt_input_text_box.get("1.0", ttk.END).strip()
    password = password_entry.get().strip()  # Отримуємо пароль
    if not validate_password(password):
        return
    if not encrypted_text_b64 or not password:
        messagebox.showerror("Error", "Будь ласка, введіть зашифрований текст та пароль.")
        return

    try:
        encrypted_text = base64.b64decode(encrypted_text_b64)
    except Exception:
        messagebox.showerror("Error", "Некоректний формат зашифрованого тексту.")
        return

    # Створення об'єкта RC5 для дешифрування
    rc5 = RC5(password)
    decrypted_text = rc5.rc5_decrypt(encrypted_text).decode('utf-8')

    # Оновлення результату на головному потоці
    window.after(0, lambda: update_result_text(decrypted_text, decrypted_output_text_box))

