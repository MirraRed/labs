import ttkbootstrap as ttk
from tkinter import messagebox
from labs.lab_4 import RSAEncryption
from interface.gui_helpers import update_result_text
import threading
import base64


# Функція для шифрування тексту (в окремому потоці)
def threaded_encrypt_text(input_text_box, output_text_box):
    plaintext = input_text_box.get("1.0", ttk.END)  # Отримуємо текст з вхідного текстового поля
    if plaintext.endswith('\n'):
        plaintext = plaintext[:-1]  # Обрізаємо символ нового рядка

    rsa = RSAEncryption()
    rsa.generate_keys()
    rsa.save_keys("private_text.pem", "public_text.pem")
    _, public_key_obj = rsa.load_keys("private_text.pem", "public_text.pem")

    try:
        encrypted_text_b64 = base64.b64encode(rsa.encrypt(plaintext, public_key_obj)).decode('utf-8')
        update_result_text(encrypted_text_b64, output_text_box)  # Оновлюємо результат в текстовому полі
    except Exception as e:
        messagebox.showerror("Error", f"Помилка під час шифрування: {str(e)}")

# Функція для дешифрування тексту (в окремому потоці)
def threaded_decrypt_text(decrypt_input_text_box, decrypted_output_text_box):
    encrypted_text_b64 = decrypt_input_text_box.get("1.0", ttk.END)  # Отримуємо зашифрований текст
    if encrypted_text_b64.endswith('\n'):
        encrypted_text_b64 = encrypted_text_b64[:-1]  # Обрізаємо символ нового рядка

    try:
        # Декодуємо Base64
        encrypted_message = base64.b64decode(encrypted_text_b64)
    except Exception as e:
        messagebox.showerror("Помилка", "Некоректний формат зашифрованого тексту.")
        return

    rsa = RSAEncryption()
    private_key_obj, _ = rsa.load_keys("private_text.pem", "public_text.pem")

    try:
        # Перевірка на використання гібридного шифрування
        if isinstance(encrypted_message, dict):
            decrypted_message = rsa.hybrid_decrypt_message(encrypted_message, private_key_obj)
        else:
            decrypted_message = rsa.decrypt_message(encrypted_message, private_key_obj)
        update_result_text(decrypted_message, decrypted_output_text_box)  # Оновлюємо результат
    except Exception as e:
        messagebox.showerror("Error", f"Помилка під час дешифрування: {str(e)}")

# Кнопка для шифрування тексту
def encrypt_text_rsa(input_text_box, output_text_box):
    thread = threading.Thread(target=threaded_encrypt_text, args=(input_text_box, output_text_box))
    thread.start()

# Кнопка для дешифрування тексту
def decrypt_text_rsa(decrypt_input_text_box, decrypted_output_text_box):
    thread = threading.Thread(target=threaded_decrypt_text, args=(decrypt_input_text_box, decrypted_output_text_box))
    thread.start()
