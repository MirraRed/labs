import ttkbootstrap as ttk
from tkinter import filedialog, messagebox
from labs.lab_2 import MD5
from interface.gui_helpers import update_result_text


def save_result_lab_2(input_text_box, output_text_box):
    input_text = input_text_box.get("1.0", ttk.END).strip('\n')  # Отримати текст з текстового поля

    input_bytes = input_text.encode('utf-8')  # Конвертуємо текст у байти
    hashed_value = MD5(input_bytes)  # Використовуємо вашу функцію хешування

    # Формуємо текст для збереження
    output_text = f"Повідомлення:\n{input_text}\n\nХешоване повідомлення:\n{hashed_value}"

    # Відкриваємо діалог для вибору місця збереження файлу
    file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                   filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_path:
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(output_text)  # Записуємо текст у файл

        # Оновлюємо текстове поле для виводу
        update_result_text(output_text, output_text_box)  # Передаємо output_text_box
    else:
        messagebox.showwarning("Попередження", "Файл не збережено.")