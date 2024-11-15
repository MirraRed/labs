import ttkbootstrap as ttk
from tkinter import messagebox


# Updating text
def update_result_text(text, text_box):
    text_box['state'] = 'normal'     # Тимчасово встановлюємо стан 'normal'
    text_box.delete(1.0, ttk.END)    # Очищаємо попередній вміст
    text_box.insert(ttk.END, text)    # Вставляємо новий текст
    text_box['state'] = 'disabled'   # Встановлюємо стан 'disabled' назад


# Clear right frame for other labs
def clear_right_frame(right_frame):
    for widget in right_frame.winfo_children():
        widget.destroy()


def validate_password(password):
    """Перевіряє, чи пароль має більше 8 символів."""
    if len(password) < 8:
        messagebox.showwarning("Warning", "Пароль повинен містити більше 8 символів!")
        return False
    return True


def toggle_password_visibility(password_entry, toggle_button):
    """Переключає видимість пароля."""
    if password_entry.cget('show') == '*':
        password_entry.config(show='')  # Показати пароль
        toggle_button.config(text='Сховати пароль')  # Змінити текст кнопки
    else:
        password_entry.config(show='*')  # Сховати пароль
        toggle_button.config(text='Показати пароль')  # Змінити текст кнопки


def clear_text(input_text_box, output_text_box):
    input_text_box.delete(1.0, ttk.END)  # Очищає весь текст з текстового поля
    output_text_box.config(state='normal')  # Змінюємо стан на 'normal'
    output_text_box.delete(1.0, ttk.END)  # Очищаємо весь текст
    output_text_box.config(state='disabled')  # Змінюємо стан назад на 'disabled'


def copy_text_from_output(window, output_text_box):
    result_text = output_text_box.get("1.0", "end-1c")  # Отримуємо текст без символа нового рядка в кінці
    if result_text:
        window.clipboard_clear()  # Очищуємо буфер обміну
        window.clipboard_append(result_text)  # Додаємо текст у буфер обміну
        window.update()  # Оновлюємо буфер обміну, щоб зміни вступили в силу
        messagebox.showinfo("Копіювання", "Текст скопійовано у буфер обміну!")
