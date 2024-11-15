import ttkbootstrap as ttk
from tkinter import messagebox, filedialog
from labs.lab_1 import LinearCongruentialGenerator
from labs.lab_3 import RC5
from labs.lab_4 import RSAEncryption
from labs.lab_5 import DSAEncryption
from interface.lab_2_algorithm import load_file, select_files_and_check_integrity, hash_input
from interface.lab_3_algorithm import encrypt_text, decrypt_text
from interface.lab_4_algorithm import encrypt_text_rsa, decrypt_text_rsa
from interface.file_operations import save_result_lab_2
from interface.gui_helpers import (update_result_text, clear_right_frame, copy_text_from_output, clear_text,
                                   toggle_password_visibility, validate_password)
import threading
import os

CLEAR_INPUT = "Очистити вхідний текст"
TEXT_ENCR = "Текст для шифрування:"
FILE_PATH = "Шлях до файлу:"
SELECT_FILE = "Обрати файл"
COPY_TEXT = "Скопіювати текст"
SAVE_RESULTS = "Зберегти результат"
PUBLIC_KEY_RSA = "public_key_dsa.pem"
PRIVATE_KEY_RSA = "private_key_dsa.pem"
PUBLIC_KEY_DSA = "private_file.pem"
PRIVATE_KEY_DSA = "public_file.pem"


# window - solar, journal, cyborg, superhero, morph, cerculean, darkly
window = ttk.Window(themename='journal')
window.title('Лабораторні')
window.geometry('1200x850')
window.minsize(1200, 850)

# icon
window.iconbitmap('C:/Users/Kate/PycharmProjects/zahist_informacii/lab_1/icon/favicon.ico')

results = []
valid_data = False

# Adjust wrap length only if welcome_label exists
def adjust_wrap(event):
    try:
        new_width = event.width  # Отримуємо нову ширину вікна
        if welcome_label.winfo_exists():
            welcome_label['wraplength'] = new_width - 20
    except NameError:
        pass  # Ігноруємо помилку, якщо welcome_label ще не визначено

def window_bind():
    window.bind('<Configure>', adjust_wrap)


# Лабораторна 1 (LCG)
def show_lab_1():
    # Welcome label
    global welcome_label
    global results, valid_data

    clear_right_frame(right_frame)

    window_bind()  # Прив'язуємо функцію до події зміни розміру


    welcome_label = ttk.Label(right_frame,
                              text='Вітаю! Це генератор випадкових чисел!',
                              font=('Calibry', 16))
    welcome_label.pack(pady=10)

    # Input label
    input_label = ttk.Label(right_frame,
                            text="Введіть кількість результатів:")
    input_label.pack()

    # Input spinbox
    global spinbox
    spinbox = ttk.Spinbox(right_frame, from_=1, to=999, increment=1)
    spinbox.pack(pady=5)

    # Generative button
    generate_btn = ttk.Button(right_frame,
                              text="Згенерувати",
                              command=lambda: generate_numbers())
    generate_btn.pack(pady=10)

    # Text frame
    global result_text
    text_frame = ttk.Frame(right_frame)
    text_frame.pack(expand=True, fill='both', pady=20)

    # Result text
    result_text = ttk.Text(text_frame, wrap='word',
                          height=10, state='disabled')
    result_text.pack(side=ttk.LEFT, expand=True, fill='both')

    y_scroll = ttk.Scrollbar(text_frame, orient='vertical',
                            command=result_text.yview)
    y_scroll.pack(side=ttk.RIGHT, fill='y')

    # Прив'язка скроллбару до віджету Text
    result_text.config(yscrollcommand=y_scroll.set)

    # save button
    save_button = ttk.Button(right_frame,
                             text='Зберегти у файл',
                             command=lambda: save_to_file())
    save_button.pack(pady=10)

    def save_to_file():
        global results, valid_data
        if valid_data and results:
            file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                     filetypes=[("Text files", "*.txt")])
            if file_path:
                with open(file_path, 'w') as file:
                    file.write("Згенеровані числа:\n")
                    file.write(", ".join(map(str, results)))
                update_result_text(f"Результати збережено у файл: {file_path}", result_text)
        else:
            update_result_text("Немає результатів для збереження або дані некоректні.", result_text)
            valid_data = False

    # Command for button to generate numbers
    def generate_numbers():
        global results, valid_data
        try:
            num = int(spinbox.get())
            if num <= 0:
                update_result_text("Введіть додатне число, більше за 0.", result_text)
                valid_data = False
                return

            if num > 999:
                update_result_text('Максимальна кількість згенерованих чисел 999. '
                                   'Оберіть меншу кількість результатів.', result_text)
                valid_data = False
                return


            lcg = LinearCongruentialGenerator()
            valid_data = True

            results = lcg.generate(num - 1)

            # Update result
            update_result_text(f"Згенеровані числа: {results}", result_text)

        except ValueError:
            update_result_text("Введіть коректне число.", result_text)
            valid_data = False


# Лабораторна 2 (MD5)
def show_lab_2():
    clear_right_frame(right_frame)

    window_bind()  # Прив'язуємо функцію до події зміни розміру

    # Welcome label
    welcome_label = ttk.Label(right_frame,
                              text='Вітаю! Тут ви можете хешувати свої повідомлення!',
                              font=('Calibry', 16))
    welcome_label.pack(pady=10)

    # Створення фрейму для розподілу вікна
    text_frame = ttk.Frame(right_frame)
    text_frame.pack(expand=True, fill='both', pady=20)

    # Фрейм для текстового поля та скроллбару
    input_frame = ttk.Frame(text_frame)
    input_frame.pack(fill=ttk.BOTH, expand=True)

    # Input label
    input_label = ttk.Label(input_frame,
                            text="Введіть повідомлення:")
    input_label.pack()

    # Поле для вводу тексту
    input_text_box = ttk.Text(input_frame, wrap='word',
                              height=10, width=30)
    input_text_box.pack(side=ttk.LEFT, fill=ttk.BOTH, expand=True)

    # Створюємо скроллбар для текстового поля
    y_scroll = ttk.Scrollbar(input_frame, orient='vertical',
                             command=input_text_box.yview)
    y_scroll.pack(side=ttk.RIGHT, fill='y')  # Прив'язуємо скроллбар праворуч

    # Прив'язка скроллбару до віджету Text
    input_text_box['yscrollcommand'] = y_scroll.set

    # Кнопка для хешування тексту
    hash_button = ttk.Button(text_frame, text="Хешувати текст",
                             command=lambda: hash_input(input_text_box, output_text_box))
    hash_button.pack(pady=10)

    # Фрейм для текстового поля та скроллбару
    output_frame = ttk.Frame(text_frame)
    output_frame.pack(fill=ttk.BOTH, expand=True)

    # Input label
    output_label = ttk.Label(output_frame,
                            text="Хешоване повідомлення:")
    output_label.pack()

    # Поле для виводу хешованого значення
    output_text_box = ttk.Text(output_frame, wrap='word',
                              height=10, width=30, state='disabled')
    output_text_box.pack(side=ttk.LEFT, fill=ttk.BOTH, expand=True)

    # Створюємо скроллбар для текстового поля
    y_scroll = ttk.Scrollbar(output_frame, orient='vertical',
                             command=output_text_box.yview)
    y_scroll.pack(side=ttk.RIGHT, fill='y')  # Прив'язуємо скроллбар праворуч

    # Прив'язка скроллбару до віджету Text
    output_text_box['yscrollcommand'] = y_scroll.set

    # Фрейм для кнопок збереження та завантаження
    button_frame = ttk.Frame(text_frame)
    button_frame.pack(pady=10)

    # Кнопка для збереження результату
    save_button = ttk.Button(button_frame, text=SAVE_RESULTS,
                             command=lambda: save_result_lab_2(input_text_box, output_text_box))
    save_button.pack(side=ttk.LEFT, padx=(0, 10))  # Додаємо відступ між кнопками

    # Кнопка для завантаження файлу
    load_button = ttk.Button(button_frame, text="Завантажити файл",
                             command=lambda: load_file(output_text_box))
    load_button.pack(side=ttk.LEFT, padx=(0, 10))

    # Додаємо кнопку для перевірки цілісності файлу
    check_integrity_btn = ttk.Button(button_frame, text="Перевірити цілісність файлу",
                                     command=select_files_and_check_integrity)
    check_integrity_btn.pack(side=ttk.LEFT)

    # Центруємо фрейм кнопок у батьківському фреймі
    button_frame.pack(anchor='center')  # Центруємо фрейм кнопок


# Лабораторна 3 (RC5)
def show_lab_3():
    clear_right_frame(right_frame)  # Очищуємо вміст правої панелі

    window_bind()  # Прив'язуємо функцію до події зміни розміру

    # Вітальне повідомлення
    welcome_label = ttk.Label(right_frame,
                              text='Вітаю! Тут ви можете зашифрувати свої повідомлення алгоритмом RC5!',
                              font=('Calibry', 16))
    welcome_label.pack(pady=10)

    # Поле для вводу пароля
    password_label = ttk.Label(right_frame, text='Пароль:')
    password_label.pack(pady=(10, 0))
    password_entry = ttk.Entry(right_frame, show='*', width=50)
    password_entry.pack(pady=(0, 10))

    # Кнопка для переключення видимості пароля
    toggle_button = ttk.Button(right_frame, text='Показати пароль',
                               command=lambda: toggle_password_visibility(password_entry, toggle_button))
    toggle_button.pack(pady=(0, 10))

    # Фрейм для текстових полів
    text_frame = ttk.Frame(right_frame)
    text_frame.pack(pady=(10, 10), fill='both', expand=True)

    # Ліва частина - поле для вводу тексту
    input_label = ttk.Label(text_frame, text=TEXT_ENCR)
    input_label.grid(row=0, column=0, padx=5, pady=(0, 5), sticky='w')

    input_text_box = ttk.Text(text_frame, height=5, width=40)
    input_text_box.grid(row=1, column=0, padx=5, pady=(0, 5), sticky='nsew')

    input_scrollbar = ttk.Scrollbar(text_frame, orient='vertical', command=input_text_box.yview)
    input_scrollbar.grid(row=1, column=1, sticky='ns')
    input_text_box['yscrollcommand'] = input_scrollbar.set

    # Права частина - поле для відображення зашифрованого тексту
    output_label = ttk.Label(text_frame, text='Зашифрований текст:')
    output_label.grid(row=0, column=2, padx=5, pady=(0, 5), sticky='w')

    output_text_box = ttk.Text(text_frame, height=5, width=40)
    output_text_box.grid(row=1, column=2, padx=5, pady=(0, 5), sticky='nsew')

    output_scrollbar = ttk.Scrollbar(text_frame, orient='vertical', command=output_text_box.yview)
    output_scrollbar.grid(row=1, column=3, sticky='ns')
    output_text_box['yscrollcommand'] = output_scrollbar.set
    output_text_box['state'] = 'disabled'  # Блокуємо редагування

    # Кнопки для шифрування та копіювання
    button_frame_enc = ttk.Frame(right_frame)  # Створюємо новий фрейм для кнопок
    button_frame_enc.pack(pady=10)  # Додаємо фрейм до правого фрейму

    # Кнопка для шифрування
    encrypt_button = ttk.Button(button_frame_enc, text='Зашифрувати',
                                command=lambda: encrypt_text(input_text_box, password_entry, window, output_text_box))
    encrypt_button.pack(side=ttk.LEFT, padx=(0, 5))  # Додаємо кнопку до фрейму кнопок, з правим відступом

    # Кнопка для копіювання тексту
    copy_button = ttk.Button(button_frame_enc, text=COPY_TEXT,
                             command=lambda: copy_text_from_output(window, output_text_box))
    copy_button.pack(side=ttk.LEFT, padx=(0, 5))  # Додаємо кнопку до фрейму кнопок

    # Додаємо кнопки для очищення текстових полів
    clear_input_button = ttk.Button(button_frame_enc, text=CLEAR_INPUT,
                                    command=lambda: clear_text(input_text_box, output_text_box))
    clear_input_button.pack(side=ttk.LEFT)  # Відступ між кнопками

    # Налаштування розширення фреймів
    text_frame.columnconfigure(0, weight=1)
    text_frame.columnconfigure(2, weight=1)
    text_frame.rowconfigure(1, weight=1)

    # Створюємо фрейм для дешифрування
    decrypt_frame = ttk.Frame(right_frame)
    decrypt_frame.pack(pady=(10, 10), fill='both', expand=True)

    # Поле для вводу зашифрованого тексту (ліворуч)
    decrypt_input_label = ttk.Label(decrypt_frame, text='Текст для дешифрування:')
    decrypt_input_label.grid(row=0, column=0, padx=5, pady=(0, 5), sticky='w')

    decrypt_input_text_box = ttk.Text(decrypt_frame, height=5, width=40)
    decrypt_input_text_box.grid(row=1, column=0, padx=5, pady=(0, 5), sticky='nsew')

    decrypt_input_scrollbar = ttk.Scrollbar(decrypt_frame, orient='vertical', command=decrypt_input_text_box.yview)
    decrypt_input_scrollbar.grid(row=1, column=1, sticky='ns')
    decrypt_input_text_box['yscrollcommand'] = decrypt_input_scrollbar.set

    # Поле для відображення розшифрованого тексту (праворуч)
    decrypted_output_label = ttk.Label(decrypt_frame, text='Розшифрований текст:')
    decrypted_output_label.grid(row=0, column=2, padx=5, pady=(0, 5), sticky='w')

    decrypted_output_text_box = ttk.Text(decrypt_frame, height=5, width=40)
    decrypted_output_text_box.grid(row=1, column=2, padx=5, pady=(0, 5), sticky='nsew')

    decrypted_output_scrollbar = ttk.Scrollbar(decrypt_frame, orient='vertical',
                                               command=decrypted_output_text_box.yview)
    decrypted_output_scrollbar.grid(row=1, column=3, sticky='ns')
    decrypted_output_text_box['yscrollcommand'] = decrypted_output_scrollbar.set
    decrypted_output_text_box['state'] = 'disabled'  # Блокуємо редагування

    # Кнопки для шифрування та копіювання
    button_frame_decr = ttk.Frame(right_frame)  # Створюємо новий фрейм для кнопок
    button_frame_decr.pack(pady=10)  # Додаємо фрейм до правого фрейму

    # Кнопка для дешифрування
    decrypt_button = ttk.Button(button_frame_decr, text='Розшифрувати',
                                command=lambda: decrypt_text(decrypt_input_text_box, password_entry,
                                                             window, decrypted_output_text_box))
    decrypt_button.pack(side=ttk.LEFT, padx=(0, 5))


    # Додаємо кнопки для очищення текстових полів
    clear_input_button = ttk.Button(button_frame_decr, text=CLEAR_INPUT,
                                    command=lambda: clear_text(decrypt_input_text_box, decrypted_output_text_box))
    clear_input_button.pack(side=ttk.LEFT)  # Відступ між кнопками

    # Налаштування розширення фрейму
    decrypt_frame.columnconfigure(0, weight=1)
    decrypt_frame.columnconfigure(2, weight=1)
    decrypt_frame.rowconfigure(1, weight=1)

    # File selection
    file_path = ttk.StringVar()  # Variable to hold the file path

    file_label = ttk.Label(right_frame, text=FILE_PATH)
    file_label.pack(pady=(10, 0))
    file_entry = ttk.Entry(right_frame, textvariable=file_path, width=50)
    file_entry.pack(pady=(0, 10))
    file_button = ttk.Button(right_frame, text=SELECT_FILE, command=lambda: select_file())
    file_button.pack(pady=(0, 10))

    # Дисплей завантаження
    progress_bar = ttk.Progressbar(right_frame, orient='horizontal', mode='determinate', length=300)
    progress_bar.pack(pady=(10, 10))

    # Кнопки для шифрування та копіювання
    button_frame_file = ttk.Frame(right_frame)  # Створюємо новий фрейм для кнопок
    button_frame_file.pack(pady=10)  # Додаємо фрейм до правого фрейму

    encrypt_button = ttk.Button(button_frame_file, text='Зашифрувати файл', command=lambda: encrypt_file())
    encrypt_button.pack(side=ttk.LEFT, padx=(0, 5))

    # Кнопка для розшифрування
    decrypt_button = ttk.Button(button_frame_file, text='Розшифрувати файл', command=lambda: decrypt_file())
    decrypt_button.pack(side=ttk.LEFT)


    def update_progress(value):
        progress_bar['value'] = value
        window.update_idletasks()  # Оновлюємо інтерфейс, щоб відобразити зміни

    def threaded_encrypt_file():
        password = password_entry.get().strip()
        if not validate_password(password):
            return  # Виходимо, якщо пароль не відповідає критеріям
        rc5 = RC5(password)
        input_file = file_path.get()
        if not input_file:
            messagebox.showwarning("Warning", "Будь ласка, виберіть файл для шифрування!")
            return
        output_file = input_file + '.enc'  # Ім'я вихідного файлу

        try:
            progress_bar['value'] = 0
            progress_bar['maximum'] = 100

            # Викликаємо метод шифрування з функцією оновлення прогресу
            rc5.encrypt_file(input_file, output_file, progress_callback=update_progress)
            messagebox.showinfo("Success", f"Файл успішно зашифровано та збережено як:\n{output_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Сталася помилка при шифруванні файлу:\n{str(e)}")
        finally:
            progress_bar['value'] = 0

    # Функція для потоку розшифрування файлу
    def threaded_decrypt_file():
        password = password_entry.get().strip()
        if not validate_password(password):
            return  # Виходимо, якщо пароль не відповідає критеріям
        rc5 = RC5(password)
        input_file = file_path.get()
        if not input_file:
            messagebox.showwarning("Warning", "Будь ласка, виберіть файл для розшифрування!")
            return

        file_name = os.path.basename(input_file).replace('.enc', '')  # Відкидаємо .enc
        output_directory = r'decrypted_files'  # Директорія для розшифрованих файлів

        if not os.path.exists(output_directory):
            os.makedirs(output_directory)

        output_file = os.path.join(output_directory, file_name)  # Шлях до вихідного файлу

        try:
            progress_bar['value'] = 0
            progress_bar['maximum'] = 100

            # Викликаємо метод розшифрування з функцією оновлення прогресу
            rc5.decrypt_file(input_file, output_file, progress_callback=update_progress)
            messagebox.showinfo("Success", f"Файл успішно розшифровано та збережено як:\n{output_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Сталася помилка при розшифруванні файлу:\n{str(e)}")
        finally:
            progress_bar['value'] = 0

    # Кнопка шифрування
    def encrypt_file():
        thread = threading.Thread(target=threaded_encrypt_file)
        thread.start()

    # Кнопка розшифрування
    def decrypt_file():
        thread = threading.Thread(target=threaded_decrypt_file)
        thread.start()

    def select_file():
        file_name = filedialog.askopenfilename(title="Виберіть файл для шифрування")
        if file_name:
            file_path.set(file_name)

# Лабораторна 4 (RSA)
def show_lab_4():
    clear_right_frame(right_frame)  # Очищуємо вміст правої панелі

    window_bind()  # Прив'язуємо функцію до події зміни розміру

    # Вітальне повідомлення
    welcome_label = ttk.Label(right_frame,
                              text='Вітаю! Тут ви можете зашифрувати свої повідомлення алгоритмом RSA!',
                              font=('Calibry', 16))
    welcome_label.pack(pady=10)

    # Фрейм для текстових полів
    text_frame = ttk.Frame(right_frame)
    text_frame.pack(pady=(10, 10), fill='both', expand=True)

    # Ліва частина - поле для вводу тексту
    input_label = ttk.Label(text_frame, text=TEXT_ENCR)
    input_label.grid(row=0, column=0, padx=5, pady=(0, 5), sticky='w')

    input_text_box = ttk.Text(text_frame, height=5, width=40)
    input_text_box.grid(row=1, column=0, padx=5, pady=(0, 5), sticky='nsew')

    input_scrollbar = ttk.Scrollbar(text_frame, orient='vertical', command=input_text_box.yview)
    input_scrollbar.grid(row=1, column=1, sticky='ns')
    input_text_box['yscrollcommand'] = input_scrollbar.set

    # Права частина - поле для відображення зашифрованого тексту
    output_label = ttk.Label(text_frame, text='Зашифрований текст:')
    output_label.grid(row=0, column=2, padx=5, pady=(0, 5), sticky='w')

    output_text_box = ttk.Text(text_frame, height=5, width=40)
    output_text_box.grid(row=1, column=2, padx=5, pady=(0, 5), sticky='nsew')

    output_scrollbar = ttk.Scrollbar(text_frame, orient='vertical', command=output_text_box.yview)
    output_scrollbar.grid(row=1, column=3, sticky='ns')
    output_text_box['yscrollcommand'] = output_scrollbar.set
    output_text_box['state'] = 'disabled'  # Блокуємо редагування

    # Кнопки для шифрування та копіювання
    button_frame_enc = ttk.Frame(right_frame)  # Створюємо новий фрейм для кнопок
    button_frame_enc.pack(pady=10)  # Додаємо фрейм до правого фрейму

    # Кнопка для шифрування
    encrypt_button = ttk.Button(button_frame_enc, text='Зашифрувати',
                                command=lambda: encrypt_text_rsa(input_text_box, output_text_box))
    encrypt_button.pack(side=ttk.LEFT, padx=(0, 5))  # Додаємо кнопку до фрейму кнопок, з правим відступом

    # Кнопка для копіювання тексту
    copy_button = ttk.Button(button_frame_enc, text=COPY_TEXT,
                             command=lambda: copy_text_from_output(window, output_text_box))
    copy_button.pack(side=ttk.LEFT, padx=(0, 5))  # Додаємо кнопку до фрейму кнопок

    # Додаємо кнопки для очищення текстових полів
    clear_input_button = ttk.Button(button_frame_enc, text=CLEAR_INPUT,
                                    command=lambda: clear_text(input_text_box, output_text_box))
    clear_input_button.pack(side=ttk.LEFT)  # Відступ між кнопками

    # Налаштування розширення фреймів
    text_frame.columnconfigure(0, weight=1)
    text_frame.columnconfigure(2, weight=1)
    text_frame.rowconfigure(1, weight=1)

    # Створюємо фрейм для дешифрування
    decrypt_frame = ttk.Frame(right_frame)
    decrypt_frame.pack(pady=(10, 10), fill='both', expand=True)

    # Поле для вводу зашифрованого тексту (ліворуч)
    decrypt_input_label = ttk.Label(decrypt_frame, text='Текст для дешифрування:')
    decrypt_input_label.grid(row=0, column=0, padx=5, pady=(0, 5), sticky='w')

    decrypt_input_text_box = ttk.Text(decrypt_frame, height=5, width=40)
    decrypt_input_text_box.grid(row=1, column=0, padx=5, pady=(0, 5), sticky='nsew')

    decrypt_input_scrollbar = ttk.Scrollbar(decrypt_frame, orient='vertical', command=decrypt_input_text_box.yview)
    decrypt_input_scrollbar.grid(row=1, column=1, sticky='ns')
    decrypt_input_text_box['yscrollcommand'] = decrypt_input_scrollbar.set

    # Поле для відображення розшифрованого тексту (праворуч)
    decrypted_output_label = ttk.Label(decrypt_frame, text='Розшифрований текст:')
    decrypted_output_label.grid(row=0, column=2, padx=5, pady=(0, 5), sticky='w')

    decrypted_output_text_box = ttk.Text(decrypt_frame, height=5, width=40)
    decrypted_output_text_box.grid(row=1, column=2, padx=5, pady=(0, 5), sticky='nsew')

    decrypted_output_scrollbar = ttk.Scrollbar(decrypt_frame, orient='vertical',
                                               command=decrypted_output_text_box.yview)
    decrypted_output_scrollbar.grid(row=1, column=3, sticky='ns')
    decrypted_output_text_box['yscrollcommand'] = decrypted_output_scrollbar.set
    decrypted_output_text_box['state'] = 'disabled'  # Блокуємо редагування

    # Кнопки для шифрування та копіювання
    button_frame_decr = ttk.Frame(right_frame)  # Створюємо новий фрейм для кнопок
    button_frame_decr.pack(pady=10)  # Додаємо фрейм до правого фрейму

    # Кнопка для дешифрування
    decrypt_button = ttk.Button(button_frame_decr, text='Розшифрувати',
                                command=lambda: decrypt_text_rsa(decrypt_input_text_box, decrypted_output_text_box))
    decrypt_button.pack(side=ttk.LEFT, padx=(0, 5))

    # Додаємо кнопки для очищення текстових полів
    clear_input_button = ttk.Button(button_frame_decr, text=CLEAR_INPUT,
                                    command=lambda: clear_text(decrypt_input_text_box, decrypted_output_text_box))
    clear_input_button.pack(side=ttk.LEFT)  # Відступ між кнопками

    # Налаштування розширення фрейму
    decrypt_frame.columnconfigure(0, weight=1)
    decrypt_frame.columnconfigure(2, weight=1)
    decrypt_frame.rowconfigure(1, weight=1)

    # File selection
    file_path = ttk.StringVar()  # Variable to hold the file path

    file_label = ttk.Label(right_frame, text=FILE_PATH)
    file_label.pack(pady=(10, 0))
    file_entry = ttk.Entry(right_frame, textvariable=file_path, width=50)
    file_entry.pack(pady=(0, 10))
    file_button = ttk.Button(right_frame, text=SELECT_FILE, command=lambda: select_file())
    file_button.pack(pady=(0, 10))

    # Кнопки для шифрування та дешифрування файлу
    button_frame_file = ttk.Frame(right_frame)  # Створюємо новий фрейм для кнопок
    button_frame_file.pack(pady=10)  # Додаємо фрейм до правого фрейму

    encrypt_button = ttk.Button(button_frame_file, text='Зашифрувати файл', command=lambda: encrypt_file())
    encrypt_button.pack(side=ttk.LEFT, padx=(0, 5))

    # Кнопка для розшифрування
    decrypt_button = ttk.Button(button_frame_file, text='Розшифрувати файл', command=lambda: decrypt_file())
    decrypt_button.pack(side=ttk.LEFT)

    # Оновлення тексту в інтерфейсі
    def update_result_message(message):
        messagebox.showinfo("Success", message)

    # Функція для шифрування файлів (в окремому потоці)
    def threaded_encrypt_file():
        rsa = RSAEncryption()
        input_file = file_path.get()  # Отримуємо шлях до файлу
        if not input_file:
            messagebox.showwarning("Warning", "Будь ласка, виберіть файл для шифрування!")
            return

        output_file = input_file + '.bin'

        try:
            rsa.generate_keys()
            rsa.save_keys(PRIVATE_KEY_RSA, PUBLIC_KEY_RSA)
            _, public_key_obj = rsa.load_keys(PRIVATE_KEY_RSA, PUBLIC_KEY_RSA)

            # Шифруємо файл
            rsa.encrypt_file(input_file, output_file, public_key_obj)
            update_result_message(f"Файл успішно зашифровано та збережено як:\n{output_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Сталася помилка при шифруванні файлу:\n{str(e)}")

    # Функція для дешифрування файлів (в окремому потоці)
    def threaded_decrypt_file():
        rsa = RSAEncryption()
        rsa.generate_keys()
        private_key_obj, _ = rsa.load_keys(PRIVATE_KEY_RSA, PUBLIC_KEY_RSA)
        input_file = file_path.get()  # Отримуємо шлях до файлу
        if not input_file:
            messagebox.showwarning("Warning", "Будь ласка, виберіть файл для розшифрування!")
            return

        # Витягуємо назву файлу без розширення
        output_file = os.path.basename(input_file).replace('.bin', '')  # Відкидаємо .bin

        try:
            # Дешифруємо файл
            rsa.decrypt_file(input_file, output_file, private_key_obj)
            update_result_message(f"Файл успішно розшифровано та збережено як:\n{output_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Сталася помилка при розшифруванні файлу:\n{str(e)}")

    # Кнопка для шифрування файлів
    def encrypt_file():
        thread = threading.Thread(target=threaded_encrypt_file)
        thread.start()

    # Кнопка для дешифрування файлів
    def decrypt_file():
        thread = threading.Thread(target=threaded_decrypt_file)
        thread.start()

    def select_file():
        file_name = filedialog.askopenfilename(title="Виберіть файл для шифрування")
        if file_name:
            file_path.set(file_name)


# Лабораторна 5 (DSA)
def show_lab_5():
    clear_right_frame(right_frame)  # Очищуємо вміст правої панелі

    window_bind()  # Прив'язуємо функцію до події зміни розміру

    # Вітальне повідомлення
    welcome_label = ttk.Label(right_frame,
                              text='Вітаю! Тут ви можете зашифрувати свої повідомлення алгоритмом DSA!',
                              font=('Calibry', 16))
    welcome_label.pack(pady=10)

    # Фрейм для текстових полів
    text_frame = ttk.Frame(right_frame)
    text_frame.pack(pady=(10, 10), fill='both', expand=True)

    # Ліва частина - поле для вводу тексту
    input_label = ttk.Label(text_frame, text=TEXT_ENCR)
    input_label.grid(row=0, column=0, padx=5, pady=(0, 5), sticky='w')

    input_text_box = ttk.Text(text_frame, height=5, width=40)
    input_text_box.grid(row=1, column=0, padx=5, pady=(0, 5), sticky='nsew')

    input_scrollbar = ttk.Scrollbar(text_frame, orient='vertical', command=input_text_box.yview)
    input_scrollbar.grid(row=1, column=1, sticky='ns')
    input_text_box['yscrollcommand'] = input_scrollbar.set

    # Права частина - поле для відображення зашифрованого тексту
    output_label = ttk.Label(text_frame, text='Згенерований цифровий підпис:')
    output_label.grid(row=0, column=2, padx=5, pady=(0, 5), sticky='w')

    output_text_box = ttk.Text(text_frame, height=5, width=40)
    output_text_box.grid(row=1, column=2, padx=5, pady=(0, 5), sticky='nsew')

    output_scrollbar = ttk.Scrollbar(text_frame, orient='vertical', command=output_text_box.yview)
    output_scrollbar.grid(row=1, column=3, sticky='ns')
    output_text_box['yscrollcommand'] = output_scrollbar.set
    output_text_box['state'] = 'disabled'  # Блокуємо редагування

    # Кнопки для шифрування та копіювання
    button_frame_enc = ttk.Frame(right_frame)  # Створюємо новий фрейм для кнопок
    button_frame_enc.pack(pady=10)  # Додаємо фрейм до правого фрейму

    # Кнопка для шифрування
    encrypt_button = ttk.Button(button_frame_enc, text='Згенерувати цифровий підпис',
                                command=lambda: generate_digital_signature_text())
    encrypt_button.pack(side=ttk.LEFT, padx=(0, 5))  # Додаємо кнопку до фрейму кнопок, з правим відступом

    # Кнопка для копіювання тексту
    copy_button = ttk.Button(button_frame_enc, text=COPY_TEXT,
                             command=lambda: copy_text_from_output(window, output_text_box))
    copy_button.pack(side=ttk.LEFT, padx=(0, 5))  # Додаємо кнопку до фрейму кнопок

    # Кнопка для збереження результату
    save_button = ttk.Button(button_frame_enc, text=SAVE_RESULTS,
                             command=lambda: save_results(input_text_box, output_text_box))
    save_button.pack(side=ttk.LEFT, padx=(0, 10))  # Додаємо відступ між кнопками

    # Додаємо кнопки для очищення текстових полів
    clear_input_button = ttk.Button(button_frame_enc, text=CLEAR_INPUT,
                                    command=lambda: clear_text(input_text_box, output_text_box))
    clear_input_button.pack(side=ttk.LEFT)  # Відступ між кнопками

    # Налаштування розширення фреймів
    text_frame.columnconfigure(0, weight=1)
    text_frame.columnconfigure(2, weight=1)
    text_frame.rowconfigure(1, weight=1)

    # File selection
    file_path = ttk.StringVar()  # Variable to hold the file path
    signature_path = ttk.StringVar()

    file_label = ttk.Label(right_frame, text=FILE_PATH)
    file_label.pack(pady=(10, 0))
    file_entry = ttk.Entry(right_frame, textvariable=file_path, width=50)
    file_entry.pack(pady=(0, 10))

    file_buttons = ttk.Frame(right_frame)
    file_buttons.pack(pady=10)
    file_button = ttk.Button(file_buttons, text=SELECT_FILE, command=lambda: select_file())
    file_button.pack(side=ttk.LEFT, padx=(0, 10))
    file_digital_signature = ttk.Button(file_buttons, text='Згенерувати цифровий підпис файлу', command=lambda: generate_digital_signature_file())
    file_digital_signature.pack(side=ttk.LEFT, padx=(0, 10))
    file_integrity_check = ttk.Button(file_buttons, text='Перевірити цілісність файлу', command=lambda: check_digital_signature_file())
    file_integrity_check.pack(side=ttk.LEFT)

    # Оновлення тексту в інтерфейсі
    def update_result_message(message):
        update_result_text(message, output_text_box)

    # Функція для генерації цифрового підпису в окремому потоці
    def threaded_generate_digital_signature():
        plaintext = input_text_box.get("1.0", ttk.END)  # Отримуємо текст
        # Обрізаємо символи нового рядка з кінця
        if plaintext.endswith('\n'):
            plaintext = plaintext[:-1]  # Видалити останній символ, якщо це '\n'

        try:
            dsa = DSAEncryption()
            dsa.generate_keys()

            # Збереження ключів
            dsa.save_private_key(PRIVATE_KEY_DSA)
            dsa.save_public_key(PUBLIC_KEY_DSA)

            # Генерація підпису
            signature_hex = dsa.sign_message(plaintext)

            # Збереження підпису
            dsa.save_signature(signature_hex, "message_signature.txt")

            update_result_message(signature_hex)  # Оновлення текстового поля з підписом
        except Exception as e:
            messagebox.showerror("Error", f"Сталася помилка при генерації підпису:\n{str(e)}")

    # Кнопка для генерування цифрового підпису
    def generate_digital_signature_text():
        thread = threading.Thread(target=threaded_generate_digital_signature)
        thread.start()

    # Функція для генерації цифрового підпису файлу в окремому потоці
    def threaded_generate_digital_signature_file():
        input_file = file_path.get()
        if not input_file:
            messagebox.showwarning("Warning", "Будь ласка, виберіть файл для отримання цифрового підпису!")
            return

        try:
            dsa = DSAEncryption()
            dsa.generate_keys()

            # Збереження ключів
            dsa.save_private_key(PRIVATE_KEY_DSA)
            dsa.save_public_key(PUBLIC_KEY_DSA)

            # Генерація цифрового підпису для файлу
            signature_file_hex = dsa.sign_file(input_file)

            # Збереження підпису
            dsa.save_signature(signature_file_hex, "file_signature.txt")

            update_result_message(signature_file_hex)  # Оновлення текстового поля з підписом

            # Інформаційне повідомлення про успіх
            messagebox.showinfo("Success",
                                f"Цифровий підпис для файлу успішно згенерований та збережений в:\n{r'C:/Users/Kate/PycharmProjects/zahist_informacii/lab_1/tests/file_signature.txt'}")
        except Exception as e:
            messagebox.showerror("Error", f"Сталася помилка при генеруванні цифрового підпису файлу:\n{str(e)}")

    # Кнопка для генерування цифрового підпису файлу
    def generate_digital_signature_file():
        thread = threading.Thread(target=threaded_generate_digital_signature_file)
        thread.start()

    # Функція для перевірки цифрового підпису файлу в окремому потоці
    def threaded_check_digital_signature_file():
        input_file = file_path.get()
        if not input_file:
            messagebox.showwarning("Warning", "Будь ласка, виберіть файл для перевірки цифрового підпису!")
            return

        select_signature()
        signature_file = signature_path.get()
        if not signature_file:
            messagebox.showwarning("Warning", "Будь ласка, виберіть файл із цифрового підпису!")
            return

        try:
            # Завантажуємо підпис і публічний ключ
            dsa = DSAEncryption()
            loaded_file_signature_hex = dsa.load_signature(signature_file)
            public_key = dsa.load_public_key(PUBLIC_KEY_DSA)

            # Перевірка підпису
            is_valid_file = dsa.verify_file_signature(public_key, input_file, loaded_file_signature_hex)

            # Виведення результату перевірки
            if is_valid_file:
                messagebox.showinfo("Success", "Перевірка цілісності файлу є успішною")
            else:
                messagebox.showerror("Error", "Перевірка цілісності файлу не успішна. Вміст файлу був змінений")

        except Exception as e:
            messagebox.showerror("Error",
                                 f"Сталася помилка при перевірці цифрового підпису файлу:\n{str(e)},\n{signature_file}")

    # Кнопка для перевірки цифрового підпису файлу
    def check_digital_signature_file():
        thread = threading.Thread(target=threaded_check_digital_signature_file)
        thread.start()


    def save_results(input_text_box, output_text_box):
        # Вибір місця збереження файлу
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title=SAVE_RESULTS
        )

        if not file_path:
            # Користувач не обрав файл для збереження
            return

        # Отримання тексту з полів введення та результату
        input_text = input_text_box.get("1.0", "end-1c")  # Вхідний текст без нового рядка в кінці
        output_text = output_text_box.get("1.0", "end-1c")  # Результат без нового рядка в кінці

        try:
            with open(file_path, "w", encoding="utf-8") as file:
                # Записуємо вхідний текст у файл
                file.write("Введені дані:\n")
                file.write(input_text + "\n\n")  # Додаємо два переходи на новий рядок

                # Записуємо цифровий підпис у файл
                file.write("Цифровий підпис:\n")
                file.write(output_text + "\n")

            # Повідомлення про успішне збереження
            messagebox.showinfo("Успіх", "Результат успішно збережено у файл!")

        except Exception as e:
            # Повідомлення про помилку у разі виникнення проблем
            messagebox.showerror("Помилка", f"Не вдалося зберегти результат:\n{str(e)}")

    def select_file():
        file_name = filedialog.askopenfilename(title="Виберіть файл")
        if file_name:
            file_path.set(file_name)

    def select_signature():
        signature_name = filedialog.askopenfilename(title="Виберіть файл")
        if signature_name:
            signature_path.set(signature_name)


# Left frame for labs buttons
left_frame = ttk.Frame(window, width=150)
left_frame.pack(side=ttk.LEFT, fill=ttk.Y)

# Buttons frame
buttons_container = ttk.Frame(left_frame)
buttons_container.pack(pady=(0, 0))

# Labs buttons
lab_buttons = [
    ("Лабораторна 1", show_lab_1),
    ("Лабораторна 2", show_lab_2),
    ("Лабораторна 3", show_lab_3),
    ("Лабораторна 4", show_lab_4),
    ("Лабораторна 5", show_lab_5),
]

for name, command in lab_buttons:
    btn = ttk.Button(buttons_container, text=name,
                     width=15, command=command)
    btn.pack(fill='x', expand=True, pady=5, padx=5)

# Right frame for content
right_frame = ttk.Frame(window)
right_frame.pack(side=ttk.RIGHT, expand=True, fill=ttk.BOTH, padx=10)

show_lab_4()

# run
window.mainloop()
