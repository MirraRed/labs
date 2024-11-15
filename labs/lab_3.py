import struct
import os
import base64
from ..labs.lab_2 import MD5
from ..labs.lab_1 import LinearCongruentialGenerator


class RC5:
    def __init__(self, password, key_length=256):
        self.w = 64
        self.r = 16
        self.b = 32
        self.key = self.generate_key(password, key_length)
        self.key_bytes = bytes.fromhex(self.key)

    def generate_iv(self, length):
        lcg = LinearCongruentialGenerator(seed=int(os.urandom(4).hex(), 16))
        return lcg.random_bytes(length)

    def rotate_left(self, x, y):
        y = y % self.w
        return ((x << y) | (x >> (self.w - y))) & ((1 << self.w) - 1)

    def rc5_key_setup(self):
        P_w = 0xB7E151628AED2A6B
        Q_w = 0x9E3779B97F4A7C15

        len_key = len(self.key_bytes)
        u = self.w // 8
        while len(self.key_bytes) % u != 0:
            self.key_bytes += b'\x00'
        c = len(self.key_bytes) // u
        L = [0] * c
        i = len(self.key_bytes) - 1
        while i >= 0:
            L[i // u] = (L[i // u] << 8) | self.key_bytes[i]
            i -= 1

        t = 2 * (self.r + 1)
        S = [0] * t
        S[0] = P_w
        for i in range(1, t):
            S[i] = (S[i - 1] + Q_w) & ((1 << self.w) - 1)

        i = j = 0
        A = B = 0
        t_c_max = max(t, c)
        for _ in range(3 * t_c_max):
            A = S[i] = self.rotate_left(S[i] + A + B, 3)
            B = L[j] = self.rotate_left(L[j] + A + B, (A + B) % self.w)
            i = (i + 1) % t
            j = (j + 1) % c
        return S

    def add_padding(self, data, block_size=16):
        pad_len = block_size - (len(data) % block_size)
        padding = bytes([pad_len] * pad_len)
        return data + padding

    def remove_padding(self, data):
        pad_len = data[-1]
        return data[:-pad_len]

    def rc5_encrypt_block(self, plain_block):
        S = self.rc5_key_setup()
        A, B = struct.unpack('QQ', plain_block)
        A = (A + S[0]) & ((1 << self.w) - 1)
        B = (B + S[1]) & ((1 << self.w) - 1)

        for i in range(1, self.r + 1):
            A = (self.rotate_left(A ^ B, B) + S[2 * i]) & ((1 << self.w) - 1)
            B = (self.rotate_left(B ^ A, A) + S[2 * i + 1]) & ((1 << self.w) - 1)

        return struct.pack('QQ', A, B)

    def rc5_encrypt(self, data):
        iv = self.generate_iv(16)  # Генерація 128-бітного IV
        encrypted_iv = self.rc5_encrypt_block(iv)
        padded_data = self.add_padding(data)  # Додавання паддінга

        encrypted_data = encrypted_iv
        previous_block = iv
        for i in range(0, len(padded_data), 16):
            block = padded_data[i:i + 16]
            block_to_encrypt = bytes(a ^ b for a, b in zip(block, previous_block))
            encrypted_block = self.rc5_encrypt_block(block_to_encrypt)
            encrypted_data += encrypted_block
            previous_block = encrypted_block

        return encrypted_data

    def rotate_right(self, x, y):
        y = y % self.w
        return ((x >> y) | (x << (self.w - y))) & ((1 << self.w) - 1)

    def rc5_decrypt_block(self, cipher_block):
        S = self.rc5_key_setup()
        A, B = struct.unpack('QQ', cipher_block)

        for i in range(self.r, 0, -1):
            B = self.rotate_right((B - S[2 * i + 1]) & ((1 << self.w) - 1), A) ^ A
            A = self.rotate_right((A - S[2 * i]) & ((1 << self.w) - 1), B) ^ B

        B = (B - S[1]) & ((1 << self.w) - 1)
        A = (A - S[0]) & ((1 << self.w) - 1)

        return struct.pack('QQ', A, B)

    def rc5_decrypt(self, encrypted_data):
        encrypted_iv = encrypted_data[:16]  # Перший блок — це IV
        iv = self.rc5_decrypt_block(encrypted_iv)
        encrypted_data = encrypted_data[16:]  # Відокремлення IV від решти даних

        decrypted_data = b""
        previous_block = iv
        for i in range(0, len(encrypted_data), 16):
            block = encrypted_data[i:i + 16]
            decrypted_block = self.rc5_decrypt_block(block)
            decrypted_block = bytes(a ^ b for a, b in zip(decrypted_block, previous_block))
            decrypted_data += decrypted_block
            previous_block = block

        return self.remove_padding(decrypted_data)

    def generate_key(self, password, key_length):
        # Хеш пароля
        H_P = MD5(password.encode('utf-8'))  # Отримуємо хеш пароля

        if key_length == 64:  # 64 біти (8 байт)
            return H_P[-16:]  # Останні 16 символів (64 біти)

        elif key_length == 256:  # 256 біт (32 байти)
            H_H_P = MD5(H_P.encode('utf-8'))  # Хеш хешу пароля
            return H_H_P + H_P  # Конкатенація обох хешів

    def encrypt_file(self, input_file, output_file, block_size=16, progress_callback=None):
        file_size = os.path.getsize(input_file)

        if file_size > 1024 * 5:  # Якщо файл більше 5 КБ, використовуємо блочне шифрування
            iv = self.generate_iv(16)  # Генерація 128-бітного IV
            encrypted_iv = self.rc5_encrypt_block(iv)

            with open(output_file, 'wb') as f:
                f.write(encrypted_iv)  # Записуємо зашифрований IV у файл

                with open(input_file, 'rb') as input_f:
                    previous_block = iv  # Ініціалізація попереднього блоку
                    processed_bytes = 0  # Кількість оброблених байтів
                    total_bytes = file_size - 16  # Віднімемо 16 байтів для IV

                    while True:
                        plaintext_block = input_f.read(block_size)
                        if not plaintext_block:  # Якщо досягнуто кінця файлу
                            break

                        # Додаємо паддінг, якщо потрібно
                        if len(plaintext_block) < block_size:
                            plaintext_block = self.add_padding(plaintext_block, block_size)

                        # Шифруємо блок
                        block_to_encrypt = bytes(a ^ b for a, b in zip(plaintext_block, previous_block))
                        encrypted_block = self.rc5_encrypt_block(block_to_encrypt)
                        f.write(encrypted_block)

                        previous_block = encrypted_block  # Оновлюємо попередній блок
                        processed_bytes += len(plaintext_block)  # Оновлюємо кількість оброблених байтів

                        # Оновлюємо прогрес бар
                        if progress_callback:
                            progress_callback(int((processed_bytes / total_bytes) * 100))
        else:  # Якщо файл менше або дорівнює 5 КБ, шифруємо весь файл
            with open(input_file, 'rb') as f:
                plaintext = f.read()

            ciphertext = self.rc5_encrypt(plaintext)

            # Перетворення зашифрованих даних у Base64
            b64_ciphertext = base64.b64encode(ciphertext)

            with open(output_file, 'wb') as f:
                f.write(b64_ciphertext)

            # Оновлюємо прогрес бар до 100%
            if progress_callback:
                progress_callback(100)

    def decrypt_file(self, input_file, output_file, block_size=16, progress_callback=None):
        file_size = os.path.getsize(input_file)

        if file_size > 1024 * 5:  # Якщо файл більше 5 КБ, використовуємо блочне дешифрування
            with open(input_file, 'rb') as f:
                encrypted_iv = f.read(16)
                iv = self.rc5_decrypt_block(encrypted_iv)

                with open(output_file, 'wb') as output_f:
                    previous_block = encrypted_iv  # Перший блок — це IV
                    processed_bytes = 0  # Кількість оброблених байтів
                    total_bytes = file_size - 16  # Віднімемо 16 байтів для IV

                    while True:
                        ciphertext_block = f.read(block_size)
                        if not ciphertext_block:  # Якщо досягнуто кінця файлу
                            break

                        # Дешифруємо блок
                        decrypted_block = self.rc5_decrypt_block(ciphertext_block)
                        decrypted_block = bytes(a ^ b for a, b in zip(decrypted_block, previous_block))
                        output_f.write(decrypted_block)

                        previous_block = ciphertext_block  # Оновлюємо попередній блок
                        processed_bytes += len(ciphertext_block)  # Оновлюємо кількість оброблених байтів

                        # Оновлюємо прогрес бар
                        if progress_callback:
                            progress_callback(int((processed_bytes / total_bytes) * 100))

                    # Зняття паддінга в кінці
                    output_data = open(output_file, 'rb').read()  # Читаємо зашифровані дані для зняття паддінга
                    output_f.write(self.remove_padding(output_data))
        else:  # Якщо файл менше або дорівнює 5 КБ, дешифруємо весь файл
            # Читання зашифрованих даних з файлу
            with open(input_file, 'rb') as f:
                b64_ciphertext = f.read()

            # Декодування Base64
            ciphertext = base64.b64decode(b64_ciphertext)

            decrypted_data = self.rc5_decrypt(ciphertext)

            with open(output_file, 'wb') as f:
                f.write(decrypted_data)

            # Оновлюємо прогрес бар до 100%
            if progress_callback:
                progress_callback(100)

# Тестування
# password = 'password'
# cipher = RC5(password)
#
# # Приклад шифрування і дешифрування
# plaintext = ('Я не знаю, як себе слід замучати,\n'
#              'Але після слів про братерство можна було вже зрозуміти,\n'
#              'Як свій гріх каяти.\n')
# # Перетворення тексту у байти з використанням кодування UTF-8
# plaintext_bytes = plaintext.encode('utf-8')
# ciphertext = cipher.rc5_encrypt(plaintext_bytes)
# print("Ciphertext:", ciphertext.hex())
#
# # Тестування дешифрування
# decrypted_data = cipher.rc5_decrypt(ciphertext)
# print("Розшифровані дані:\n", decrypted_data.decode('utf-8'))
#
# # Тестування
# input_filename = r'C:\Users\Kate\OneDrive\Рабочий стол\tests\test_2.docx'  # Вкажіть файл для шифрування
# output_filename = r'C:\Users\Kate\OneDrive\Рабочий стол\tests\encrypted_output.txt'  # Вкажіть файл для збереження зашифрованих даних
#
# cipher.encrypt_file(input_filename, output_filename)
# print(f"Файл {input_filename} зашифровано і збережено як {output_filename}.")
#
# # Тестування
# input_filename = r'C:\Users\Kate\OneDrive\Рабочий стол\tests\encrypted_output.txt'  # Вкажіть файл для дешифрування
# output_filename = r'C:\Users\Kate\OneDrive\Рабочий стол\tests\decrypted_output.docx'  # Вкажіть файл для збереження розшифрованих даних
# cipher.decrypt_file(input_filename, output_filename)
# print(f"Файл {input_filename} розшифровано і збережено як {output_filename}.")
