from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from ..labs.lab_3 import RC5
import chardet
import time


class RSAEncryption:
    def __init__(self, bits=2048, hybrid_threshold=1000):
        self.bits = bits
        self.private_key = None
        self.public_key = None
        self.hybrid_threshold = hybrid_threshold  # Поріг для вибору методу шифрування

    # Генерація ключів RSA
    def generate_keys(self):
        key = RSA.generate(self.bits)
        self.private_key = key.export_key()
        self.public_key = key.publickey().export_key()

    # Збереження ключів у файли
    def save_keys(self, private_filename="private.pem", public_filename="public.pem"):
        with open(private_filename, "wb") as priv_file:
            priv_file.write(self.private_key)
        with open(public_filename, "wb") as pub_file:
            pub_file.write(self.public_key)

    # Читання ключів з файлів
    def load_keys(self, private_filename="private.pem", public_filename="public.pem"):
        with open(private_filename, "rb") as priv_file:
            private_key = priv_file.read()
        with open(public_filename, "rb") as pub_file:
            public_key = pub_file.read()

        private_key_obj = RSA.import_key(private_key)
        public_key_obj = RSA.import_key(public_key)

        return private_key_obj, public_key_obj

    # Шифрування для невеликих повідомлень (RSA)
    def encrypt_message(self, message, public_key_obj):
        cipher = PKCS1_OAEP.new(public_key_obj)
        block_size = public_key_obj.size_in_bytes() - 42  # 42 байти для OAEP padding
        encrypted_message = b""

        # Розбиваємо повідомлення на блоки
        for i in range(0, len(message), block_size):
            block = message[i:i + block_size]
            # Перевіряємо, чи блок вже є байтами
            if isinstance(block, str):
                # Якщо блок є рядком, то кодуємо його перед шифруванням
                encrypted_message += cipher.encrypt(block.encode())
            else:
                encrypted_message += cipher.encrypt(block)

        return encrypted_message

    # Гібридне шифрування для великих повідомлень
    def hybrid_encrypt_message(self, message, public_key_obj):
        # Генеруємо випадковий ключ AES
        aes_key = get_random_bytes(32)  # AES-256

        # Шифруємо повідомлення за допомогою AES
        cipher_aes = AES.new(aes_key, AES.MODE_GCM)
        if isinstance(message, str):
            # Якщо блок є рядком, то кодуємо його перед шифруванням
            message = message.encode()
        ciphertext, tag = cipher_aes.encrypt_and_digest(message)

        # Шифруємо ключ AES за допомогою RSA
        cipher_rsa = PKCS1_OAEP.new(public_key_obj)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        # Повертаємо зашифроване повідомлення разом з зашифрованим ключем AES і параметрами AES
        return {
            'encrypted_message': ciphertext,
            'encrypted_aes_key': encrypted_aes_key,
            'nonce': cipher_aes.nonce,
            'tag': tag
        }

    # Дешифрування за допомогою RSA
    def decrypt_message(self, encrypted_message, private_key_obj):
        cipher = PKCS1_OAEP.new(private_key_obj)
        block_size = private_key_obj.size_in_bytes()  # Розмір блоку для дешифрування
        decrypted_message = b""

        # Розбиваємо зашифроване повідомлення на блоки
        for i in range(0, len(encrypted_message), block_size):
            block = encrypted_message[i:i + block_size]
            decrypted_message += cipher.decrypt(block)  # Дешифруємо кожен блок
        # Використовуємо функцію для декодування
        if isinstance(decrypted_message, bytes):
            decrypted_message = self.safe_decode(decrypted_message)
        return decrypted_message  # Перетворюємо на строку після дешифрування

    def safe_decode(self, bytes_data):
        try:
            # Пробуємо декодувати як UTF-8
            return bytes_data.decode()
        except UnicodeDecodeError:
            # Якщо виникає помилка, обробляємо її, наприклад, повертаємо оригінальні байти
            return bytes_data

    # Дешифрування гібридного повідомлення
    def hybrid_decrypt_message(self, encrypted_data, private_key_obj):
        # Дешифруємо ключ AES за допомогою RSA
        cipher_rsa = PKCS1_OAEP.new(private_key_obj)
        aes_key = cipher_rsa.decrypt(encrypted_data['encrypted_aes_key'])

        # Дешифруємо повідомлення за допомогою AES
        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=encrypted_data['nonce'])
        decrypted_message = cipher_aes.decrypt_and_verify(encrypted_data['encrypted_message'], encrypted_data['tag'])
        # Використовуємо функцію для декодування
        if isinstance(decrypted_message, bytes):
            decrypted_message = self.safe_decode(decrypted_message)
        return decrypted_message

    # Вибір методу шифрування залежно від розміру повідомлення
    def encrypt(self, message, public_key_obj):
        if len(message) > self.hybrid_threshold:
            return self.hybrid_encrypt_message(message, public_key_obj)  # Використовуємо гібридне шифрування
        else:
            return self.encrypt_message(message, public_key_obj)  # Використовуємо звичайне RSA

    def encrypt_file(self, input_file_path, output_file_path, public_key_obj, hybrid_threshold=1000):
        # Читаємо вміст файлу
        with open(input_file_path, 'rb') as file:
            file_data = file.read()

        # Виявлення кодування
        detected_encoding = chardet.detect(file_data)['encoding']
        if detected_encoding == 'ascii':
            file_data = file_data.decode()
        elif detected_encoding == None:
            file_data = file_data
        else:
            file_data = file_data.decode(detected_encoding)

        # Перевіряємо розмір файлу, щоб визначити метод шифрування
        if len(file_data) > hybrid_threshold:
            # Використовуємо гібридне шифрування для великих файлів
            encrypted_data = self.hybrid_encrypt_message(file_data, public_key_obj)
        else:
            # Використовуємо стандартне RSA шифрування для малих файлів
            encrypted_data = self.encrypt_message(file_data, public_key_obj)

        # Зберігаємо зашифровані дані у вихідний файл
        with open(output_file_path, 'wb') as encrypted_file:
            if isinstance(encrypted_data, dict):
                # Якщо використовувалося гібридне шифрування
                encrypted_file.write(
                    encrypted_data['encrypted_aes_key'] + encrypted_data['nonce'] + encrypted_data['tag'] +
                    encrypted_data['encrypted_message'])
            else:
                # Якщо використовувалося стандартне RSA шифрування
                encrypted_file.write(encrypted_data)

        # print(f"Файл {input_file_path} успішно зашифрований та збережений як {output_file_path}.")

    def decrypt_file(self, input_file_path, output_file_path, private_key_obj, hybrid_threshold=1000):
        # Читаємо зашифровані дані з файлу
        with open(input_file_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()

        # Перевіряємо розмір зашифрованих даних для вибору методу дешифрування
        if len(encrypted_data) > hybrid_threshold:
            # Використовуємо гібридне дешифрування (AES + RSA)
            encrypted_aes_key = encrypted_data[:private_key_obj.size_in_bytes()]
            nonce = encrypted_data[private_key_obj.size_in_bytes():private_key_obj.size_in_bytes() + 16]
            tag = encrypted_data[private_key_obj.size_in_bytes() + 16:private_key_obj.size_in_bytes() + 32]
            encrypted_message = encrypted_data[private_key_obj.size_in_bytes() + 32:]

            # Відновлюємо структуру для гібридного дешифрування
            encrypted_file_data = {
                'encrypted_aes_key': encrypted_aes_key,
                'nonce': nonce,
                'tag': tag,
                'encrypted_message': encrypted_message
            }

            # Дешифруємо зашифроване повідомлення
            decrypted_message = self.hybrid_decrypt_message(encrypted_file_data, private_key_obj)
        else:
            # Використовуємо стандартне RSA дешифрування для малих файлів
            decrypted_message = self.decrypt_message(encrypted_data, private_key_obj)

        # Записуємо розшифровані дані у вихідний файл
        with open(output_file_path, 'wb') as decrypted_file:
            if isinstance(decrypted_message, str):  # Якщо це рядок
                decrypted_message = decrypted_message.encode('utf-8')  # Кодуємо в байти
            decrypted_file.write(decrypted_message)


# Тестування шифрування та дешифрування RC5
# def test_rc5_encryption(message, key):
#     cipher = RC5(key)
#     encrypted_message = cipher.rc5_encrypt(message.encode())
#     return encrypted_message
#
#
# def test_rc5_decryption(encrypted_message, key):
#     cipher = RC5(key)
#     decrypted_message = cipher.rc5_decrypt(encrypted_message).decode()
#     return decrypted_message
#
#
# # Тестування функцій шифрування та дешифрування файлів RSA
# def test_file_encryption_rsa():
#     # Створення об'єкта RSAEncryption і генерація ключів
#     rsa_encryption = RSAEncryption()
#     rsa_encryption.generate_keys()
#
#     # Збереження ключів у файли
#     rsa_encryption.save_keys()
#
#     # Читання ключів з файлів
#     private_key_obj, public_key_obj = rsa_encryption.load_keys()
#
#     # Створення тестового файлу з повідомленням
#     original_filename = "test_file.txt"
#     encrypted_filename = "test_file.txt.bin"
#     decrypted_filename = "test_file_dec.txt"
#
#     # Шифрування файлу
#     rsa_encryption.encrypt_file(original_filename, encrypted_filename, public_key_obj)
#     print(f"Файл '{original_filename}' зашифровано в '{encrypted_filename}'.")
#
#     # Дешифрування файлу
#     rsa_encryption.decrypt_file(encrypted_filename, decrypted_filename, private_key_obj)
#     print(f"Файл '{encrypted_filename}' розшифровано в '{decrypted_filename}'.")
#
#     # Перевірка, чи відповідає розшифрований файл оригінальному
#     with open(original_filename, "r") as original_file, open(decrypted_filename, "r") as decrypted_file:
#         original_content = original_file.read()
#         decrypted_content = decrypted_file.read()
#
#         assert original_content == decrypted_content, "Помилка: Вміст розшифрованого файлу не співпадає з оригіналом"
#         print("Тест пройдено: Вміст розшифрованого файлу відповідає оригіналу.")
#
#     # Очищення тестових файлів
#     # os.remove(original_filename)
#     # os.remove(encrypted_filename)
#     # os.remove(decrypted_filename)
#     print("Тестові файли видалено.")
#
# # Основна функція для тестування
# if __name__ == "__main__":
#     message = "Hello!"
#
#     # Створення об'єкта RSAEncryption і генерація ключів
#     rsa_encryption = RSAEncryption()
#     rsa_encryption.generate_keys()
#
#     # Збереження ключів у файли
#     rsa_encryption.save_keys()
#
#     # Читання ключів з файлів
#     private_key_obj, public_key_obj = rsa_encryption.load_keys()
#
#     # Тестування RSA та гібридного шифрування
#     start_time = time.time()
#     encrypted_message = rsa_encryption.encrypt(message, public_key_obj)
#     if isinstance(encrypted_message, dict):  # Якщо використовується гібридне шифрування
#         print("Використано гібридне шифрування.")
#     else:
#         print("Використано RSA шифрування.")
#     print(f'Шифроване повідомлення: {encrypted_message}')
#     print(f"RSA: Шифрування завершено за {time.time() - start_time:.6f} секунд")
#
#     start_time = time.time()
#     # Якщо повідомлення зашифроване гібридно
#     if isinstance(encrypted_message, dict):
#         decrypted_message = rsa_encryption.hybrid_decrypt_message(encrypted_message, private_key_obj)
#     else:
#         decrypted_message = rsa_encryption.decrypt_message(encrypted_message, private_key_obj)
#     print(f"RSA: Дешифрування завершено за {time.time() - start_time:.6f} секунд")
#     print(f"RSA: Розшифроване повідомлення: {decrypted_message}")
#
#     # Шифрування та дешифрування RC5
#     start_time = time.time()
#     encrypted_rc5_message = test_rc5_encryption(message, 'key')
#     print(f"RC5: Шифрування завершено за {time.time() - start_time:.6f} секунд")
#
#     start_time = time.time()
#     decrypted_rc5_message = test_rc5_decryption(encrypted_rc5_message, 'key')
#     print(f"RC5: Дешифрування завершено за {time.time() - start_time:.6f} секунд")
#     print(f"RC5: Розшифроване повідомлення: {decrypted_rc5_message}")
#
#     test_file_encryption_rsa()
