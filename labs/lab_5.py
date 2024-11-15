from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


class DSAEncryption:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    # Генерація DSA ключів
    def generate_keys(self):
        self.private_key = dsa.generate_private_key(key_size=2048, backend=default_backend())
        self.public_key = self.private_key.public_key()

    # Збереження приватного ключа в файл
    def save_private_key(self, file_path):
        with open(file_path, "wb") as key_file:
            key_file.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

    # Збереження публічного ключа в файл
    def save_public_key(self, file_path):
        with open(file_path, "wb") as key_file:
            key_file.write(
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

    # Читання приватного ключа з файлу
    @staticmethod
    def load_private_key(file_path):
        with open(file_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        return private_key

    # Читання публічного ключа з файлу
    @staticmethod
    def load_public_key(file_path):
        with open(file_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        return public_key

    # Створення підпису для даного тексту
    def sign_message(self, message):
        signature = self.private_key.sign(
            message.encode('utf-8'),
            hashes.SHA256()
        )
        return signature.hex()  # повертаємо підпис у шістнадцятковому форматі

    # Перевірка підпису
    @staticmethod
    def verify_signature(public_key, message, signature_hex):
        signature = bytes.fromhex(signature_hex)  # перетворюємо з шістнадцяткового формату
        try:
            public_key.verify(
                signature,
                message.encode('utf-8'),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print("Verification failed:", e)
            return False

    # Створення підпису для файлу
    def sign_file(self, file_path):
        with open(file_path, "rb") as f:
            file_data = f.read()
        signature = self.private_key.sign(
            file_data,
            hashes.SHA256()
        )
        return signature.hex()  # повертаємо підпис у шістнадцятковому форматі

    # Перевірка підпису для файлу
    @staticmethod
    def verify_file_signature(public_key, file_path, signature_hex):
        with open(file_path, "rb") as f:
            file_data = f.read()
        signature = bytes.fromhex(signature_hex)  # перетворюємо з шістнадцяткового формату
        try:
            public_key.verify(
                signature,
                file_data,
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print("Verification failed:", e)
            return False

    # Збереження підпису в файл
    @staticmethod
    def save_signature(signature_hex, file_path):
        with open(file_path, "w") as sig_file:
            sig_file.write(signature_hex)

    # Читання підпису з файлу
    @staticmethod
    def load_signature(file_path):
        with open(file_path, "r") as sig_file:
            signature_hex = sig_file.read()
        return signature_hex


# Демонстрація використання
# if __name__ == "__main__":
#     # Створення об'єкта класу
#     dsa_encryption = DSAEncryption()
#
#     # Генерація ключів
#     dsa_encryption.generate_keys()
#
#     # Збереження ключів
#     dsa_encryption.save_private_key("tests/private_key.pem")
#     dsa_encryption.save_public_key("tests/public_key.pem")
#
#     # Завантаження ключів з файлів
#     private_key = DSAEncryption.load_private_key("tests/private_key.pem")
#     public_key = DSAEncryption.load_public_key("tests/public_key.pem")
#
#     # Приклад для підпису рядка
#     message = "Це тестовий текст для підпису."
#     signature_hex = dsa_encryption.sign_message(message)
#     print("Підпис для повідомлення (шістнадцятковий формат):", signature_hex)
#     DSAEncryption.save_signature(signature_hex, "tests/message_signature.txt")
#
#     # Завантаження підпису з файлу та перевірка
#     loaded_signature_hex = DSAEncryption.load_signature("tests/message_signature.txt")
#     is_valid = DSAEncryption.verify_signature(public_key, message, loaded_signature_hex)
#     print("Перевірка підпису для повідомлення:", "Валідний" if is_valid else "Невалідний")
#
#     # Приклад для підпису файлу
#     file_path = "tests/test_file.txt"  # створіть тестовий файл перед запуском
#     signature_file_hex = dsa_encryption.sign_file(file_path)
#     print("Підпис для файлу (шістнадцятковий формат):", signature_file_hex)
#     DSAEncryption.save_signature(signature_file_hex, "tests/file_signature.txt")
#
#     # Завантаження підпису файлу та перевірка
#     loaded_file_signature_hex = DSAEncryption.load_signature("tests/file_signature.txt")
#     is_valid_file = DSAEncryption.verify_file_signature(public_key, file_path, loaded_file_signature_hex)
#     print("Перевірка підпису для файлу:", "Валідний" if is_valid_file else "Невалідний")
