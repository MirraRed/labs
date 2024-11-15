import os

import pytest

from Crypto.PublicKey import RSA
from ..labs.lab_4 import RSAEncryption


# Тест для генерації ключів RSA
def test_generate_keys():
    rsa_encryption = RSAEncryption()
    rsa_encryption.generate_keys()
    assert rsa_encryption.private_key is not None
    assert rsa_encryption.public_key is not None


# Тест для збереження і завантаження ключів
def test_save_load_keys():
    rsa_encryption = RSAEncryption()
    rsa_encryption.generate_keys()
    rsa_encryption.save_keys(private_filename="test_private.pem", public_filename="test_public.pem")

    private_key_obj, public_key_obj = rsa_encryption.load_keys(private_filename="test_private.pem",
                                                               public_filename="test_public.pem")
    assert private_key_obj is not None
    assert public_key_obj is not None


# Тест для шифрування і дешифрування повідомлень RSA
def test_rsa_encryption_decryption():
    rsa_encryption = RSAEncryption()
    rsa_encryption.generate_keys()
    message = "hello world"
    rsa_encryption.save_keys(private_filename="test_private.pem", public_filename="test_public.pem")
    private_key_obj, public_key_obj = rsa_encryption.load_keys(private_filename="test_private.pem",
                                                               public_filename="test_public.pem")

    encrypted_message = rsa_encryption.encrypt_message(message, public_key_obj)
    decrypted_message = rsa_encryption.decrypt_message(encrypted_message, private_key_obj)

    assert message == decrypted_message


# Тест для гібридного шифрування
def test_hybrid_encryption_decryption():
    rsa_encryption = RSAEncryption()
    rsa_encryption.generate_keys()
    message = "hello world, this is a large message"
    rsa_encryption.save_keys(private_filename="test_private.pem", public_filename="test_public.pem")
    private_key_obj, public_key_obj = rsa_encryption.load_keys(private_filename="test_private.pem",
                                                               public_filename="test_public.pem")

    encrypted_data = rsa_encryption.hybrid_encrypt_message(message, public_key_obj)
    decrypted_message = rsa_encryption.hybrid_decrypt_message(encrypted_data, private_key_obj)

    assert message == decrypted_message


# Тест для вибору методу шифрування в залежності від розміру повідомлення
@pytest.mark.parametrize("message, expected_method", [
    ("short message", "encrypt_message"),
    ("a" * 1001, "hybrid_encrypt_message")
])
def test_choose_encryption_method(message, expected_method):
    rsa_encryption = RSAEncryption()
    rsa_encryption.generate_keys()
    public_key_obj = RSA.import_key(rsa_encryption.public_key)

    # Перевірка, який метод буде вибрано для шифрування
    encryption_method = rsa_encryption.encrypt(message, public_key_obj)
    assert isinstance(encryption_method, dict if expected_method == "hybrid_encrypt_message" else bytes)


# Тест для шифрування і дешифрування файлів
def test_encrypt_decrypt_file():
    # Створення тестового файлу з правильним кодуванням
    with open('input_file.txt', 'wb') as file:
        file.write("Це тестовий файл для шифрування і дешифрування.".encode('utf-8'))

    rsa_encryption = RSAEncryption()
    rsa_encryption.generate_keys()
    rsa_encryption.save_keys(private_filename="test_private.pem", public_filename="test_public.pem")
    private_key_obj, public_key_obj = rsa_encryption.load_keys(private_filename="test_private.pem",
                                                               public_filename="test_public.pem")

    # Тест для шифрування файлу
    rsa_encryption.encrypt_file('input_file.txt', 'encrypted_file.txt', public_key_obj)

    # Тест для дешифрування файлу
    rsa_encryption.decrypt_file('encrypted_file.txt', 'decrypted_file.txt', private_key_obj)

    with open('input_file.txt', 'rb') as original_file:
        original_data = original_file.read()

    with open('decrypted_file.txt', 'rb') as decrypted_file:
        decrypted_data = decrypted_file.read()

    assert original_data == decrypted_data

    # Видалення файлів після тесту
    os.remove('input_file.txt')
    os.remove('encrypted_file.txt')
    os.remove('decrypted_file.txt')


# Тест для безпечного декодування
def test_safe_decode():
    rsa_encryption = RSAEncryption()
    bytes_data = b'Hello world'
    decoded_message = rsa_encryption.safe_decode(bytes_data)
    assert decoded_message == 'Hello world'

    bytes_data_invalid = b'\x80\x81\x82'  # Некоректні байти
    decoded_message = rsa_encryption.safe_decode(bytes_data_invalid)
    assert decoded_message == bytes_data_invalid


@pytest.fixture(autouse=True)
def cleanup_files():
    """Фікстура для очищення тестових файлів після кожного тесту"""
    test_files = [
        "test_private.pem",
        "test_public.pem"
    ]
    yield
    # Після тесту очищаємо файли
    for file in test_files:
        if os.path.exists(file):
            os.remove(file)
