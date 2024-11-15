import os

import pytest
from ..labs.lab_3 import RC5



# Фікстура для створення екземпляра RC5
@pytest.fixture
def rc5_instance():
    password = "test_password"
    return RC5(password)

def test_generate_key(rc5_instance):
    # Тест на правильність генерації ключа
    key_64 = rc5_instance.generate_key("test_password", key_length=64)
    key_256 = rc5_instance.generate_key("test_password", key_length=256)
    assert len(key_64) == 16  # 64 біти = 16 символів
    assert len(key_256) == 64  # 256 біт = 64 символи

def test_encrypt_decrypt_block(rc5_instance):
    # Перевірка шифрування і дешифрування одного блоку
    plain_block = os.urandom(16)  # Генерація випадкового блоку
    encrypted_block = rc5_instance.rc5_encrypt_block(plain_block)
    decrypted_block = rc5_instance.rc5_decrypt_block(encrypted_block)
    assert decrypted_block == plain_block

def test_add_remove_padding(rc5_instance):
    # Тест на додавання та видалення паддінга
    data = b"example_data"
    padded_data = rc5_instance.add_padding(data, block_size=16)
    assert len(padded_data) % 16 == 0  # Перевірка довжини з паддінгом
    assert rc5_instance.remove_padding(padded_data) == data  # Перевірка видалення паддінга

def test_encrypt_decrypt_data(rc5_instance):
    # Перевірка шифрування і дешифрування даних
    data = b"This is a test message"
    encrypted_data = rc5_instance.rc5_encrypt(data)
    decrypted_data = rc5_instance.rc5_decrypt(encrypted_data)
    assert decrypted_data == data

def test_encrypt_decrypt_file(rc5_instance, tmp_path):
    # Перевірка шифрування і дешифрування файлів
    input_file = tmp_path / "input.txt"
    encrypted_file = tmp_path / "encrypted.txt"
    decrypted_file = tmp_path / "decrypted.txt"

    # Створення тестового файлу
    original_data = b"This is a test file content for RC5"
    with open(input_file, 'wb') as f:
        f.write(original_data)

    # Шифрування файлу
    rc5_instance.encrypt_file(str(input_file), str(encrypted_file), progress_callback=None)

    # Перевірка, що файл був зашифрований
    assert os.path.getsize(encrypted_file) > 0

    # Дешифрування файлу
    rc5_instance.decrypt_file(str(encrypted_file), str(decrypted_file), progress_callback=None)

    # Перевірка, що дешифрований файл збігається з оригіналом
    with open(decrypted_file, 'rb') as f:
        decrypted_data = f.read()
    assert decrypted_data == original_data

def test_generate_iv(rc5_instance):
    # Тест на генерацію IV
    iv = rc5_instance.generate_iv(16)
    assert len(iv) == 16  # IV має бути 16 байт

def test_progress_callback(rc5_instance, tmp_path):
    # Тест для перевірки роботи прогрес-колбека
    input_file = tmp_path / "input.txt"
    encrypted_file = tmp_path / "encrypted.txt"

    # Створення тестового файлу
    original_data = b"This is a test file content for RC5"
    with open(input_file, 'wb') as f:
        f.write(original_data)

    progress = []

    def progress_callback(percent):
        progress.append(percent)

    rc5_instance.encrypt_file(str(input_file), str(encrypted_file), progress_callback=progress_callback)

    # Перевірка, що прогрес збільшувався від 0 до 100
    assert progress[0] > 0
    assert progress[-1] == 100
