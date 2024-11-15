import os

import pytest
from ..labs.lab_5 import DSAEncryption


@pytest.fixture
def dsa_encryption():
    """Фікстура для створення об'єкта DSAEncryption"""
    dsa = DSAEncryption()
    dsa.generate_keys()
    return dsa


def test_generate_keys(dsa_encryption):
    """Тестуємо генерацію ключів"""
    assert dsa_encryption.private_key is not None
    assert dsa_encryption.public_key is not None


def test_sign_message(dsa_encryption):
    """Тестуємо підписування повідомлення"""
    message = "Це тестове повідомлення."
    signature_hex = dsa_encryption.sign_message(message)
    assert isinstance(signature_hex, str)
    assert len(signature_hex) > 0


def test_verify_signature(dsa_encryption):
    """Тестуємо перевірку підпису повідомлення"""
    message = "Це тестове повідомлення."
    signature_hex = dsa_encryption.sign_message(message)
    is_valid = DSAEncryption.verify_signature(dsa_encryption.public_key, message, signature_hex)
    assert is_valid


def test_sign_file(dsa_encryption):
    """Тестуємо підписування файлу"""
    file_path = "test_file.txt"
    with open(file_path, "w") as f:
        f.write("Це тестовий файл для підпису.")

    signature_hex = dsa_encryption.sign_file(file_path)
    assert isinstance(signature_hex, str)
    assert len(signature_hex) > 0


def test_verify_file_signature(dsa_encryption):
    """Тестуємо перевірку підпису для файлу"""
    file_path = "test_file.txt"
    with open(file_path, "w") as f:
        f.write("Це тестовий файл для підпису.")

    signature_hex = dsa_encryption.sign_file(file_path)
    DSAEncryption.save_signature(signature_hex, "file_signature_utest.txt")

    loaded_signature_hex = DSAEncryption.load_signature("file_signature_utest.txt")
    is_valid = DSAEncryption.verify_file_signature(dsa_encryption.public_key, file_path, loaded_signature_hex)
    assert is_valid


def test_save_and_load_private_key(dsa_encryption):
    """Тестуємо збереження та завантаження приватного ключа"""
    dsa_encryption.save_private_key("private_key_utest.pem")
    loaded_private_key = DSAEncryption.load_private_key("private_key_utest.pem")
    assert loaded_private_key is not None


def test_save_and_load_public_key(dsa_encryption):
    """Тестуємо збереження та завантаження публічного ключа"""
    dsa_encryption.save_public_key("public_key_utest.pem")
    loaded_public_key = DSAEncryption.load_public_key("public_key_utest.pem")
    assert loaded_public_key is not None


def test_verify_signature_fail(dsa_encryption):
    """Тестуємо випадок, коли перевірка підпису не проходить"""
    message = "Це тестове повідомлення."
    signature_hex = dsa_encryption.sign_message(message)
    wrong_message = "Це неправильне повідомлення."
    is_valid = DSAEncryption.verify_signature(dsa_encryption.public_key, wrong_message, signature_hex)
    assert not is_valid


def test_save_signature(dsa_encryption):
    """Тестуємо збереження підпису в файл"""
    message = "Це тестове повідомлення."
    signature_hex = dsa_encryption.sign_message(message)

    # Зберігаємо підпис у файл
    DSAEncryption.save_signature(signature_hex, "message_signature_utest.txt")

    # Перевіряємо, чи файл існує
    assert os.path.exists("message_signature_utest.txt")

    # Перевіряємо, чи збережено правильний підпис
    with open("message_signature_utest.txt", "r") as sig_file:
        saved_signature = sig_file.read()
    assert saved_signature == signature_hex


def test_load_signature(dsa_encryption):
    """Тестуємо завантаження підпису з файлу"""
    message = "Це тестове повідомлення."
    signature_hex = dsa_encryption.sign_message(message)

    # Зберігаємо підпис у файл
    DSAEncryption.save_signature(signature_hex, "message_signature_utest.txt")

    # Завантажуємо підпис із файлу
    loaded_signature_hex = DSAEncryption.load_signature("message_signature_utest.txt")

    # Перевіряємо, чи завантажений підпис збігається з оригіналом
    assert loaded_signature_hex == signature_hex


@pytest.fixture(autouse=True)
def cleanup_files():
    """Фікстура для очищення тестових файлів після кожного тесту"""
    test_files = [
        "private_key_utest.pem",
        "public_key_utest.pem",
        "message_signature_utest.txt",
        "file_signature_utest.txt",
        "test_file.txt"
    ]
    yield
    # Після тесту очищаємо файли
    for file in test_files:
        if os.path.exists(file):
            os.remove(file)
