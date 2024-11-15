from hashlib import md5

from ..labs.lab_2 import pad_message, MD5, hash_file


# Тест для функції pad_message
def test_pad_message():
    # Тестове повідомлення
    msg = b"abc"
    padded_msg = pad_message(msg)

    # Перевіряємо, що довжина повідомлення після доповнення має бути кратною 512 біт
    assert len(padded_msg) * 8 % 512 == 0, "Довжина повідомлення після доповнення повинна бути кратною 512 біт"

    # Перевіряємо, чи додано 1 біт та довжину оригінального повідомлення в кінець
    assert padded_msg[-8:] == (len(msg) * 8).to_bytes(8,
                                                      'little'), "Останні 8 байт повинні містити довжину оригінального повідомлення"


# Тест для функції MD5
def test_MD5():
    # Тестове повідомлення
    msg = b"abc"

    # Очікуваний хеш для "abc"
    expected_hash = md5(msg).hexdigest()

    # Перевіряємо, що обчислений хеш співпадає з очікуваним
    assert MD5(msg) == expected_hash, "MD5 хеш для повідомлення не співпадає з очікуваним"


# Тест для функції hash_file
def test_hash_file(tmpdir):
    # Створюємо тимчасовий файл для тестування
    test_file = tmpdir.join("test_file.txt")

    # Записуємо тестове повідомлення у файл
    test_file.write("abc")

    # Викликаємо функцію hash_file для цього файлу
    computed_hash = hash_file(str(test_file))

    # Перевіряємо, що хеш файлу правильний
    expected_hash = md5(b"abc").hexdigest()
    assert computed_hash == expected_hash, "Хеш файлу не співпадає з очікуваним"

