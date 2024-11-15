import random

from ..labs.lab_1 import LinearCongruentialGenerator
from ..labs.cesaro import cesaro_test



# Тест для класу LinearCongruentialGenerator
def test_lcg_generate():
    lcg = LinearCongruentialGenerator()
    random_numbers = lcg.generate(9)
    assert len(random_numbers) == 10, "Кількість згенерованих чисел має бути 10 (враховуючи початкове значення)"
    assert random_numbers[0] == 8, "Перше число має бути X0 (8)"

def test_lcg_check_period():
    lcg = LinearCongruentialGenerator()
    lcg.generate(9)
    period = lcg.check_period()
    assert period > 0, "Період генератора має бути більшим за 0"

def test_lcg_next():
    lcg = LinearCongruentialGenerator()
    lcg.generate(9)
    first_next = lcg.next()
    second_next = lcg.next()
    assert first_next != second_next, "Наступні значення повинні бути різними"

def test_lcg_random_bytes():
    lcg = LinearCongruentialGenerator()
    random_bytes = lcg.random_bytes(10)
    assert len(random_bytes) == 10, "Має бути згенеровано 10 байт"
    assert isinstance(random_bytes, bytes), "Має бути тип bytes"

# Тест для cesaro_test
def test_cesaro_test():
    test_data = [random.randint(1, 100) for _ in range(100)]
    result = cesaro_test(test_data)

    assert isinstance(result, float), "Результат тесту має бути числом з плаваючою точкою"
    assert 0 <= result <= 4, "Результат тесту має бути в діапазоні [0, 4]"
