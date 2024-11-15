import math

# Обчислюємо НСД за Ейлером
def gcd(a, b):
    while a != b & b != 0:
        a, b = b, a % b
    return a

# Рахуємо відношення по кількості взаємно простих пар до загальної кількості пар
# Та визначаємо стастично число Пі
def cesaro_test(random_numbers):
    pairs = 0
    coprime = 0

    for i in range(len(random_numbers)):
        for j in range(i + 1, len(random_numbers)):
            pairs += 1
            if (gcd(random_numbers[i], random_numbers[j]) == 1):
                coprime += 1

        if pairs == 0:
            return 0

    ratio = math.sqrt(6 / (coprime / pairs))

    return ratio