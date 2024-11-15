import random


m = 2**12 - 1
a = 4**5
c = 2
X0 = 8


# Реалізовуємо алгоритм Лемерома по заданій формулі
class LinearCongruentialGenerator:
    def __init__(self, seed=42):
        self.state = seed
        self.X0 = X0
        self.m = m
        self.a = a
        self.c = c

    def generate(self, n):
        randomNumbers = []
        x = self.X0
        randomNumbers.append(x)
        for _ in range(n):
            x = (self.a * x + self.c) % self.m
            randomNumbers.append(x)
        return randomNumbers

    def check_period(self):
        x0 = set()
        x = self.X0
        count = 0
        max_iterations = 1000000  # Максимальна кількість кроків для запобігання нескінченним циклам

        while x not in x0:
            x0.add(x)
            x = (self.a * x + self.c) % self.m
            count += 1

            if count > max_iterations:
                raise Exception("Перевищено максимальну кількість кроків при пошуку періоду")

        return count

    def next(self):
        self.state = (self.a * self.state + c) % self.m
        return self.state

    def random_bytes(self, n):
        return bytes(self.next() % 256 for _ in range(n))


# Використовуємо вбудовану функцію
def generate_system_random_numbers(n):
    return [random.randint(a, m) for _ in range(n)]
