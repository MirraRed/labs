import math


# Функція для доповнення повідомлення
def pad_message(msg):
    original_bit_len = len(msg) * 8

    # Додаємо 1 біт
    msg += b'\x80'

    # Додаємо нулі
    while (len(msg) * 8) % 512 != 448:
        msg += b'\x00'

    # Додаємо довжину оригінального повідомлення
    msg += original_bit_len.to_bytes(8, 'little')
    return msg


# Функція для обчислення MD5
def MD5(msg):
    # Ініціалізація буферів
    A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    # Константи
    T = [int(abs(math.sin(i + 1)) * 2 ** 32) & 0xFFFFFFFF for i in range(64)]

    # Функція зсуву
    def left_rotate(x, amount):
        x &= 0xFFFFFFFF
        return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF

    # Порядок зсувів для кожного циклу
    shifts = [
        [7, 12, 17, 22],  # Перша група
        [5, 9, 14, 20],   # Друга група
        [4, 11, 16, 23],  # Третя група
        [6, 10, 15, 21]   # Четверта група
    ]

    # Обробка блоків
    msg = pad_message(msg)
    for i in range(0, len(msg), 64):
        block = msg[i:i + 64]
        M = [int.from_bytes(block[j:j + 4], byteorder='little') for j in range(0, 64, 4)]

        AA, BB, CC, DD = A, B, C, D

        for j in range(64):
            if j < 16:
                F = (B & C) | (~B & D)
                g = j
                s = shifts[0][j % 4]
            elif j < 32:
                F = (D & B) | (~D & C)
                g = (5 * j + 1) % 16
                s = shifts[1][j % 4]
            elif j < 48:
                F = B ^ C ^ D
                g = (3 * j + 5) % 16
                s = shifts[2][j % 4]
            else:
                F = C ^ (B | ~D)
                g = (7 * j) % 16
                s = shifts[3][j % 4]

            temp = D
            D = C
            C = B
            B = (B + left_rotate(A + F + M[g] + T[j], s)) & 0xFFFFFFFF
            A = temp

        # Додаємо до буферів
        A = (A + AA) & 0xFFFFFFFF
        B = (B + BB) & 0xFFFFFFFF
        C = (C + CC) & 0xFFFFFFFF
        D = (D + DD) & 0xFFFFFFFF

    # Форматування результату
    return ''.join('{:02x}'.format(x) for x in
                   A.to_bytes(4, 'little') + B.to_bytes(4, 'little') + C.to_bytes(4, 'little') + D.to_bytes(4, 'little'))

# Функція для обчислення MD5 для файлу
def hash_file(file_path):
    with open(file_path, 'rb') as f:  # Відкриваємо файл у двійковому режимі
        file_content = f.read()
        return MD5(file_content)
