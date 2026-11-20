"""Synthetic fixtures. Checksums are real; the people are not."""

from __future__ import annotations

import random


def generate_tckn(rng: random.Random) -> str:
    digits = [rng.randint(1, 9)]
    digits.extend(rng.randint(0, 9) for _ in range(8))
    odd = sum(digits[i] for i in range(0, 9, 2))
    even = sum(digits[i] for i in range(1, 8, 2))
    digits.append((odd * 7 - even) % 10)
    digits.append(sum(digits) % 10)
    return "".join(str(digit) for digit in digits)


def iban_check_digits(country: str, bban: str) -> str:
    rearranged = bban + country + "00"
    pieces: list[str] = []
    for char in rearranged:
        if char.isdigit():
            pieces.append(char)
        else:
            pieces.append(str(ord(char) - 55))
    return f"{98 - (int(''.join(pieces)) % 97):02d}"


def generate_tr_iban(rng: random.Random) -> str:
    bank = "".join(str(rng.randint(0, 9)) for _ in range(5))
    account = "".join(str(rng.randint(0, 9)) for _ in range(16))
    bban = bank + str(rng.randint(0, 9)) + account
    return "TR" + iban_check_digits("TR", bban) + bban


def with_luhn(payload: str) -> str:
    total = 0
    for index, char in enumerate(reversed(payload)):
        digit = int(char)
        if index % 2 == 0:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return payload + str((10 - (total % 10)) % 10)


def grouped(number: str, size: int = 4, sep: str = " ") -> str:
    return sep.join(number[index : index + size] for index in range(0, len(number), size))


KNOWN_TCKN = "10000000146"
NEGATIVE_MOD_TCKN = "19090909018"
VISA_16 = "4111111111111111"
