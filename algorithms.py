"""Учебные алгоритмы Диффи — Хеллмана и обобщённых рюкзаков."""

from dataclasses import dataclass, field
from math import gcd, prod


ALPHABET = "abcdefghijklmnopqrstuvwxyz "
SYMBOL_CODES = {symbol: code for code, symbol in enumerate(ALPHABET)}
THRESHOLD = 14
MAX_DH_MODULUS = 2**32 - 1
PRIME_TEST_LIMIT = 318665857834031151167461
PRIME_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def is_prime(number: int) -> bool:
    """Детерминированная проверка Миллера — Рабина в указанном диапазоне."""
    if number >= PRIME_TEST_LIMIT:
        raise ValueError(
            f"Для проверки простоты число должно быть меньше {PRIME_TEST_LIMIT}."
        )
    if number < 2:
        return False
    for prime in PRIME_BASES:
        if number % prime == 0:
            return number == prime

    # Первые 12 простых оснований достаточны до PRIME_TEST_LIMIT (Sorenson–Webster).
    odd_part, power_of_two = number - 1, 0
    while odd_part % 2 == 0:
        odd_part //= 2
        power_of_two += 1

    for base in PRIME_BASES:
        residue = pow(base, odd_part, number)
        if residue in (1, number - 1):
            continue
        for _ in range(power_of_two - 1):
            residue = residue * residue % number
            if residue == number - 1:
                break
        else:
            return False
    return True


def prime_divisors(number: int):
    """Различные простые делители в порядке возрастания."""
    divisor = 2
    while divisor * divisor <= number:
        if number % divisor == 0:
            yield divisor
            while number % divisor == 0:
                number //= divisor
        divisor = 3 if divisor == 2 else divisor + 2
    if number > 1:
        yield number


@dataclass(frozen=True)
class Exchange:
    alice_public: int
    bob_public: int
    alice_secret: int
    bob_secret: int

    @property
    def matches(self) -> bool:
        return self.alice_secret == self.bob_secret


def diffie_hellman(q: int, g: int, a: int, b: int) -> Exchange:
    if not 5 <= q <= MAX_DH_MODULUS:
        raise ValueError(f"Модуль q должен быть от 5 до {MAX_DH_MODULUS}.")
    if not is_prime(q):
        raise ValueError("Модуль q должен быть простым числом.")
    for name, value in (("g", g), ("a", a), ("b", b)):
        if not 2 <= value <= q - 2:
            raise ValueError(f"Для {name} допустим диапазон 2…{q - 2}.")
    if any(pow(g, (q - 1) // factor, q) == 1 for factor in prime_divisors(q - 1)):
        raise ValueError(
            "Основание g должно порождать все ненулевые остатки по модулю q."
        )

    alice_public = pow(g, a, q)
    bob_public = pow(g, b, q)
    return Exchange(
        alice_public, bob_public, pow(bob_public, a, q), pow(alice_public, b, q)
    )


def validate_block_size(base: int, size: int) -> None:
    if base < 2:
        raise ValueError("Основание p должно быть не меньше 2.")
    largest_code = len(ALPHABET) - 1
    minimum_size = 0
    while largest_code:
        largest_code //= base
        minimum_size += 1
    if size < minimum_size:
        raise ValueError(
            f"Для этого p нужно не менее {minimum_size} весов W, чтобы кодировать весь алфавит."
        )


@dataclass(frozen=True)
class AdditiveKey:
    weights: tuple[int, ...]
    modulus: int
    multiplier: int
    base: int = THRESHOLD
    public_weights: tuple[int, ...] = field(init=False)
    inverse: int = field(init=False)

    def __post_init__(self) -> None:
        validate_block_size(self.base, len(self.weights))
        total = 0
        for weight in self.weights:
            if weight <= (self.base - 1) * total:
                raise ValueError(
                    "Каждый вес W должен превышать (p − 1) × сумму предыдущих."
                )
            total += weight
        if self.modulus <= (self.base - 1) * total:
            raise ValueError("Модуль m должен превышать (p − 1) × сумму весов W.")
        if gcd(self.multiplier, self.modulus) != 1:
            raise ValueError("Множитель a и модуль m должны быть взаимно простыми.")
        public = tuple(
            self.multiplier * weight % self.modulus for weight in self.weights
        )
        object.__setattr__(self, "public_weights", public)
        object.__setattr__(self, "inverse", pow(self.multiplier, -1, self.modulus))

    def encrypt_block(self, digits: tuple[int, ...]) -> int:
        return sum(weight * digit for weight, digit in zip(self.public_weights, digits))

    def decrypt_block(self, ciphertext: int) -> tuple[tuple[int, ...], int]:
        if ciphertext < 0:
            raise ValueError("ожидается неотрицательная сумма")
        private_sum = self.inverse * ciphertext % self.modulus
        remainder = private_sum
        reversed_digits = []
        for weight in reversed(self.weights):
            digit, remainder = divmod(remainder, weight)
            reversed_digits.append(digit)
        if remainder or any(digit >= self.base for digit in reversed_digits):
            raise ValueError(
                "сумма не раскладывается по закрытым весам с допустимыми коэффициентами"
            )

        digits = tuple(reversed(reversed_digits))
        if self.encrypt_block(digits) != ciphertext:
            raise ValueError(
                "число не равно сумме по открытому рюкзаку для восстановленного блока"
            )
        return digits, private_sum


@dataclass(frozen=True)
class MultiplicativeKey:
    weights: tuple[int, ...]
    modulus: int
    exponent: int
    base: int = THRESHOLD
    public_weights: tuple[int, ...] = field(init=False)
    inverse: int = field(init=False)

    def __post_init__(self) -> None:
        validate_block_size(self.base, len(self.weights))
        if len(set(self.weights)) != len(self.weights) or any(
            weight < 2 for weight in self.weights
        ):
            raise ValueError("Веса W должны быть различными простыми числами.")
        if self.modulus >= PRIME_TEST_LIMIT or not is_prime(self.modulus):
            raise ValueError(
                f"Модуль m должен быть простым числом меньше {PRIME_TEST_LIMIT}."
            )
        weight_product = prod(self.weights)
        max_digit = self.base - 1
        # Нижняя оценка размера степени позволяет отклонить слишком большое p без возведения в степень.
        if (
            (weight_product.bit_length() - 1) * max_digit >= self.modulus.bit_length()
            or self.modulus <= weight_product** max_digit
        ):
            raise ValueError(
                "Модуль m должен превышать произведение весов W в степени p − 1."
            )
        if not all(is_prime(weight) for weight in self.weights):
            raise ValueError("Веса W должны быть различными простыми числами.")
        if (
            not 1 < self.exponent < self.modulus - 1
            or gcd(self.exponent, self.modulus - 1) != 1
        ):
            raise ValueError(
                "Показатель s должен удовлетворять 1 < s < m − 1 и НОД(s, m − 1) = 1."
            )

        inverse = pow(self.exponent, -1, self.modulus - 1)
        public = tuple(pow(weight, inverse, self.modulus) for weight in self.weights)
        object.__setattr__(self, "public_weights", public)
        object.__setattr__(self, "inverse", inverse)

    def encrypt_block(self, digits: tuple[int, ...]) -> int:
        return (
            prod(
                pow(weight, digit, self.modulus)
                for weight, digit in zip(self.public_weights, digits)
            )
            % self.modulus
        )

    def decrypt_block(self, ciphertext: int) -> tuple[tuple[int, ...], int]:
        if not 1 <= ciphertext < self.modulus:
            raise ValueError("ожидается число от 1 до m − 1")
        private_product = pow(ciphertext, self.exponent, self.modulus)
        remainder = private_product
        digits = []
        for weight in self.weights:
            digit = 0
            while remainder % weight == 0:
                remainder //= weight
                digit += 1
            digits.append(digit)
        if remainder != 1 or any(digit >= self.base for digit in digits):
            raise ValueError(
                "произведение не раскладывается по закрытым простым весам с допустимыми степенями"
            )
        return tuple(digits), private_product


@dataclass(frozen=True)
class Block:
    symbol: str
    code: int
    digits: tuple[int, ...]
    ciphertext: int
    private_value: int | None = None


def encrypt(message: str, key: AdditiveKey | MultiplicativeKey) -> list[Block]:
    blocks = []
    for position, symbol in enumerate(message, start=1):
        if symbol not in SYMBOL_CODES:
            raise ValueError(
                f"Символ {symbol!r} в позиции {position}. Разрешены строчные a–z и пробел."
            )
        code = SYMBOL_CODES[symbol]
        remainder = code
        digits = [0] * len(key.public_weights)
        for index in range(len(digits) - 1, -1, -1):
            remainder, digits[index] = divmod(remainder, key.base)
        coefficients = tuple(digits)
        blocks.append(
            Block(symbol, code, coefficients, key.encrypt_block(coefficients))
        )
    return blocks


def decrypt(ciphertext: list[int], key: AdditiveKey | MultiplicativeKey) -> list[Block]:
    blocks = []
    for position, value in enumerate(ciphertext, start=1):
        try:
            digits, private_value = key.decrypt_block(value)
            code = 0
            for digit in digits:
                code = code * key.base + digit
            if code >= len(ALPHABET):
                raise ValueError(f"код {code} отсутствует в алфавите")
        except ValueError as error:
            raise ValueError(f"Блок {position}: {error}.") from error
        blocks.append(Block(ALPHABET[code], code, digits, value, private_value))
    return blocks
