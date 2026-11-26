import unittest

from algorithms import (
    ALPHABET,
    AdditiveKey,
    MultiplicativeKey,
    decrypt,
    diffie_hellman,
    encrypt,
    is_prime,
)


ADDITIVE = AdditiveKey((2, 29), 409, 31)
MULTIPLICATIVE = MultiplicativeKey((2, 3), 13060694051, 11)


class DiffieHellmanTests(unittest.TestCase):
    def test_report_examples(self):
        for bob_exponent, expected in ((7, (8, 17, 12, 12)), (8, (8, 16, 4, 4))):
            with self.subTest(b=bob_exponent):
                exchange = diffie_hellman(23, 5, 6, bob_exponent)
                self.assertEqual(
                    (
                        exchange.alice_public,
                        exchange.bob_public,
                        exchange.alice_secret,
                        exchange.bob_secret,
                    ),
                    expected,
                )
                self.assertTrue(exchange.matches)

    def test_rejects_invalid_parameters(self):
        for parameters in (
            (21, 5, 6, 7),
            (7, 2, 3, 4),
            (23, 1, 6, 7),
            (23, 5, 1, 7),
            (23, 5, 6, 22),
        ):
            with self.subTest(parameters=parameters), self.assertRaises(ValueError):
                diffie_hellman(*parameters)


class KnapsackTests(unittest.TestCase):
    def assert_example(self, key, public_weights, ciphertext, private_values):
        self.assertEqual(key.public_weights, public_weights)
        self.assertEqual([block.ciphertext for block in encrypt("hi", key)], ciphertext)
        decoded = decrypt(ciphertext, key)
        self.assertEqual([block.private_value for block in decoded], private_values)
        self.assertEqual("".join(block.symbol for block in decoded), "hi")

    def test_additive_example_base_14(self):
        self.assert_example(ADDITIVE, (62, 81), [567, 648], [203, 232])

    def test_multiplicative_example_base_14(self):
        self.assert_example(
            MULTIPLICATIVE,
            (11380751744, 4294346720),
            [5957337453, 8496292532],
            [2187, 6561],
        )
        self.assertEqual(
            tuple(
                pow(weight, MULTIPLICATIVE.exponent, MULTIPLICATIVE.modulus)
                for weight in MULTIPLICATIVE.public_weights
            ),
            MULTIPLICATIVE.weights,
        )

    def test_additive_example_base_3_from_report(self):
        key = AdditiveKey((2, 5, 16, 50), 149, 31, base=3)
        self.assert_example(key, (62, 6, 49, 60), [158, 218], [82, 132])

    def test_multiplicative_example_base_3_with_corrected_arithmetic(self):
        key = MultiplicativeKey((2, 3, 5), 1009, 5, base=3)
        self.assert_example(key, (328, 738, 659), [934, 16], [45, 225])

    def test_all_symbols_including_leading_repeated_and_trailing_spaces(self):
        message = "  " + ALPHABET + " a  "
        for key in (ADDITIVE, MULTIPLICATIVE):
            with self.subTest(key=type(key)):
                encoded = encrypt(message, key)
                self.assertEqual(
                    len(set(block.ciphertext for block in encoded)), len(ALPHABET)
                )
                self.assertEqual(encoded[1].digits, (1, 12))
                self.assertEqual(encoded[16].digits, (1, 0))  # o → 14
                decoded = decrypt([block.ciphertext for block in encoded], key)
                self.assertEqual(
                    [block.digits for block in decoded],
                    [block.digits for block in encoded],
                )
                self.assertEqual("".join(block.symbol for block in decoded), message)

    def test_empty_message_and_invalid_characters(self):
        for key in (ADDITIVE, MULTIPLICATIVE):
            with self.subTest(key=type(key)):
                self.assertEqual(encrypt("", key), [])
                self.assertEqual(decrypt([], key), [])
                for message in ("Hi", "привет", "a\nb", "hi!"):
                    with self.assertRaisesRegex(ValueError, "позиции"):
                        encrypt(message, key)

    def test_invalid_keys(self):
        for key_type, parameters in (
            (AdditiveKey, ((2,), 409, 31)),
            (AdditiveKey, ((2, 26), 409, 31)),
            (AdditiveKey, ((2, 29), 403, 31)),
            (AdditiveKey, ((2, 29), 405, 15)),
            (MultiplicativeKey, ((2, 2), 13060694051, 11)),
            (MultiplicativeKey, ((2, 4), 10**13 + 37, 11)),
            (MultiplicativeKey, ((2, 3), 13060694053, 11)),
            (MultiplicativeKey, ((2, 3), 1009, 11)),
            (MultiplicativeKey, ((2, 3), 13060694051, 5)),
        ):
            with (
                self.subTest(key=key_type, parameters=parameters),
                self.assertRaises(ValueError),
            ):
                key_type(*parameters)

    def test_invalid_ciphertexts(self):
        for key, invalid in (
            (ADDITIVE, [-1, 1, 567 + 409, 62 + 13 * 81]),
            (MULTIPLICATIVE, [-1, 0, 2, MULTIPLICATIVE.modulus]),
        ):
            for ciphertext in invalid:
                with self.subTest(key=type(key), ciphertext=ciphertext):
                    with self.assertRaisesRegex(ValueError, "Блок 2"):
                        decrypt([key.encrypt_block((0, 0)), ciphertext], key)

    def test_primality_for_large_numbers(self):
        self.assertTrue(is_prime(18446744073709551557))
        self.assertFalse(is_prime(3825123056546413051))
        self.assertFalse(is_prime(1))


if __name__ == "__main__":
    unittest.main()
