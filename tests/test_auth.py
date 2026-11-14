import unittest

from app.auth import (
    hash_password,
    verify_password,
    generate_session_token,
    hash_token,
    generate_approval_key,
    verify_approval_key,
)


class AuthenticationTests(unittest.TestCase):

    def test_password_hash_and_verification(self):
        password = "SecurePassword123!"
        password_hash, salt = hash_password(password)

        self.assertTrue(
            verify_password(password, password_hash, salt)
        )

    def test_wrong_password_rejected(self):
        password_hash, salt = hash_password("SecurePassword123!")

        self.assertFalse(
            verify_password("WrongPassword123!", password_hash, salt)
        )

    def test_passwords_receive_unique_salts(self):
        first = hash_password("SecurePassword123!")
        second = hash_password("SecurePassword123!")

        self.assertNotEqual(first[1], second[1])

    def test_short_password_rejected(self):
        with self.assertRaises(ValueError):
            hash_password("short")

    def test_session_tokens_are_unique(self):
        first = generate_session_token()
        second = generate_session_token()

        self.assertNotEqual(first, second)

    def test_token_hashing_is_consistent(self):
        token = generate_session_token()

        self.assertEqual(hash_token(token), hash_token(token))
        self.assertNotEqual(hash_token(token), token)

    def test_approval_keys_are_unique(self):
        self.assertNotEqual(
            generate_approval_key(),
            generate_approval_key()
        )

    def test_approval_key_verification(self):
        key = generate_approval_key()
        stored_hash = hash_token(key)

        self.assertTrue(verify_approval_key(key, stored_hash))

    def test_wrong_approval_key_rejected(self):
        key = generate_approval_key()
        stored_hash = hash_token(key)

        self.assertFalse(
            verify_approval_key("wrong-key", stored_hash)
        )


if __name__ == "__main__":
    unittest.main()
