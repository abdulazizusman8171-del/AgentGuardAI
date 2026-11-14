import unittest
from pydantic import ValidationError

from app.auth_models import (
    RegistrationRequest,
    EmailVerificationRequest,
)


class TestAuthModels(unittest.TestCase):

    def test_valid_registration(self):
        request = RegistrationRequest(
            email="user@example.com",
            password="StrongPassword123!"
        )
        self.assertEqual(request.email, "user@example.com")

    def test_short_password_rejected(self):
        with self.assertRaises(ValidationError):
            RegistrationRequest(
                email="user@example.com",
                password="short"
            )

    def test_empty_email_rejected(self):
        with self.assertRaises(ValidationError):
            RegistrationRequest(
                email="",
                password="StrongPassword123!"
            )

    def test_valid_verification_token(self):
        request = EmailVerificationRequest(
            token="a" * 32
        )
        self.assertEqual(len(request.token), 32)

    def test_short_verification_token_rejected(self):
        with self.assertRaises(ValidationError):
            EmailVerificationRequest(token="short")


if __name__ == "__main__":
    unittest.main()
