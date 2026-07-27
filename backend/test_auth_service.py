"""
Unit tests for auth.auth_service.

NOTE: requires the full backend dependency set (SQLAlchemy in particular).
Run with:
    cd backend && python -m unittest test_auth_service.py -v

Uses a temporary SQLite file per test run (via NIDS_DATA_DIR) so it never
touches your real app.db.
"""

import os
import sys
import shutil
import tempfile
import unittest

# Point the app at a scratch data directory BEFORE importing appconfig,
# since appconfig resolves and creates its paths at import time.
_TEST_DATA_DIR = tempfile.mkdtemp(prefix="nids_test_")
os.environ["NIDS_DATA_DIR"] = _TEST_DATA_DIR

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from auth.auth_service import (  # noqa: E402
    AuthError,
    register_user,
    login_local,
    generate_token,
    verify_token,
    validate_dummy_card,
    detect_card_brand,
)


class TestRegistrationAndLogin(unittest.TestCase):
    def setUp(self):
        self._counter = getattr(TestRegistrationAndLogin, "_counter", 0) + 1
        TestRegistrationAndLogin._counter = self._counter
        self.username = f"testuser{self._counter}"
        self.email = f"test{self._counter}@example.com"
        self.password = "correcthorse1"

    def test_register_and_login(self):
        user = register_user(self.username, self.email, self.password)
        self.assertEqual(user.tier, "free")
        self.assertEqual(user.auth_provider, "local")
        self.assertNotEqual(user.password_hash, self.password)  # never stored in plaintext

        logged_in = login_local(self.email, self.password)
        self.assertEqual(logged_in.id, user.id)

    def test_duplicate_email_rejected(self):
        register_user(self.username, self.email, self.password)
        with self.assertRaises(AuthError):
            register_user(self.username + "2", self.email, self.password)

    def test_wrong_password_rejected(self):
        register_user(self.username, self.email, self.password)
        with self.assertRaises(AuthError):
            login_local(self.email, "wrongpassword1")

    def test_weak_password_rejected(self):
        with self.assertRaises(AuthError):
            register_user(self.username, self.email, "short")

    def test_password_without_number_rejected(self):
        with self.assertRaises(AuthError):
            register_user(self.username, self.email, "onlylettershere")

    def test_jwt_round_trip(self):
        user = register_user(self.username, self.email, self.password)
        token = generate_token(user)
        payload = verify_token(token)
        self.assertEqual(payload["sub"], user.id)
        self.assertEqual(payload["email"], self.email)

    def test_invalid_jwt_rejected(self):
        self.assertIsNone(verify_token("not.a.valid.token"))


class TestDummyCardValidation(unittest.TestCase):
    def test_valid_visa_test_number(self):
        result = validate_dummy_card("4111 1111 1111 1111", 12, 2030, "123")
        self.assertEqual(result["brand"], "Visa")
        self.assertEqual(result["last4"], "1111")

    def test_valid_mastercard_test_number(self):
        result = validate_dummy_card("5555 5555 5555 4444", 12, 2030, "123")
        self.assertEqual(result["brand"], "Mastercard")

    def test_luhn_failure_rejected(self):
        with self.assertRaises(AuthError):
            validate_dummy_card("4111 1111 1111 1112", 12, 2030, "123")

    def test_expired_card_rejected(self):
        with self.assertRaises(AuthError):
            validate_dummy_card("4111 1111 1111 1111", 1, 2020, "123")

    def test_detect_brand(self):
        self.assertEqual(detect_card_brand("4111111111111111"), "Visa")
        self.assertEqual(detect_card_brand("341111111111111"), "Amex")


def tearDownModule():
    shutil.rmtree(_TEST_DATA_DIR, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
