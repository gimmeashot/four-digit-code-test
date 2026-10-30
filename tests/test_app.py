import os
import re
import unittest
from unittest.mock import patch

from app import app, new_code


def extract_code(response):
    match = re.search(rb'class="code"[^>]*>(\d{4})</div>', response.data)
    return match.group(1).decode() if match else None


class CodeServiceTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_public_refresh_changes_four_digit_code(self):
        first = self.client.get("/")
        second = self.client.get("/")
        self.assertRegex(extract_code(first), r"^\d{4}$")
        self.assertRegex(extract_code(second), r"^\d{4}$")
        self.assertNotEqual(extract_code(first), extract_code(second))
        self.assertIn("no-store", second.headers["Cache-Control"])

    def test_leading_zeroes_are_kept(self):
        with patch("app.secrets.randbelow", return_value=42):
            self.assertEqual(new_code(), "0042")

    def test_private_code_requires_login_and_refresh_logs_out(self):
        with patch.dict(os.environ, {"APP_USERNAME": "demo", "APP_PASSWORD": "test-pass"}):
            self.assertIsNone(extract_code(self.client.get("/private")))
            denied = self.client.post("/private", data={"username": "demo", "password": "wrong"})
            self.assertEqual(denied.status_code, 401)
            self.assertIsNone(extract_code(denied))

            login = self.client.post("/private", data={"username": "demo", "password": "test-pass"})
            self.assertEqual(login.status_code, 303)
            shown = self.client.get(login.headers["Location"])
            self.assertRegex(extract_code(shown), r"^\d{4}$")

            refreshed = self.client.get("/private")
            self.assertEqual(refreshed.status_code, 200)
            self.assertIsNone(extract_code(refreshed))
            self.assertIn("Вход".encode(), refreshed.data)


if __name__ == "__main__":
    unittest.main()
