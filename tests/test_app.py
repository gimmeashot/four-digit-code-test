import os
import re
import unittest
import uuid
from unittest.mock import patch

from app import app, new_code


def extract_code(response):
    match = re.search(rb'class="code"[^>]*>(\d{4})</div>', response.data)
    return match.group(1).decode() if match else None


class CodeServiceTests(unittest.TestCase):
    def setUp(self):
        self.state_file = os.path.join(os.path.dirname(__file__), "..", ".state", f"test-{uuid.uuid4().hex}.sqlite3")
        self.state_path = patch("security_store.STATE_DB_PATH", self.state_file)
        self.state_path.start()
        self.client = app.test_client()

    def tearDown(self):
        self.state_path.stop()
        if os.path.exists(self.state_file):
            os.remove(self.state_file)

    def test_menu_links_to_both_code_flows(self):
        menu = self.client.get("/")
        self.assertEqual(menu.status_code, 200)
        self.assertIsNone(extract_code(menu))
        self.assertIn(b'href="/public"', menu.data)
        self.assertIn(b'href="/private"', menu.data)

    def test_public_refresh_changes_four_digit_code(self):
        first = self.client.get("/public")
        second = self.client.get("/public")
        self.assertRegex(extract_code(first), r"^\d{4}$")
        self.assertRegex(extract_code(second), r"^\d{4}$")
        self.assertNotEqual(extract_code(first), extract_code(second))
        self.assertIn("no-store", second.headers["Cache-Control"])

    def test_public_button_requests_new_code(self):
        page = self.client.get("/public")
        self.assertIn("Обновить код".encode(), page.data)
        self.assertNotIn("Задание".encode(), page.data)
        refreshed = self.client.post("/api/code")
        self.assertEqual(refreshed.status_code, 200)
        self.assertRegex(refreshed.json["code"], r"^\d{4}$")
        self.assertNotEqual(extract_code(page), refreshed.json["code"])
        self.assertIn("no-store", refreshed.headers["Cache-Control"])

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
            self.assertIn("Выйти".encode(), shown.data)

            refreshed = self.client.get("/private")
            self.assertEqual(refreshed.status_code, 200)
            self.assertIsNone(extract_code(refreshed))
            self.assertIn("Вход".encode(), refreshed.data)

    def test_logout_button_returns_to_login(self):
        with patch.dict(os.environ, {"APP_USERNAME": "demo", "APP_PASSWORD": "test-pass"}):
            self.client.post("/private", data={"username": "demo", "password": "test-pass"})
            self.client.get("/private")
            result = self.client.post("/logout", follow_redirects=True)
            self.assertEqual(result.status_code, 200)
            self.assertIsNone(extract_code(result))
            self.assertIn("Вход".encode(), result.data)
            self.assertIsNone(extract_code(self.client.get("/private")))

    def test_saved_login_cookie_cannot_reopen_code(self):
        with patch.dict(os.environ, {"APP_USERNAME": "demo", "APP_PASSWORD": "test-pass"}):
            self.client.post("/private", data={"username": "demo", "password": "test-pass"})
            saved_cookie = self.client.get_cookie("session").value
            self.assertIsNotNone(extract_code(self.client.get("/private")))

            replay = app.test_client()
            replay.set_cookie("session", saved_cookie)
            self.assertIsNone(extract_code(replay.get("/private")))

            self.client.post("/private", data={"username": "demo", "password": "test-pass"})
            pending_cookie = self.client.get_cookie("session").value
            self.client.post("/logout")
            replay.set_cookie("session", pending_cookie)
            self.assertIsNone(extract_code(replay.get("/private")))

    def test_login_attempts_are_limited(self):
        with patch.dict(os.environ, {"APP_USERNAME": "demo", "APP_PASSWORD": "test-pass"}):
            with patch("security_store.time.time", return_value=1000):
                for _ in range(10):
                    response = self.client.post("/private", data={"username": "demo", "password": "wrong"})
                    self.assertEqual(response.status_code, 401)
                blocked = self.client.post("/private", data={"username": "demo", "password": "test-pass"})
                self.assertEqual(blocked.status_code, 429)
                self.assertEqual(blocked.headers["Retry-After"], "60")

            with patch("security_store.time.time", return_value=1061):
                allowed = self.client.post("/private", data={"username": "demo", "password": "test-pass"})
                self.assertEqual(allowed.status_code, 303)

    def test_one_client_cannot_block_another_client(self):
        with patch.dict(os.environ, {"APP_USERNAME": "demo", "APP_PASSWORD": "test-pass", "RENDER": "true"}):
            attacker = app.test_client()
            visitor = app.test_client()
            for _ in range(10):
                response = attacker.post(
                    "/private",
                    data={"username": "demo", "password": "wrong"},
                    headers={"CF-Connecting-IP": "198.51.100.10"},
                )
                self.assertEqual(response.status_code, 401)
            blocked = attacker.post(
                "/private",
                data={"username": "demo", "password": "test-pass"},
                headers={"CF-Connecting-IP": "198.51.100.10"},
            )
            self.assertEqual(blocked.status_code, 429)
            allowed = visitor.post(
                "/private",
                data={"username": "demo", "password": "test-pass"},
                headers={"CF-Connecting-IP": "198.51.100.11"},
            )
            self.assertEqual(allowed.status_code, 303)

    def test_private_code_is_not_stored_in_cookie(self):
        with patch.dict(os.environ, {"APP_USERNAME": "demo", "APP_PASSWORD": "test-pass"}):
            self.client.get("/public")
            self.client.post("/private", data={"username": "demo", "password": "test-pass"})
            shown = self.client.get("/private")
            code = extract_code(shown)
            cookie = self.client.get_cookie("session").value
            contents = app.session_interface.get_signing_serializer(app).loads(cookie)
            self.assertNotIn("last_private_code", contents)

            with self.client.session_transaction() as old_session:
                old_session["last_private_code"] = code
            self.client.get("/private")
            cookie = self.client.get_cookie("session").value
            contents = app.session_interface.get_signing_serializer(app).loads(cookie)
            self.assertNotIn("last_private_code", contents)

    def test_non_ascii_login_input_does_not_crash(self):
        with patch.dict(os.environ, {"APP_USERNAME": "demo", "APP_PASSWORD": "test-pass"}):
            for username, password in [("тест", "x"), ("demo", "пароль")]:
                response = self.client.post("/private", data={"username": username, "password": password})
                self.assertEqual(response.status_code, 401)

        with patch.dict(os.environ, {"APP_USERNAME": "тест", "APP_PASSWORD": "пароль"}):
            response = self.client.post("/private", data={"username": "тест", "password": "пароль"})
            self.assertEqual(response.status_code, 303)


if __name__ == "__main__":
    unittest.main()
