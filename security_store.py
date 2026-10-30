"""серверное состояние входа"""

import hashlib
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager


LOGIN_WINDOW_SECONDS = 60
MAX_LOGIN_ATTEMPTS = 10
VIEW_TOKEN_SECONDS = 300
STATE_DB_PATH = os.environ.get("STATE_DB_PATH") or os.path.join(
    os.path.dirname(__file__), ".state", "state.sqlite3"
)


@contextmanager
def state_db():
    os.makedirs(os.path.dirname(STATE_DB_PATH), exist_ok=True)
    db = sqlite3.connect(STATE_DB_PATH, timeout=5)
    try:
        db.execute(
            "CREATE TABLE IF NOT EXISTS login_attempts (created_at REAL NOT NULL)"
        )
        db.execute(
            "CREATE TABLE IF NOT EXISTS view_tokens (token_hash TEXT PRIMARY KEY, expires_at REAL NOT NULL)"
        )
        yield db
    finally:
        db.close()


def allow_login_attempt():
    now = time.time()
    with state_db() as db:
        with db:
            # блокировка делает подсчёт попыток атомарным
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM login_attempts WHERE created_at <= ?", (now - LOGIN_WINDOW_SECONDS,))
            count = db.execute("SELECT COUNT(*) FROM login_attempts").fetchone()[0]
            if count >= MAX_LOGIN_ATTEMPTS:
                return False
            db.execute("INSERT INTO login_attempts (created_at) VALUES (?)", (now,))
            return True


def issue_view_token():
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = time.time()
    with state_db() as db:
        with db:
            db.execute("DELETE FROM view_tokens WHERE expires_at <= ?", (now,))
            db.execute(
                "INSERT INTO view_tokens (token_hash, expires_at) VALUES (?, ?)",
                (token_hash, now + VIEW_TOKEN_SECONDS),
            )
    return token


def consume_view_token(token):
    if not token:
        return False
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with state_db() as db:
        with db:
            # удаление допускает только один успешный запрос
            deleted = db.execute(
                "DELETE FROM view_tokens WHERE token_hash = ? AND expires_at > ?",
                (token_hash, time.time()),
            )
            return deleted.rowcount == 1


def revoke_view_token(token):
    if not token:
        return
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with state_db() as db:
        with db:
            db.execute("DELETE FROM view_tokens WHERE token_hash = ?", (token_hash,))
