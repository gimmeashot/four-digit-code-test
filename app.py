"""генератор четырёхзначного кода"""

import hmac
import ipaddress
import os
import secrets

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from security_store import (
    allow_login_attempt,
    consume_view_token,
    issue_view_token,
    revoke_view_token,
)


app = Flask(__name__)
# ключ подписывает cookie сессии
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.environ.get("RENDER")),
)


@app.before_request
def clear_legacy_private_code():
    # удаляем код из старых cookie сессии
    session.pop("last_private_code", None)


def new_code(previous=None):
    """код с ведущими нулями без повтора"""
    if previous is None:
        return f"{secrets.randbelow(10_000):04d}"
    # исключаем предыдущий код из диапазона
    number = secrets.randbelow(9_999)
    if number >= int(previous):
        number += 1
    return f"{number:04d}"


@app.after_request
def disable_cache(response):
    # запрет кэша для нового кода и выхода при обновлении
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.get("/")
def home():
    return render_template("menu.html")


@app.get("/public")
def public_code():
    code = next_public_code()
    return render_template("code.html", code=code, private=False)


def next_public_code():
    code = new_code(session.get("last_public_code"))
    # сохраняем код для исключения повтора
    session["last_public_code"] = code
    return code


@app.post("/api/code")
def api_code():
    return jsonify(code=next_public_code())


@app.route("/private", methods=["GET", "POST"])
def private_code():
    if request.method == "POST":
        revoke_view_token(session.pop("view_token", None))
        if not allow_login_attempt(login_client_ip()):
            return (
                render_template("login.html", error="Слишком много попыток. Повторите через минуту"),
                429,
                {"Retry-After": "60"},
            )
        username = os.environ.get("APP_USERNAME", "test")
        password = os.environ.get("APP_PASSWORD")
        valid = bool(password) and hmac.compare_digest(
            request.form.get("username", "").encode(), username.encode()
        ) and hmac.compare_digest(request.form.get("password", "").encode(), password.encode())
        if valid:
            session["view_token"] = issue_view_token()
            return redirect(url_for("private_code"), code=303)
        return render_template("login.html", error="Неверный логин или пароль"), 401

    # разрешение действует только на один показ
    if consume_view_token(session.pop("view_token", None)):
        return render_template("code.html", code=new_code(), private=True)
    return render_template("login.html", error=None)


def login_client_ip():
    if os.environ.get("RENDER"):
        # render получает адрес клиента от cloudflare
        candidate = request.headers.get("CF-Connecting-IP", "")
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            pass
    return request.remote_addr or "unknown"


@app.post("/logout")
def logout():
    revoke_view_token(session.get("view_token"))
    session.clear()
    return redirect(url_for("private_code"), code=303)


if __name__ == "__main__":
    app.run(debug=False)
