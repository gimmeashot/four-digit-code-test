"""Two small four-digit-code demos."""

import hmac
import os
import secrets

from flask import Flask, redirect, render_template, request, session, url_for


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.environ.get("RENDER")),
)


def new_code(previous=None):
    """Keep leading zeroes and avoid repeating the previous visible code."""
    if previous is None:
        return f"{secrets.randbelow(10_000):04d}"
    number = secrets.randbelow(9_999)
    if number >= int(previous):
        number += 1
    return f"{number:04d}"


@app.after_request
def disable_cache(response):
    # A refresh must request a new page, and Back must not reveal an old code.
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.get("/")
def public_code():
    code = new_code(session.get("last_public_code"))
    session["last_public_code"] = code
    return render_template("code.html", code=code, private=False)


@app.route("/private", methods=["GET", "POST"])
def private_code():
    if request.method == "POST":
        session.pop("can_view_code", None)
        username = os.environ.get("APP_USERNAME", "demo")
        password = os.environ.get("APP_PASSWORD")
        valid = bool(password) and hmac.compare_digest(
            request.form.get("username", ""), username
        ) and hmac.compare_digest(request.form.get("password", ""), password)
        if valid:
            session["can_view_code"] = True
            return redirect(url_for("private_code"), code=303)
        return render_template("login.html", error="Неверный логин или пароль"), 401

    if session.pop("can_view_code", False):
        code = new_code(session.get("last_private_code"))
        session["last_private_code"] = code
        return render_template("code.html", code=code, private=True)
    return render_template("login.html", error=None)


if __name__ == "__main__":
    app.run(debug=False)
