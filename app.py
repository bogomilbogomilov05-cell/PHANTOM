
from flask import (
    Flask,
    render_template,
    render_template_string,
    request,
    redirect,
    url_for,
    session
)
import sqlite3
import smtplib
import os
import secrets

from pathlib import Path
from datetime import datetime, timedelta
from email.message import EmailMessage
from dotenv import load_dotenv


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env", override=True)

app = Flask(__name__)

DATABASE = BASE_DIR / "phantom.db"

SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
ADMIN_PASSWORD = os.getenv("PHANTOM_ADMIN_PASSWORD")

SENDER_EMAIL = os.getenv("PHANTOM_GMAIL")
APP_PASSWORD = os.getenv("PHANTOM_GMAIL_APP_PASSWORD")
RECIPIENT_EMAIL = os.getenv("PHANTOM_RECIPIENT")

if not SECRET_KEY:
    raise RuntimeError("Missing FLASK_SECRET_KEY in .env")

if not ADMIN_PASSWORD:
    raise RuntimeError("Missing PHANTOM_ADMIN_PASSWORD in .env")

app.secret_key = SECRET_KEY

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # Localhost development only
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)


# --------------------------------------------------
# DATABASE
# --------------------------------------------------

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                test_code TEXT NOT NULL,
                action TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)
init_db()

# --------------------------------------------------
# EMAIL REPORT
# --------------------------------------------------

def send_email_report(event_id, username, test_code, action, timestamp):

    if not SENDER_EMAIL or not APP_PASSWORD or not RECIPIENT_EMAIL:
        print("EMAIL ERROR: Gmail configuration is missing.")
        return False

    message = EmailMessage()

    message["Subject"] = f"Security Awareness Report - Event #{event_id}"
    message["From"] = SENDER_EMAIL
    message["To"] = RECIPIENT_EMAIL

    message.set_content(f"""
SECURITY AWARENESS REPORT

A demonstration form submission has been recorded.

EVENT INFORMATION
-----------------
Event ID: {event_id}
Demonstration username: {username}
Demonstration code: {test_code}
Action: {action}
Date and time: {timestamp}

DATABASE STATUS
---------------
Successfully saved in SQLite.

Use fictional demonstration data only.

""")

    try:
        with smtplib.SMTP_SSL(
            "smtp.gmail.com",
            465,
            timeout=20
        ) as smtp:

            smtp.login(SENDER_EMAIL, APP_PASSWORD)
            smtp.send_message(message)

        print(f"EMAIL SENT: Event #{event_id}")
        return True

    except Exception as error:
        print(f"EMAIL ERROR: {type(error).__name__}: {error}")
        return False


# --------------------------------------------------
# CSRF TOKEN
# --------------------------------------------------

def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    return session["csrf_token"]


def valid_csrf_token():
    submitted_token = request.form.get("csrf_token", "")
    stored_token = session.get("csrf_token", "")

    return (
        bool(submitted_token)
        and bool(stored_token)
        and secrets.compare_digest(submitted_token, stored_token)
    )


# --------------------------------------------------
# PUBLIC CONFIRMATION PAGE
# --------------------------------------------------

SUCCESS_PAGE = """
<!DOCTYPE html>
<html lang="bg">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Потвърждение</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #f0f2f5;
            font-family: Arial, sans-serif;
            color: #1c1e21;
        }

        .confirmation {
            width: 90%;
            max-width: 430px;
            padding: 38px 28px;
            background: white;
            border-radius: 12px;
            box-shadow: 0 2px 12px rgba(0, 0, 0, 0.10);
            text-align: center;
        }

        .check {
            width: 62px;
            height: 62px;
            margin: 0 auto 22px;
            border-radius: 50%;
            background: #e7f3ff;
            color: #1877f2;
            font-size: 36px;
            line-height: 62px;
            font-weight: bold;
        }

        h1 {
            font-size: 23px;
            margin-bottom: 12px;
        }

        p {
            color: #606770;
            font-size: 15px;
            line-height: 1.5;
        }
    </style>
</head>

<body>
    <main class="confirmation">
        <div class="check">&#10003;</div>
        <h1>Потвърждението е успешно.</h1>
        <p>Вашето действие беше обработено успешно.</p>
    </main>
</body>
</html>
"""


# --------------------------------------------------
# ADMIN LOGIN PAGE
# --------------------------------------------------

LOGIN_PAGE = """
<!DOCTYPE html>
<html lang="bg">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Администраторски вход</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #f0f2f5;
            font-family: Arial, sans-serif;
            color: #1c1e21;
        }

        .login {
            width: 90%;
            max-width: 390px;
            padding: 30px;
            background: white;
            border-radius: 12px;
            box-shadow: 0 2px 12px rgba(0, 0, 0, 0.10);
        }

        h1 {
            text-align: center;
            font-size: 23px;
            margin-top: 0;
        }

        input {
            width: 100%;
            padding: 14px;
            margin: 12px 0;
            border: 1px solid #ccd0d5;
            border-radius: 7px;
            font-size: 16px;
        }

        button {
            width: 100%;
            padding: 13px;
            border: none;
            border-radius: 7px;
            background: #1877f2;
            color: white;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
        }

        button:hover {
            background: #166fe5;
        }

        .error {
            color: #c62828;
            text-align: center;
            font-size: 14px;
        }
    </style>
</head>

<body>
    <main class="login">
        <h1>Администраторски вход</h1>

        {% if error %}
            <p class="error">{{ error }}</p>
        {% endif %}

        <form method="POST">
            <input
                type="hidden"
                name="csrf_token"
                value="{{ csrf_token }}"
            >

            <input
                type="password"
                name="password"
                placeholder="Администраторска парола"
                required
                autocomplete="current-password"
            >

            <button type="submit">Вход</button>
        </form>
    </main>
</body>
</html>
"""


# --------------------------------------------------
# PUBLIC ROUTES
# --------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/record", methods=["POST"])
def record():

    username = request.form.get("username", "").strip()
    test_code = request.form.get("test_code", "").strip()

    if not username or not test_code:
        return "Моля, попълнете демонстрационните полета.", 400

    if len(username) > 100 or len(test_code) > 100:
        return "Въведените данни са прекалено дълги.", 400

    # Fictional demonstration data only
    action = "SIMULATED_TEST"
    timestamp = datetime.now().isoformat(timespec="seconds")

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.execute(
            """
            INSERT INTO events
            (username, test_code, action, timestamp)
            VALUES (?, ?, ?, ?)
            """,
            (username, test_code, action, timestamp)
        )

        event_id = cursor.lastrowid

    email_sent = send_email_report(
        event_id,
        username,
        test_code,
        action,
        timestamp
    )

    print(
        "REPORT STATUS:",
        "SENT" if email_sent else "NOT SENT"
    )

    # The visitor sees only the confirmation page.
    # No redirect to the admin dashboard.
    return render_template_string(SUCCESS_PAGE)


# --------------------------------------------------
# ADMIN AUTHENTICATION
# --------------------------------------------------

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():

    if session.get("admin_authenticated"):
        return redirect(url_for("dashboard"))

    error = None

    if request.method == "POST":

        if not valid_csrf_token():
            return "Invalid security token.", 400

        entered_password = request.form.get("password", "")

        if secrets.compare_digest(entered_password, ADMIN_PASSWORD):
            session.clear()
            session["admin_authenticated"] = True
            session.permanent = True

            return redirect(url_for("dashboard"))

        error = "Невалидна парола."

    return render_template_string(
        LOGIN_PAGE,
        error=error,
        csrf_token=get_csrf_token()
    )


@app.route("/admin/logout", methods=["POST"])
def admin_logout():

    if not session.get("admin_authenticated"):
        return redirect(url_for("admin_login"))

    if not valid_csrf_token():
        return "Invalid security token.", 400

    session.clear()

    return redirect(url_for("admin_login"))


# --------------------------------------------------
# PROTECTED DASHBOARD
# --------------------------------------------------

@app.route("/dashboard")
def dashboard():

    if not session.get("admin_authenticated"):
        return redirect(url_for("admin_login"))

    with sqlite3.connect(DATABASE) as conn:
        events = conn.execute(
            """
            SELECT id, username, test_code, action, timestamp
            FROM events
            ORDER BY id DESC
            """
        ).fetchall()

    return render_template(
        "dashboard.html",
        events=events,
        csrf_token=get_csrf_token()
    )


# --------------------------------------------------
# SECURITY HEADERS
# --------------------------------------------------

@app.after_request
def add_security_headers(response):

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    if request.path == "/dashboard":
        response.headers["Cache-Control"] = "no-store"

    return response


# --------------------------------------------------
# START APPLICATION
# --------------------------------------------------

if __name__ == "__main__":

    init_db()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
        use_reloader=False
    )
