"""
MEDIC CARE backend  (Flask + Firebase Firestore)

Serves the website files and the JSON API that auth.js talks to under /api.
All data lives in Firestore, one document per account:

    users/{sha256(login id)} = {
        id:            "name@email.com" or "09123456789"   (normalized login id)
        password_hash: "...",                               (never sent to the browser)
        profile:       {name, email, phone, code, photo},
        data:          {appointments: [...], profileExtra: {...}},
        created_at:    1730000000.0
    }

Only this server talks to Firestore (Firebase Admin SDK), so the Firestore
rules can deny every direct browser access (see firestore.rules).

Run locally:   python app.py
Production:    gunicorn app:app        (set SECRET_KEY and SESSION_COOKIE_SECURE=1)
"""

import copy
import hashlib
import json
import os
import re
import secrets
import threading
import time
from datetime import timedelta
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

try:                                    # optional: read settings from backend/.env
    from dotenv import load_dotenv # type: ignore
    load_dotenv(Path(__file__).resolve().parent / ".env")
except ImportError:
    pass


BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = Path(os.getenv("FRONTEND_DIR", BASE_DIR.parent / "frontend")).resolve()

USERS_COLLECTION = os.getenv("FIRESTORE_USERS_COLLECTION", "users")

SESSION_DAYS = 7
VERIFY_WINDOW = 300          # seconds a successful password check stays valid for login / password change
MAX_PHOTO_CHARS = 600_000    # Firestore documents are limited to 1 MiB
MAX_DATA_BYTES = 300_000     # per saved data key
MAX_APPOINTMENTS = 500

# Keys the website may save with Auth.setData(key, value), and the type each must be.
ALLOWED_DATA = {"appointments": list, "profileExtra": dict}

# Only these file types are ever served as website files.
STATIC_EXTENSIONS = {
    ".html", ".js", ".css", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".webp", ".ico", ".woff", ".woff2",
}

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$")
PHONE_RE = re.compile(r"^\+?\d{7,15}$")
PHOTO_RE = re.compile(r"^data:image/(png|jpeg|jpg|webp|gif);base64,[A-Za-z0-9+/=]+$")


def env_flag(name, default=False):
    return os.getenv(name, "1" if default else "0").strip().lower() in ("1", "true", "yes", "on")


class MemoryStore:
    """Throw-away store for local testing. Set USE_MEMORY_DB=1. Data is lost on restart."""

    def __init__(self):
        self._docs = {}
        self._lock = threading.Lock()

    def get(self, uid):
        with self._lock:
            doc = self._docs.get(uid)
            return copy.deepcopy(doc) if doc is not None else None

    def create(self, uid, doc):
        with self._lock:
            if uid in self._docs:
                return False
            self._docs[uid] = copy.deepcopy(doc)
            return True

    def update(self, uid, fields):
        with self._lock:
            doc = self._docs.get(uid)
            if doc is None:
                return False
            for path, value in fields.items():           # supports "data.appointments"
                target = doc
                *parents, last = path.split(".")
                for part in parents:
                    target = target.setdefault(part, {})
                target[last] = copy.deepcopy(value)
            return True

    def delete(self, uid):
        with self._lock:
            self._docs.pop(uid, None)


class FirestoreStore:
    """Firebase Firestore through the Firebase Admin SDK."""

    def __init__(self):
        import firebase_admin # pyright: ignore[reportMissingImports]
        from firebase_admin import credentials, firestore
        from google.api_core import exceptions

        self._exceptions = exceptions

        if not firebase_admin._apps:
            key_path = os.getenv("FIREBASE_CREDENTIALS")          # path to the service-account .json
            if key_path:
                cred = credentials.Certificate(key_path)
            else:                                                 # e.g. GOOGLE_APPLICATION_CREDENTIALS
                cred = credentials.ApplicationDefault()
            firebase_admin.initialize_app(cred)

        self._col = firestore.client().collection(USERS_COLLECTION)

    def get(self, uid):
        snap = self._col.document(uid).get()
        return snap.to_dict() if snap.exists else None

    def create(self, uid, doc):
        try:
            self._col.document(uid).create(doc)       # fails if the account already exists
            return True
        except self._exceptions.AlreadyExists:
            return False

    def update(self, uid, fields):
        try:
            self._col.document(uid).update(fields)
            return True
        except self._exceptions.NotFound:
            return False

    def delete(self, uid):
        self._col.document(uid).delete()


def make_store():
    if env_flag("USE_MEMORY_DB"):
        print("WARNING: USE_MEMORY_DB=1 - using a temporary in-memory database, NOT Firebase.")
        return MemoryStore()
    return FirestoreStore()


store = make_store()


app = Flask(__name__, static_folder=None)

secret = os.getenv("SECRET_KEY")
if not secret:
    secret = secrets.token_hex(32)
    print("WARNING: SECRET_KEY is not set. Using a random key, so everyone is logged out on restart.")

app.config.update(
    SECRET_KEY=secret,
    SESSION_COOKIE_NAME="medic_care_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=env_flag("SESSION_COOKIE_SECURE"),   # set to 1 when served over HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(days=SESSION_DAYS),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)

if env_flag("TRUST_PROXY"):                                    # behind nginx / a hosting proxy
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


def normalize(raw):
    """Same rules as Auth.normalize() in auth.js."""
    s = str(raw or "").strip()
    if "@" in s:
        return s.lower()
    s = re.sub(r"[\s\-().]", "", s)
    if re.fullmatch(r"\+63\d{10}", s):
        s = "0" + s[3:]
    elif re.fullmatch(r"63\d{10}", s):
        s = "0" + s[2:]
    return s


def valid_id(login_id):
    return len(login_id) <= 254 and bool(EMAIL_RE.match(login_id) or PHONE_RE.match(login_id))


def valid_password(pw):
    return (
        isinstance(pw, str)
        and 8 <= len(pw) <= 128
        and re.search(r"[A-Za-z]", pw) is not None
        and re.search(r"\d", pw) is not None
    )


def uid_for(login_id):
    """Firestore document id for a login id (emails contain characters that are awkward in ids)."""
    return hashlib.sha256(login_id.encode("utf-8")).hexdigest()


def body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def fail(error=None, status=400, **extra):
    payload = {"ok": False}
    if error:
        payload["error"] = error
    payload.update(extra)
    return jsonify(payload), status


def current_user():
    """(uid, document) for the signed-in account, or None."""
    uid = session.get("uid")
    if not uid:
        return None
    doc = store.get(uid)
    if doc is None:
        session.clear()
        return None
    return uid, doc


def clean_profile(profile):
    """Fields of the account profile that are safe to send to the browser."""
    p = profile if isinstance(profile, dict) else {}
    return {
        "name": p.get("name", ""),
        "email": p.get("email", ""),
        "phone": p.get("phone", ""),
        "code": p.get("code", "+63"),
        "photo": p.get("photo", ""),
    }


class RateLimiter:
    """Small in-memory limiter. Use Redis instead if you run several server processes."""

    def __init__(self, limit, window):
        self.limit, self.window = limit, window
        self._hits = {}
        self._lock = threading.Lock()

    def _recent(self, key):
        now = time.time()
        hits = [t for t in self._hits.get(key, []) if now - t < self.window]
        self._hits[key] = hits
        return hits

    def blocked(self, key):
        with self._lock:
            return len(self._recent(key)) >= self.limit

    def hit(self, key):
        with self._lock:
            self._recent(key).append(time.time())

    def reset(self, key):
        with self._lock:
            self._hits.pop(key, None)


login_limiter = RateLimiter(limit=5, window=300)      # wrong passwords per IP + account
signup_limiter = RateLimiter(limit=20, window=3600)   # sign-ups per IP


@app.before_request
def require_json_for_changes():
    """Every changing request must be JSON. Together with SameSite cookies this blocks cross-site forms (CSRF)."""
    if request.path.startswith("/api/") and request.method not in ("GET", "HEAD", "OPTIONS"):
        if not request.is_json:
            return fail("json_required", 415)


@app.after_request
def add_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.errorhandler(404)
def not_found(_e):
    if request.path.startswith("/api/"):
        return fail("not_found", 404)
    return "Not found", 404


@app.errorhandler(413)
def too_large(_e):
    return fail("too_large", 413)


@app.errorhandler(500)
def server_error(_e):
    return fail("server_error", 500)


@app.get("/api/me")
def me():
    found = current_user()
    if not found:
        return jsonify(ok=False, user=None), 401
    _, doc = found
    return jsonify(ok=True, user={
        "id": doc["id"],
        "profile": clean_profile(doc.get("profile")),
        "data": doc.get("data", {}),
    })


@app.post("/api/signup")
def signup():
    ip = request.remote_addr or "?"
    if signup_limiter.blocked(ip):
        return fail("too_many", 429)

    data = body()
    login_id = normalize(data.get("id"))
    password = data.get("password")
    profile = data.get("profile") if isinstance(data.get("profile"), dict) else {}
    name = str(profile.get("name", "")).strip()

    if not name or len(name) > 200:
        return fail("invalid_name")
    if not valid_id(login_id):
        return fail("invalid_id")
    if not valid_password(password):
        return fail("weak_password")

    signup_limiter.hit(ip)

    is_email = "@" in login_id
    doc = {
        "id": login_id,
        "password_hash": generate_password_hash(password),
        "profile": {
            "name": name,
            "email": login_id if is_email else "",
            "phone": "" if is_email else login_id,
            "code": "+63",
            "photo": "",
        },
        "data": {},
        "created_at": time.time(),
    }

    if not store.create(uid_for(login_id), doc):
        return fail("exists", 409)

    return jsonify(ok=True, id=login_id), 201


@app.post("/api/verify")
def verify():
    """Step 1 of signing in: check the password. Step 2 is /api/login."""
    data = body()
    login_id = normalize(data.get("id"))
    password = data.get("password")

    if not login_id or not isinstance(password, str):
        return fail(reason="bad", status=400)

    key = f"{request.remote_addr}|{login_id}"
    if login_limiter.blocked(key):
        return fail(reason="too_many", status=429)

    uid = uid_for(login_id)
    doc = store.get(uid)

    if doc is None:
        login_limiter.hit(key)
        return fail(reason="not_found", status=404)

    if not check_password_hash(doc["password_hash"], password):
        login_limiter.hit(key)
        return fail(reason="bad", status=401)

    login_limiter.reset(key)
    session["verified"] = {"uid": uid, "t": time.time()}
    return jsonify(ok=True, id=doc["id"])


@app.post("/api/login")
def login():
    """Step 2: start the session. Only works right after a successful /api/verify."""
    verified = session.get("verified") or {}
    uid = verified.get("uid")

    if not uid or time.time() - verified.get("t", 0) > VERIFY_WINDOW:
        session.pop("verified", None)
        return fail("not_verified", 401)

    asked = normalize(body().get("id"))
    if asked and uid_for(asked) != uid:
        return fail("not_verified", 403)

    if store.get(uid) is None:
        session.clear()
        return fail("not_found", 404)

    session.clear()
    session["uid"] = uid
    session.permanent = True
    return jsonify(ok=True)


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


def validate_profile_patch(patch):
    """Returns (clean_fields, error_code)."""
    out = {}

    if "name" in patch:
        name = str(patch["name"] or "").strip()
        if not name or len(name) > 200:
            return None, "invalid_name"
        out["name"] = name

    if "email" in patch:
        email = str(patch["email"] or "").strip().lower()
        if email and (len(email) > 254 or not EMAIL_RE.match(email)):
            return None, "invalid_email"
        out["email"] = email

    if "phone" in patch:
        phone = str(patch["phone"] or "").strip()
        if len(phone) > 30 or not re.fullmatch(r"[0-9+\-().\s]*", phone):
            return None, "invalid_phone"
        out["phone"] = phone

    if "code" in patch:
        code = str(patch["code"] or "").strip()
        if not re.fullmatch(r"\+?\d{1,4}", code):
            return None, "invalid_code"
        out["code"] = code

    if "photo" in patch:
        photo = patch["photo"] or ""
        if photo and (not isinstance(photo, str) or len(photo) > MAX_PHOTO_CHARS or not PHOTO_RE.match(photo)):
            return None, "invalid_photo"
        out["photo"] = photo

    return out, None


@app.put("/api/profile")
def save_profile():
    found = current_user()
    if not found:
        return fail("unauthorized", 401)
    uid, doc = found

    fields, error = validate_profile_patch(body())
    if error:
        return fail(error)

    profile = {**clean_profile(doc.get("profile")), **fields}
    store.update(uid, {"profile": profile})
    return jsonify(ok=True, profile=profile)


@app.post("/api/password/check")
def password_check():
    found = current_user()
    if not found:
        return fail("unauthorized", 401)
    uid, doc = found

    password = body().get("password")
    key = f"pw|{uid}"
    if login_limiter.blocked(key):
        return fail("too_many", 429)

    if not isinstance(password, str) or not check_password_hash(doc["password_hash"], password):
        login_limiter.hit(key)
        return fail("bad", 401)

    login_limiter.reset(key)
    session["pw_ok"] = time.time()          # allows one password change in the next few minutes
    return jsonify(ok=True)


@app.put("/api/password")
def password_change():
    found = current_user()
    if not found:
        return fail("unauthorized", 401)
    uid, _ = found

    if time.time() - session.get("pw_ok", 0) > VERIFY_WINDOW:
        return fail("current_password_required", 403)

    password = body().get("password")
    if not valid_password(password):
        return fail("weak_password")

    store.update(uid, {"password_hash": generate_password_hash(password)})
    session.pop("pw_ok", None)
    return jsonify(ok=True)


@app.delete("/api/account")
def delete_account():
    found = current_user()
    if not found:
        return fail("unauthorized", 401)
    uid, _ = found

    store.delete(uid)
    session.clear()
    return jsonify(ok=True)


@app.put("/api/data/<key>")
def save_data(key):
    found = current_user()
    if not found:
        return fail("unauthorized", 401)
    uid, _ = found

    expected = ALLOWED_DATA.get(key)
    if expected is None:
        return fail("invalid_key", 400)

    value = body().get("value")
    if not isinstance(value, expected):
        return fail("invalid_value", 400)

    if key == "appointments":
        if len(value) > MAX_APPOINTMENTS or not all(isinstance(a, dict) for a in value):
            return fail("invalid_value", 400)

    if len(json.dumps(value)) > MAX_DATA_BYTES:
        return fail("too_large", 413)

    store.update(uid, {f"data.{key}": value})
    return jsonify(ok=True)

@app.post("/api/forgot-password")
def forgot_password():
    try:
        import smtplib
        import ssl
        from email.message import EmailMessage
        from firebase_admin import auth

        data = body()
        email = data.get("email")
        if not isinstance(email, str) or not EMAIL_RE.fullmatch(email.strip()):
            return fail("invalid_email")
        email = email.strip().lower()

        smtp_host = os.getenv("SMTP_HOST")
        smtp_user = os.getenv("SMTP_USERNAME")
        smtp_password = os.getenv("SMTP_PASSWORD")
        sender = os.getenv("RESET_EMAIL_FROM", smtp_user or "")
        if not all((smtp_host, smtp_user, smtp_password, sender)):
            return fail("reset_unavailable", 503)

        try:
            reset_link = auth.generate_password_reset_link(email)
        except auth.UserNotFoundError:
            # Keep the response identical for unknown accounts.
            return jsonify(ok=True)

        message = EmailMessage()
        message["Subject"] = "Reset your Medic Care password"
        message["From"] = sender
        message["To"] = email
        message.set_content(
            "Use this link to reset your Medic Care password. "
            "If you did not request this, you can ignore this email.\n\n"
            f"{reset_link}"
        )

        port = int(os.getenv("SMTP_PORT", "587"))
        if port == 465:
            with smtplib.SMTP_SSL(
                smtp_host, port, context=ssl.create_default_context(), timeout=15
            ) as smtp:
                smtp.login(smtp_user, smtp_password)
                smtp.send_message(message)
        else:
            with smtplib.SMTP(smtp_host, port, timeout=15) as smtp:
                smtp.starttls(context=ssl.create_default_context())
                smtp.login(smtp_user, smtp_password)
                smtp.send_message(message)
        return jsonify(ok=True)
    except Exception:
        app.logger.exception("Password reset request failed")
        return fail("reset_unavailable", 503)

# Serve frontend files from the configured directory using the allowlist above.
@app.get("/")
def home():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.get("/<path:filename>")
def site_file(filename):
    path = Path(filename)
    if any(part.startswith(".") for part in path.parts) or path.suffix.lower() not in STATIC_EXTENSIONS:
        abort(404)
    resp = send_from_directory(FRONTEND_DIR, filename)      # refuses paths outside FRONTEND_DIR
    if path.suffix.lower() in (".html", ".js"):
        resp.headers["Cache-Control"] = "no-cache"
    return resp


if __name__ == "__main__":
    app.run(
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "5000")),
        debug=env_flag("FLASK_DEBUG"),
    )