""" MEDIC CARE backend  (Flask + Firebase Firestore)

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

from flask import Flask, abort, jsonify, request, send_from_directory, session  # type: ignore[reportMissingImports]
from werkzeug.security import check_password_hash, generate_password_hash # type: ignore

try:                                    # optional: read settings from backend/.env
    from dotenv import load_dotenv # type: ignore
    load_dotenv(Path(__file__).resolve().parent / ".env")
except ImportError:
    pass


BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = Path(os.getenv("FRONTEND_DIR", BASE_DIR.parent / "frontend")).resolve()

USERS_COLLECTION = os.getenv("FIRESTORE_USERS_COLLECTION", "users")
RESETS_COLLECTION = "password_resets"
SLOTS_COLLECTION = "appointment_slots"
RESET_TOKEN_MINUTES = 30
CHALLENGES_COLLECTION = "login_challenges"
LOGIN_LINK_MINUTES = 10

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


def env_flag(name, default=False):
    return os.getenv(name, "1" if default else "0").strip().lower() in ("1", "true", "yes", "on")


class DatabaseUnavailable(Exception):
    """The account database could not complete a request."""


class MemoryStore:
    """Throw-away store for local testing. Set USE_MEMORY_DB=1. Data is lost on restart."""

    def __init__(self):
        self._docs = {}                      # (collection, id) -> dict
        self._lock = threading.Lock()

    def get_doc(self, col, uid):
        with self._lock:
            doc = self._docs.get((col, uid))
            return copy.deepcopy(doc) if doc is not None else None

    def create_doc(self, col, uid, doc):
        with self._lock:
            if (col, uid) in self._docs:
                return False
            self._docs[(col, uid)] = copy.deepcopy(doc)
            return True

    def update_doc(self, col, uid, fields):
        with self._lock:
            doc = self._docs.get((col, uid))
            if doc is None:
                return False
            for path, value in fields.items():           # supports "data.appointments"
                target = doc
                *parents, last = path.split(".")
                for part in parents:
                    target = target.setdefault(part, {})
                target[last] = copy.deepcopy(value)
            return True

    def delete_doc(self, col, uid):
        with self._lock:
            self._docs.pop((col, uid), None)


class FirestoreStore:
    """Firebase Firestore, accessed only from this server with the Admin SDK."""

    def __init__(self):
        import firebase_admin
        from firebase_admin import credentials, firestore
        from google.api_core import exceptions

        if not firebase_admin._apps:
            firebase_admin.initialize_app(load_firebase_credentials(credentials))

        self._db = firestore.client()
        self._exceptions = exceptions

    def _ref(self, col, uid):
        return self._db.collection(col).document(uid)

    def get_doc(self, col, uid):
        try:
            snap = self._ref(col, uid).get()
            return snap.to_dict() if snap.exists else None
        except self._exceptions.GoogleAPICallError as error:
            raise DatabaseUnavailable from error

    def create_doc(self, col, uid, doc):
        try:
            self._ref(col, uid).create(doc)               # fails if it already exists
            return True
        except self._exceptions.AlreadyExists:
            return False
        except self._exceptions.GoogleAPICallError as error:
            raise DatabaseUnavailable from error

    def update_doc(self, col, uid, fields):
        try:
            self._ref(col, uid).update(fields)
            return True
        except self._exceptions.NotFound:
            return False
        except self._exceptions.GoogleAPICallError as error:
            raise DatabaseUnavailable from error

    def delete_doc(self, col, uid):
        try:
            self._ref(col, uid).delete()
        except self._exceptions.GoogleAPICallError as error:
            raise DatabaseUnavailable from error


def load_firebase_credentials(credentials):
    """Where the service-account key comes from, in order of preference:

    1. FIREBASE_CREDENTIALS_JSON    the whole JSON as one environment variable (best for hosting)
    2. GOOGLE_APPLICATION_CREDENTIALS / FIREBASE_KEY_PATH   path to the JSON file
    3. backend/firebase-key.json    local development only - never commit this file
    """
    raw = os.getenv("FIREBASE_CREDENTIALS_JSON")
    if raw:
        return credentials.Certificate(json.loads(raw))

    for candidate in (
        os.getenv("FIREBASE_KEY_PATH"),
        os.getenv("GOOGLE_APPLICATION_CREDENTIALS"),
        "/etc/secrets/firebase-key.json",                   # Render secret file
        BASE_DIR / "firebase-key.json",
    ):
        if candidate and Path(candidate).exists():
            return credentials.Certificate(str(candidate))

    raise FileNotFoundError(
        "Firebase credentials not found. Set FIREBASE_CREDENTIALS_JSON, or put the "
        "service-account key at backend/firebase-key.json (or set FIREBASE_KEY_PATH)."
    )


class Store:
    """Thin wrapper so the routes never touch a database client directly."""

    def __init__(self, backend):
        self._b = backend

    # accounts
    def get(self, uid):                return self._b.get_doc(USERS_COLLECTION, uid)
    def create(self, uid, doc):        return self._b.create_doc(USERS_COLLECTION, uid, doc)
    def update(self, uid, fields):     return self._b.update_doc(USERS_COLLECTION, uid, fields)
    def delete(self, uid):             self._b.delete_doc(USERS_COLLECTION, uid)

    # password-reset tokens (only a hash of the token is ever stored)
    def get_reset(self, token_hash):   return self._b.get_doc(RESETS_COLLECTION, token_hash)
    def put_reset(self, token_hash, doc):
        self._b.delete_doc(RESETS_COLLECTION, token_hash)
        self._b.create_doc(RESETS_COLLECTION, token_hash, doc)
    def delete_reset(self, token_hash): self._b.delete_doc(RESETS_COLLECTION, token_hash)

    # e-mail confirmation of a login (only a hash of the emailed token is stored)
    def get_challenge(self, th):           return self._b.get_doc(CHALLENGES_COLLECTION, th)
    def put_challenge(self, th, doc):
        self._b.delete_doc(CHALLENGES_COLLECTION, th)
        self._b.create_doc(CHALLENGES_COLLECTION, th, doc)
    def confirm_challenge(self, th):       return self._b.update_doc(CHALLENGES_COLLECTION, th, {"confirmed": True})
    def delete_challenge(self, th):        self._b.delete_doc(CHALLENGES_COLLECTION, th)

    # appointment slots: one document per doctor + date + time, so two patients can't book the same slot
    def claim_slot(self, key, uid):
        if self._b.create_doc(SLOTS_COLLECTION, key, {"uid": uid, "t": time.time()}):
            return True
        existing = self._b.get_doc(SLOTS_COLLECTION, key)
        return bool(existing and existing.get("uid") == uid)

    def release_slot(self, key, uid):
        existing = self._b.get_doc(SLOTS_COLLECTION, key)
        if existing and existing.get("uid") == uid:
            self._b.delete_doc(SLOTS_COLLECTION, key)


def make_store():
    if env_flag("USE_MEMORY_DB"):
        print("WARNING: USE_MEMORY_DB=1 - using a temporary in-memory database, NOT Firebase.")
        return Store(MemoryStore())
    return Store(FirestoreStore())


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
    from werkzeug.middleware.proxy_fix import ProxyFix # type: ignore
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


def normalize(raw):
    """Same rules as Auth.normalize() in auth.js: accounts are identified by e-mail address."""
    return str(raw or "").strip().lower()


def valid_id(login_id):
    return len(login_id) <= 254 and bool(EMAIL_RE.match(login_id))


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


login_mail_limiter = RateLimiter(limit=5, window=3600)  # confirmation e-mails per account
login_limiter = RateLimiter(limit=5, window=300)      # wrong passwords per IP + account
signup_limiter = RateLimiter(limit=20, window=3600)   # sign-ups per IP
reset_limiter = RateLimiter(limit=5, window=3600)     # reset e-mails per IP
reset_try_limiter = RateLimiter(limit=10, window=600) # reset-token attempts per IP


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
def not_found(_):
    if request.path.startswith("/api/"):
        return fail("not_found", 404)
    return "Not found", 404


@app.errorhandler(413)
def too_large(_):
    return fail("too_large", 413)


@app.errorhandler(500)
def server_error(_):
    return fail("server_error", 500)


@app.errorhandler(DatabaseUnavailable)
def database_down(error):
    app.logger.error("Firestore request failed: %s", error.__cause__ or error)
    return fail("database_unavailable", 503)


@app.get("/api/health")
def health():
    return jsonify(ok=True)


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

    doc = {
        "id": login_id,
        "password_hash": generate_password_hash(password),
        "profile": {
            "name": name,
            "email": login_id,
            "phone": "",
            "code": "+63",
        },
        "data": {},
        "created_at": time.time(),
    }

    try:
        created = store.create(uid_for(login_id), doc)
    except DatabaseUnavailable:
        app.logger.exception("Account creation failed because Firestore is unavailable.")
        return fail("database_unavailable", 503)

    if not created:
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

    if "@" not in str(doc.get("id", "")):          # old phone-number test accounts can no longer sign in
        return fail(reason="not_found", status=404)

    if LOGIN_EMAIL_VERIFICATION:
        th, error = issue_login_link(uid, doc["id"])
        if error:
            session.pop("verified", None)
            return fail(error, 503 if error == "email_unavailable" else 429)
        session["verified"] = {"uid": uid, "t": time.time(), "th": th}
        return jsonify(ok=True, id=doc["id"], needs_email=True, email=mask_email(doc["id"]))

    session["verified"] = {"uid": uid, "t": time.time()}
    return jsonify(ok=True, id=doc["id"], needs_email=False)


@app.post("/api/login")
def login():
    """Step 2: start the session. Only works right after a successful /api/verify."""
    verified = session.get("verified") or {}
    uid = verified.get("uid")
    th = verified.get("th")                       # set when an e-mail confirmation is required
    window = LOGIN_LINK_MINUTES * 60 if th else VERIFY_WINDOW

    if not uid or time.time() - verified.get("t", 0) > window:
        session.pop("verified", None)
        return fail("not_verified", 401)

    if th:
        challenge = store.get_challenge(th)
        if not challenge or challenge.get("uid") != uid or challenge.get("exp", 0) < time.time():
            session.pop("verified", None)
            return fail("not_verified", 401)
        if not challenge.get("confirmed"):
            return fail("email_not_confirmed", 401)
        store.delete_challenge(th)                # the link works once

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


LOGIN_EMAIL_VERIFICATION = env_flag("LOGIN_EMAIL_VERIFICATION", True)


def mask_email(email):
    name, _, domain = email.partition("@")
    return f"{name[:1]}***@{domain}"


def issue_login_link(uid, email):
    """Creates a one-time confirmation link and e-mails it. Returns (token_hash, error_code)."""
    if login_mail_limiter.blocked(uid):
        return None, "too_many"
    login_mail_limiter.hit(uid)

    old = (session.get("verified") or {}).get("th")
    if old:
        store.delete_challenge(old)

    token = secrets.token_urlsafe(32)
    th = token_hash(token)
    store.put_challenge(th, {"uid": uid, "exp": time.time() + LOGIN_LINK_MINUTES * 60, "confirmed": False})

    base = os.getenv("PUBLIC_URL", request.host_url).rstrip("/")
    link = f"{base}/confirm-login.html?token={token}"
    try:
        sent = send_email(
            email,
            "Confirm your Medic Care login",
            f"Someone is logging in to your Medic Care account. If this is you, open this link "
            f"(valid for {LOGIN_LINK_MINUTES} minutes):\n\n{link}\n\n"
            "If this was not you, ignore this email and change your password.",
        )
    except Exception:
        app.logger.exception("Could not send the login confirmation e-mail")
        store.delete_challenge(th)
        return None, "email_unavailable"

    if not sent:
        if env_flag("FLASK_DEBUG"):
            app.logger.warning("SMTP not configured - login link for %s: %s", email, link)
        else:
            store.delete_challenge(th)
            return None, "email_unavailable"
    return th, None


@app.post("/api/confirm-login")
def confirm_login():
    """Called by confirm-login.html when the user opens the e-mailed link (on any device)."""
    ip = request.remote_addr or "?"
    if reset_try_limiter.blocked(ip):
        return fail("too_many", 429)
    reset_try_limiter.hit(ip)

    token = body().get("token")
    if not isinstance(token, str) or not token:
        return fail("invalid_token", 400)

    th = token_hash(token)
    challenge = store.get_challenge(th)
    if not challenge or challenge.get("exp", 0) < time.time():
        return fail("invalid_token", 400)

    store.confirm_challenge(th)
    return jsonify(ok=True)


@app.get("/api/login-status")
def login_status():
    """The login page polls this until the e-mailed link has been opened."""
    th = (session.get("verified") or {}).get("th")
    if not th:
        return jsonify(ok=True, confirmed=False, expired=True)
    challenge = store.get_challenge(th)
    if not challenge or challenge.get("exp", 0) < time.time():
        return jsonify(ok=True, confirmed=False, expired=True)
    return jsonify(ok=True, confirmed=bool(challenge.get("confirmed")), expired=False)


@app.post("/api/login/resend")
def login_resend():
    verified = session.get("verified") or {}
    uid = verified.get("uid")
    if not uid or not verified.get("th") or time.time() - verified.get("t", 0) > LOGIN_LINK_MINUTES * 60:
        return fail("not_verified", 401)
    doc = store.get(uid)
    if not doc:
        return fail("not_verified", 401)
    th, error = issue_login_link(uid, doc["id"])
    if error:
        return fail(error, 503 if error == "email_unavailable" else 429)
    session["verified"] = {"uid": uid, "t": time.time(), "th": th}
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
    uid, doc = found

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

    if key == "appointments":
        old_keys = slot_keys((doc.get("data") or {}).get("appointments"))
        new_keys = slot_keys(value)
        claimed = []
        for k in new_keys - old_keys:
            if not store.claim_slot(k, uid):
                for done in claimed:
                    store.release_slot(done, uid)
                return fail("slot_taken", 409)
            claimed.append(k)

    store.update(uid, {f"data.{key}": value})

    if key == "appointments":
        for k in old_keys - new_keys:         # cancelled or removed: free the slot again
            store.release_slot(k, uid)
    return jsonify(ok=True)


def slot_keys(appointments):
    """Ids of the doctor/date/time slots held by a list of appointments (cancelled ones hold none)."""
    keys = set()
    for a in appointments if isinstance(appointments, list) else []:
        if not isinstance(a, dict) or str(a.get("status", "")).lower() == "cancelled":
            continue
        doctor, date, slot = (str(a.get(f, "")).strip() for f in ("doctorName", "date", "time"))
        if doctor and date and slot:
            keys.add(hashlib.sha256(f"{doctor}|{date}|{slot}".encode("utf-8")).hexdigest())
    return keys

def send_email(to, subject, text):
    """Send through SMTP (SMTP_HOST / SMTP_PORT / SMTP_USERNAME / SMTP_PASSWORD / RESET_EMAIL_FROM)."""
    import smtplib
    import ssl
    from email.message import EmailMessage

    host = os.getenv("SMTP_HOST")
    user = os.getenv("SMTP_USERNAME")
    password = os.getenv("SMTP_PASSWORD")
    sender = os.getenv("RESET_EMAIL_FROM", user or "")
    if not all((host, user, password, sender)):
        return False

    message = EmailMessage()
    message["Subject"], message["From"], message["To"] = subject, sender, to
    message.set_content(text)

    port = int(os.getenv("SMTP_PORT", "587"))
    context = ssl.create_default_context()
    if port == 465:
        with smtplib.SMTP_SSL(host, port, context=context, timeout=15) as smtp:
            smtp.login(user, password)
            smtp.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            smtp.starttls(context=context)
            smtp.login(user, password)
            smtp.send_message(message)
    return True


def token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@app.post("/api/forgot-password")
def forgot_password():
    """Emails a one-time reset link. The answer is the same whether or not the account exists."""
    ip = request.remote_addr or "?"
    if reset_limiter.blocked(ip):
        return fail("too_many", 429)

    email = body().get("email")
    if not isinstance(email, str) or not EMAIL_RE.fullmatch(email.strip()):
        return fail("invalid_email")
    email = email.strip().lower()
    reset_limiter.hit(ip)

    uid = uid_for(email)
    if store.get(uid) is None:
        return jsonify(ok=True)

    token = secrets.token_urlsafe(32)
    store.put_reset(token_hash(token), {"uid": uid, "exp": time.time() + RESET_TOKEN_MINUTES * 60})

    base = os.getenv("PUBLIC_URL", request.host_url).rstrip("/")
    link = f"{base}/reset-password.html?token={token}"

    try:
        sent = send_email(
            email,
            "Reset your Medic Care password",
            f"Use this link to reset your Medic Care password (valid for {RESET_TOKEN_MINUTES} minutes):\n\n"
            f"{link}\n\nIf you did not request this, you can ignore this email.",
        )
    except Exception:
        app.logger.exception("Could not send the password reset e-mail")
        return fail("reset_unavailable", 503)

    if not sent:
        if env_flag("FLASK_DEBUG"):
            app.logger.warning("SMTP not configured - reset link for %s: %s", email, link)
            return jsonify(ok=True)
        return fail("reset_unavailable", 503)
    return jsonify(ok=True)


@app.post("/api/reset-password")
def reset_password():
    """Sets a new password using the token from the e-mailed link."""
    ip = request.remote_addr or "?"
    if reset_try_limiter.blocked(ip):
        return fail("too_many", 429)
    reset_try_limiter.hit(ip)

    data = body()
    token, password = data.get("token"), data.get("password")
    if not isinstance(token, str) or not token:
        return fail("invalid_token", 400)
    if not valid_password(password):
        return fail("weak_password")

    th = token_hash(token)
    record = store.get_reset(th)
    if not record or record.get("exp", 0) < time.time():
        if record:
            store.delete_reset(th)
        return fail("invalid_token", 400)

    if not store.update(record["uid"], {"password_hash": generate_password_hash(password)}):
        store.delete_reset(th)
        return fail("invalid_token", 400)

    store.delete_reset(th)                    # one use only
    session.clear()
    return jsonify(ok=True)


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