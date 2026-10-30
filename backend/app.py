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

import requests
from flask import Flask, abort, jsonify, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash


class DatabaseUnavailable(Exception):
    pass


def env_flag(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID", "")
FIREBASE_API_KEY = os.getenv("FIREBASE_API_KEY", "")
USERS_COLLECTION = os.getenv("USERS_COLLECTION", "users")
RESETS_COLLECTION = os.getenv("RESETS_COLLECTION", "password_resets")
CHALLENGES_COLLECTION = os.getenv("CHALLENGES_COLLECTION", "login_challenges")
SLOTS_COLLECTION = os.getenv("SLOTS_COLLECTION", "appointment_slots")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
APPOINTMENT_STATUSES = {"pending", "confirmed", "cancelled", "completed"}
ALLOWED_DATA = {"appointments": list}
MAX_APPOINTMENTS = 500
MAX_DATA_BYTES = 1_000_000
SESSION_DAYS = 30
VERIFY_WINDOW = 600
LOGIN_LINK_MINUTES = 15
RESET_TOKEN_MINUTES = 30
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
STATIC_EXTENSIONS = {".html", ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp"}


class MemoryStore:
    def __init__(self):
        self._lock = threading.RLock()
        self._docs = {}

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
            for path, value in fields.items():
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
    def __init__(self):
        self._base_url = f"https://googleapis.com{FIREBASE_PROJECT_ID}/databases/(default)/documents"

    def _to_firestore_value(self, val):
        if val is None:
            return {"nullValue": None}
        if isinstance(val, bool):
            return {"booleanValue": val}
        if isinstance(val, int):
            return {"integerValue": str(val)}
        if isinstance(val, float):
            return {"doubleValue": val}
        if isinstance(val, str):
            return {"stringValue": val}
        if isinstance(val, dict):
            return {"mapValue": {"fields": {str(k): self._to_firestore_value(v) for k, v in val.items()}}}
        if isinstance(val, (list, tuple, set)):
            return {"arrayValue": {"values": [self._to_firestore_value(v) for v in val]}}
        return {"stringValue": str(val)}

    def _from_firestore_value(self, f_val):
        if not isinstance(f_val, dict) or not f_val:
            return f_val
        k = next(iter(f_val))
        v = f_val[k]
        if k == "nullValue":
            return None
        if k == "booleanValue":
            return bool(v)
        if k == "integerValue":
            return int(v)
        if k == "doubleValue":
            return float(v)
        if k in ("stringValue", "timestampValue"):
            return str(v)
        if k == "mapValue":
            return {fk: self._from_firestore_value(fv) for fk, fv in v.get("fields", {}).items()}
        if k == "arrayValue":
            return [self._from_firestore_value(i) for i in v.get("values", [])]
        return v

    def get_doc(self, col, uid):
        url = f"{self._base_url}/{col}/{uid}?key={FIREBASE_API_KEY}"
        try:
            res = requests.get(url, timeout=10)
            if res.status_code == 200:
                fields = res.json().get("fields", {})
                return {k: self._from_firestore_value(v) for k, v in fields.items()}
            elif res.status_code == 404:
                return None
            raise DatabaseUnavailable
        except Exception:
            raise DatabaseUnavailable

    def create_doc(self, col, uid, doc):
        url = f"{self._base_url}/{col}?documentId={uid}&key={FIREBASE_API_KEY}"
        payload = {"fields": {k: self._to_firestore_value(v) for k, v in doc.items()}}
        try:
            res = requests.post(url, json=payload, timeout=10)
            return res.status_code == 200
        except Exception:
            raise DatabaseUnavailable

    def update_doc(self, col, uid, fields):
        current = self.get_doc(col, uid)
        if current is None:
            return False
        for path, value in fields.items():
            target = current
            *parents, last = path.split(".")
            for part in parents:
                target = target.setdefault(part, {})
            target[last] = value
        url = f"{self._base_url}/{col}/{uid}?key={FIREBASE_API_KEY}"
        payload = {"fields": {k: self._to_firestore_value(v) for k, v in current.items()}}
        try:
            res = requests.patch(url, json=payload, timeout=10)
            return res.status_code == 200
        except Exception:
            raise DatabaseUnavailable

    def delete_doc(self, col, uid):
        url = f"{self._base_url}/{col}/{uid}?key={FIREBASE_API_KEY}"
        try:
            requests.delete(url, timeout=10)
        except Exception:
            raise DatabaseUnavailable


class Store:
    def __init__(self, backend):
        self._b = backend

    def get(self, uid):                return self._b.get_doc(USERS_COLLECTION, uid)
    def create(self, uid, doc):        return self._b.create_doc(USERS_COLLECTION, uid, doc)
    def update(self, uid, fields):     return self._b.update_doc(USERS_COLLECTION, uid, fields)
    def delete(self, uid):             self._b.delete_doc(USERS_COLLECTION, uid)

    def get_reset(self, token_hash):   return self._b.get_doc(RESETS_COLLECTION, token_hash)
    def put_reset(self, token_hash, doc):
        self._b.delete_doc(RESETS_COLLECTION, token_hash)
        self._b.create_doc(RESETS_COLLECTION, token_hash, doc)
    def delete_reset(self, token_hash): self._b.delete_doc(RESETS_COLLECTION, token_hash)

    def get_challenge(self, th):           return self._b.get_doc(CHALLENGES_COLLECTION, th)
    def put_challenge(self, th, doc):
        self._b.delete_doc(CHALLENGES_COLLECTION, th)
        self._b.create_doc(CHALLENGES_COLLECTION, th, doc)
    def confirm_challenge(self, th):       return self._b.update_doc(CHALLENGES_COLLECTION, th, {"confirmed": True})
    def delete_challenge(self, th):        self._b.delete_doc(CHALLENGES_COLLECTION, th)

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
        return Store(MemoryStore())
    return Store(FirestoreStore())

store = make_store()

app = Flask(__name__, static_folder=None)

secret = os.getenv("SECRET_KEY")
if not secret:
    secret = secrets.token_hex(32)

app.config.update(
    SECRET_KEY=secret,
    SESSION_COOKIE_NAME="medic_care_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=env_flag("SESSION_COOKIE_SECURE"),   
    PERMANENT_SESSION_LIFETIME=timedelta(days=SESSION_DAYS),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)

if env_flag("TRUST_PROXY"):                                    
    from werkzeug.middleware.proxy_fix import ProxyFix 
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

def normalize(raw):
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
    return hashlib.sha256(login_id.encode("utf-8")).hexdigest()

def is_int(v):
    """True only for real integers (bool is a subclass of int, so exclude it)."""
    return isinstance(v, int) and not isinstance(v, bool)

def is_text(v, max_len):
    return isinstance(v, str) and len(v) <= max_len

def valid_appointment(a):
    """Type-check one appointment record coming from the browser."""
    if not isinstance(a, dict):
        return False
    if "id" in a and not is_int(a["id"]):
        return False
    for field, limit in (("doctor", 100), ("doctorName", 200), ("spec", 200), ("service", 300),
                         ("specific", 300), ("date", 10), ("time", 40), ("status", 20)):
        if field in a and not is_text(a[field], limit):
            return False
    if "status" in a and a["status"].lower() not in APPOINTMENT_STATUSES:
        return False
    if "date" in a and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", a["date"]):
        return False
    if "patient" in a and not isinstance(a["patient"], dict):
        return False
    return True

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
    uid = session.get("uid")
    if not uid:
        return None
    doc = store.get(uid)
    if doc is None:
        session.clear()
        return None
    return uid, doc

def clean_profile(profile):
    p = profile if isinstance(profile, dict) else {}
    return {
        "name": p.get("name", ""),
        "email": p.get("email", ""),
        "phone": p.get("phone", ""),
        "code": p.get("code", "+63"),
    }

class RateLimiter:
    def __init__(self, limit, window):
        self.limit, self.window = limit, window
        self._hits = {}
        self._lock = threading.Lock()

    def _recent(self, key):
        now = time.time()
        hits = [t for t in self._hits.get(key, []) if now - t < self.window]
        if hits:
            self._hits[key] = hits
        else:
            self._hits.pop(key, None)
        return hits

    def blocked(self, key):
        with self._lock:
            return len(self._recent(key)) >= self.limit

    def hit(self, key):
        with self._lock:
            hits = self._recent(key)
            hits.append(time.time())
            self._hits[key] = hits

    def reset(self, key):
        with self._lock:
            self._hits.pop(key, None)

login_mail_limiter = RateLimiter(limit=5, window=3600)
login_limiter = RateLimiter(limit=5, window=300)
signup_limiter = RateLimiter(limit=20, window=3600)
reset_limiter = RateLimiter(limit=5, window=3600)
reset_try_limiter = RateLimiter(limit=10, window=600)

@app.before_request
def require_json_for_changes():
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
    ip = request.remote_addr or "unknown"
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
        "created_at": int(time.time()),
    }
    try:
        if not store.create(uid_for(login_id), doc):
            return fail("exists", 409)
        return jsonify(ok=True, id=login_id), 201
    except DatabaseUnavailable:
        return fail("database_unavailable", 503)

@app.post("/api/verify")
def verify():
    data = body()
    login_id = normalize(data.get("id"))
    password = data.get("password")
    if not login_id or not isinstance(password, str):
        return fail(reason="bad", status=400)
    key = f"{request.remote_addr}|{login_id}"
    if login_limiter.blocked(key):
        return fail(reason="too_many", status=429)
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"
    payload = {
        "email": login_id,
        "password": password,
        "returnSecureToken": True
    }
    try:
        response = requests.post(url, json=payload, timeout=10)
        res_data = response.json()
        if response.status_code == 200:
            login_limiter.reset(key)
            uid = res_data['localId']
            if LOGIN_EMAIL_VERIFICATION:
                th, error = issue_login_link(uid, login_id)
                if error:
                    session.pop("verified", None)
                    return fail(error, 503 if error == "email_unavailable" else 429)
                session["verified"] = {"uid": uid, "t": time.time(), "th": th}
                return jsonify(ok=True, id=login_id, needs_email=True, email=mask_email(login_id))
            session["verified"] = {"uid": uid, "t": time.time()}
            return jsonify(ok=True, id=login_id, needs_email=False)
        else:
            login_limiter.hit(key)
            res_data = response.json()
            error_msg = res_data.get('error', {}).get('message', '')
            
            if "EMAIL_NOT_FOUND" in error_msg:
                return fail(error="No account found. Please create an account.", status=404)
            elif "INVALID_PASSWORD" in error_msg:
                return fail(error="Incorrect password. Please try again.", status=401)
            else:
                return fail(error="Login failed. Please check your credentials.", status=400)

    except Exception as e:
        return fail(str(e), 500)


@app.post("/api/login")
def login():
    verified = session.get("verified") or {}
    uid = verified.get("uid")
    th = verified.get("th")
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
        store.delete_challenge(th)
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
        store.delete_challenge(th)
        return None, "email_unavailable"
    if not sent:
        if env_flag("FLASK_DEBUG"):
            return th, None
        store.delete_challenge(th)
        return None, "email_unavailable"
    return th, None

@app.post("/api/confirm-login")
def confirm_login():
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
    session["pw_ok"] = time.time()
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
        if len(value) > MAX_APPOINTMENTS or not all(valid_appointment(a) for a in value):
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
        for k in old_keys - new_keys:
            store.release_slot(k, uid)
    return jsonify(ok=True)

def slot_keys(appointments):
    keys = set()
    for a in appointments if isinstance(appointments, list) else []:
        if not isinstance(a, dict) or str(a.get("status", "")).lower() == "cancelled":
            continue
        doctor, date, slot = (str(a.get(f, "")).strip() for f in ("doctorName", "date", "time"))
        if doctor and date and slot:
            keys.add(hashlib.sha256(f"{doctor}|{date}|{slot}".encode("utf-8")).hexdigest())
    return keys

def send_email(to, subject, text):
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
        return fail("reset_unavailable", 503)
    if not sent:
        if env_flag("FLASK_DEBUG"):
            return jsonify(ok=True)
        return fail("reset_unavailable", 503)
    return jsonify(ok=True)

@app.post("/api/reset-password")
def reset_password():
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
    store.delete_reset(th)
    session.clear()
    return jsonify(ok=True)

@app.get("/")
def home():
    if "uid" not in session:
        return send_from_directory(FRONTEND_DIR, "login.html")
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.get("/<path:filename>")
def site_file(filename):
    path = Path(filename)
    if any(part.startswith(".") for part in path.parts) or path.suffix.lower() not in STATIC_EXTENSIONS:
        abort(404)
    resp = send_from_directory(FRONTEND_DIR, filename)
    if path.suffix.lower() in (".html", ".js"):
        resp.headers["Cache-Control"] = "no-cache"
    return resp

if __name__ == "__main__":
    port: int = int(os.environ.get("PORT", "10000"))
    app.run(
        host="0.0.0.0",
        port=port,
        debug=env_flag("FLASK_DEBUG")
    )