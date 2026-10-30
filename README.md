# Medic Care

    backend/app.py        Flask API + serves ../frontend   (Firestore via firebase-admin)
    frontend/             HTML pages, auth.js, languages.js
    firestore.rules       deny-all rules (deploy them in the Firebase console)

## Run locally
    pip install -r requirements.txt
    copy backend\.env.example backend\.env     # fill in the Firebase values
    # keep the service-account JSON in an ignored local file, not in Git
    python backend/app.py                       # http://127.0.0.1:5000
    # Firestore can be replaced locally with USE_MEMORY_DB=1 (data is lost on restart).
    # Firebase Auth is still required for signup and login.

## Production
    gunicorn --chdir backend app:app
Set `SECRET_KEY`, `FIREBASE_PROJECT_ID`, `FIREBASE_API_KEY`, and
`FIREBASE_CREDENTIALS_JSON` (service-account JSON or its file path), plus
`SESSION_COOKIE_SECURE=1`, `TRUST_PROXY=1`, and `PUBLIC_URL`. Email-based login
confirmation is enabled by default and requires the `SMTP_*` settings; set
`LOGIN_EMAIL_VERIFICATION=0` if that confirmation step is not wanted.

The Firebase project must have Email/Password sign-in enabled. The backend uses
the Firebase Auth REST API for sign-in and the Firebase Admin SDK for Firestore;
the Admin SDK bypasses Firestore security rules. Never commit service-account
credentials. If a service-account key has already been committed, revoke it and
create a replacement.

## Firestore collections
    users, login_challenges (emailed login links), password_resets (reset links), appointment_slots (prevents double booking)
(Firestore creates each collection automatically the first time the server writes to it.)
