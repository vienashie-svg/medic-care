# Medic Care

    backend/app.py        Flask API + serves ../frontend   (Firestore via firebase-admin)
    frontend/             HTML pages, auth.js, languages.js
    firestore.rules       deny-all rules (deploy them in the Firebase console)

## Run locally
    pip install -r backend/requirements.txt
    cp backend/.env.example backend/.env       # fill in SECRET_KEY
    # put the service-account key at backend/firebase-key.json  (git-ignored)
    python backend/app.py                       # http://127.0.0.1:5000
    # no Firebase yet?  USE_MEMORY_DB=1 python backend/app.py   (data lost on restart)

## Production
    gunicorn --chdir backend app:app
Set SECRET_KEY, SESSION_COOKIE_SECURE=1, TRUST_PROXY=1, PUBLIC_URL, FIREBASE_CREDENTIALS_JSON and the SMTP_* variables (see backend/.env.example).

## Firestore collections
    users, login_challenges (emailed login links), password_resets (reset links), appointment_slots (prevents double booking)
(Firestore creates each collection automatically the first time the server writes to it.)
