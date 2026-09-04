# DalanID

[![tests](https://github.com/csiyuan/DalanID/actions/workflows/tests.yml/badge.svg)](https://github.com/csiyuan/DalanID/actions/workflows/tests.yml)

A privacy-by-design REST API for contextual profile disclosure, with a browser
client that demonstrates it.

DalanID separates a citizen's core identity from the disclosure of their
profile. A relying party presents a signed Context-Key naming a purpose; the
service verifies it through five layers and returns only the fields that
purpose permits. Which fields a context may see are rows in the database, not
branches in code.

    backend/   Django REST Framework service - the system itself
    src/       React client; a thin renderer that computes nothing

The interface decides nothing. Every field it displays arrives from the
service, which alone determines what may be released.

All data is fictional.

## Run

The API must be running first (see `backend/README.md`):

    cd backend && python manage.py runserver

Then:

    npm install
    npm run dev

Open the printed URL, usually http://localhost:5173.

Point the client elsewhere with `VITE_API_BASE`:

    VITE_API_BASE=http://127.0.0.1:8000/api/v1 npm run dev

## What to look at

- **Context selector** - each choice is a fresh authenticated request.
- **Date of birth** - shows an age band, never the raw date. The `derived`
  badge marks fields transformed before release.
- **Compare** - two contexts side by side, two separate API calls.
- **New context** - posts to the role-gated creation endpoint. Try requesting
  all eight fields and the server will refuse it.
- **Verify audit chain** - walks the hash-linked disclosure log.

## Layout

    backend/identity/keys.py         five-layer Context-Key verification
    backend/identity/signatures.py   Ed25519 and HMAC suites
    backend/identity/disclosure.py   projection and derivation
    backend/identity/models.py       contexts, grants, hash-chained audit log
    backend/identity/auth.py         citizen two-factor authentication

    src/api.js                       the only module that talks to the API
    src/App.jsx                      presentation; holds no disclosure logic

## Tests

    cd backend && python manage.py test identity
