# DalanID Prototype (front end)

Interactive demonstration of contextual profile disclosure. The interface is a
thin client: it computes nothing. Every field it displays arrives from the
Django service, which verifies a signed Context-Key and decides what may be
released.

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

- **Context selector** — each choice is a fresh authenticated request.
- **Date of birth** — shows an age band, never the raw date. The `derived`
  badge marks fields transformed before release.
- **Compare** — two contexts side by side, two separate API calls.
- **New context** — posts to the role-gated creation endpoint. Try requesting
  all eight fields and the server will refuse it.
- **Verify audit chain** — walks the hash-linked disclosure log.

## Layout

    src/api.js    the only module that talks to the API
    src/App.jsx   presentation; holds no disclosure logic
