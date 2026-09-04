# DalanID API

Privacy-by-design identity disclosure service for Timor-Leste's national
digital identity, built with Django REST Framework.

One citizen record, many minimal views. A relying party presents a signed
Context-Key naming the purpose it is acting under; the service verifies the
key, resolves the purpose to a permitted attribute set, and returns only those
fields. Contexts are stored as data, so new ones can be introduced at runtime
by an authorised party without redeploying.

All personal data in this repository is synthetic.

## Run

    python -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    python manage.py migrate
    python manage.py seed_demo
    python manage.py runserver

## Test

    python manage.py test identity

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/profile/<id>` | Context-Key | Contextual disclosure |
| GET | `/api/v1/profile/<id>/full` | none | Unprotected baseline (evaluation only) |
| GET | `/api/v1/contexts` | none | Catalogue of active contexts |
| GET | `/api/v1/audit/verify` | none | Verify the disclosure log's hash chain |

## Context-Keys

A Context-Key is `base64url(payload).base64url(HMAC-SHA256(payload, secret))`,
where the payload binds relying party, context and expiry. Verification runs in
five layers, each with its own reason code:

| Layer | Checks | Reason codes |
|---|---|---|
| Structural | Token is well-formed | `CTXKEY_MISSING`, `CTXKEY_MALFORMED` |
| Identity | Party is registered and active | `RP_UNKNOWN`, `RP_INACTIVE` |
| Cryptographic | Signature verifies | `CTXKEY_BAD_SIGNATURE` |
| Temporal | Key has not expired | `CTXKEY_EXPIRED` |
| Authorisation | Context live, grant held | `CONTEXT_UNKNOWN`, `CONTEXT_INACTIVE`, `CONTEXT_NOT_GRANTED` |

Possessing a valid signature is not sufficient. The party must also hold a live
grant for the context named in the key.

## Layout

    identity/keys.py         Context-Key issuance and verification
    identity/permissions.py  Request-level enforcement
    identity/disclosure.py   Field projection and derived attributes
    identity/models.py       Domain models and the audit chain
