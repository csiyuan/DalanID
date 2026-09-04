"""
Evaluation harness.

Produces every quantitative result reported in Chapter 5, writing them to
``results/`` as JSON and CSV so that figures can be regenerated and the numbers
traced back to the run that produced them.

Run against a live server::

    python manage.py runserver          # terminal 1
    python evaluate.py                  # terminal 2

Five strands are measured:

1. Disclosure correctness - every context against an independently written
   expectation, not against the seeded configuration.
2. Security refusals - one case per reason code, with expected status.
3. Minimisation - fields released per context against the full schema.
4. Audit integrity - chain verification before and after deliberate tampering.
5. Latency - contextual disclosure against the unprotected baseline.

The oracle in strand 1 matters. The preliminary report acknowledged that its
48/48 result was weakened because expectations and seed data shared a source,
so the test partly confirmed itself. Here the expected field sets are written
out by hand below and compared against what the API returns.
"""

import json
import os
import statistics
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dalanid.settings")
django.setup()

from identity import keys, signatures  # noqa: E402
from identity.models import (  # noqa: E402
    Attribute, AuditEntry, Citizen, Context, Grant, RelyingParty,
)

BASE = "http://127.0.0.1:8000/api/v1"
CITIZEN = "maria-da-costa"
RESULTS = Path(__file__).parent / "results"

# Independently authored expectations. Deliberately not read from the database.
EXPECTED = {
    "immigration": {"legal_name", "passport", "dob"},
    "public_health": {"legal_name", "dob", "vaccination"},
    "banking": {"legal_name", "tax_id", "dob"},
    "insurance": {"dob", "risk"},
    "public_service": {"vid_token"},
    "social": {"nickname"},
}
HOLDER = {
    "immigration": "border-authority",
    "public_health": "ministry-health",
    "banking": "banco-nacional",
    "insurance": "seguros-dili",
    "public_service": "ministry-health",
    "social": "rede-social",
}


def request(method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    for name, value in (headers or {}).items():
        req.add_header(name, value)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        try:
            return error.code, json.loads(error.read())
        except ValueError:
            return error.code, {}


def key_for(rp_slug, ctx_slug):
    return keys.issue_context_key(
        RelyingParty.objects.get(slug=rp_slug),
        Context.objects.get(slug=ctx_slug),
    )


def disclose(rp_slug, ctx_slug):
    return request(
        "GET", f"/profile/{CITIZEN}",
        headers={"X-Context-Key": key_for(rp_slug, ctx_slug)},
    )


# --- Strand 1: disclosure correctness ---------------------------------------

def measure_correctness():
    schema = sorted(Attribute.objects.values_list("code", flat=True))
    rows, passes = [], 0
    for ctx_slug, expected in EXPECTED.items():
        status, body = disclose(HOLDER[ctx_slug], ctx_slug)
        disclosed = set(body.get("disclosed", {}))
        for code in schema:
            should = code in expected
            did = code in disclosed
            ok = should == did
            passes += ok
            rows.append({
                "context": ctx_slug, "attribute": code,
                "expected": "disclose" if should else "withhold",
                "actual": "disclosed" if did else "withheld",
                "result": "pass" if ok else "FAIL",
            })
    return {"cases": len(rows), "passes": passes,
            "failures": len(rows) - passes, "rows": rows}


# --- Strand 2: security refusals --------------------------------------------

def measure_refusals():
    good = key_for("border-authority", "immigration")
    payload, signature = good.split(".")
    cases = []

    def case(label, key, expected_reason, expected_status=401):
        status, body = request(
            "GET", f"/profile/{CITIZEN}",
            headers={"X-Context-Key": key} if key is not None else {},
        )
        cases.append({
            "case": label,
            "expected_status": expected_status,
            "actual_status": status,
            "expected_reason": expected_reason,
            "actual_reason": body.get("reason", ""),
            "result": "pass" if (status == expected_status
                                 and body.get("reason") == expected_reason)
                      else "FAIL",
        })

    case("no key presented", None, keys.MISSING)
    case("not a token", "garbage", keys.MALFORMED)
    case("undecodable payload", "!!!!.!!!!", keys.MALFORMED)
    case("oversized key (10 KB)", "A" * 10000, keys.MALFORMED)
    case("signature: one byte flipped",
         f"{payload}.{'A' if signature[0] != 'A' else 'B'}{signature[1:]}",
         keys.BAD_SIGNATURE)

    social = key_for("rede-social", "social")
    sp, ss = social.split(".")
    claims = json.loads(keys._b64decode(sp))
    claims["ctx"] = "immigration"
    forged = keys._b64encode(
        json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
    )
    case("payload rewritten to a richer context",
         f"{forged}.{ss}", keys.BAD_SIGNATURE)

    other = RelyingParty.objects.get(slug="banco-nacional")
    case("signed with another party's secret",
         f"{payload}.{keys._sign(payload, other.signing_secret)}",
         keys.BAD_SIGNATURE)

    # The expiry case has to be built by hand: issue_context_key clamps a
    # requested lifetime to at least one second, so it cannot mint a key that
    # is already outside its window. The signature must be produced under the
    # party's *registered* suite, since that is what verification will select;
    # signing with the HMAC helper against an Ed25519 party fails at layer 3
    # and never reaches the temporal check this case exists to exercise.
    party = RelyingParty.objects.get(slug="border-authority")
    expired_claims = {
        "rp": party.slug, "ctx": "immigration", "jti": "eval-expired",
        "iat": int(time.time()) - 600, "exp": int(time.time()) - 60,
    }
    expired_claims["alg"] = signatures.ALG_NAME.get(
        party.algorithm, party.algorithm
    )
    expired_payload = keys._b64encode(
        json.dumps(
            expired_claims, sort_keys=True, separators=(",", ":"),
        ).encode()
    )
    expired_sig = keys._b64encode(
        signatures.sign(party.algorithm, expired_payload, party)
    )
    case("expired key", f"{expired_payload}.{expired_sig}", keys.EXPIRED)

    unknown_payload = keys._b64encode(
        json.dumps(
            {"rp": "ghost-agency", "ctx": "immigration", "jti": "eval-ghost",
             "exp": int(time.time()) + 300},
            sort_keys=True, separators=(",", ":"),
        ).encode()
    )
    case("unregistered relying party",
         f"{unknown_payload}.zz", keys.RP_UNKNOWN)

    case("valid signature, no grant held",
         key_for("unaffiliated-vendor", "immigration"), keys.CONTEXT_NOT_GRANTED)

    replayed = key_for("border-authority", "immigration")
    request("GET", f"/profile/{CITIZEN}", headers={"X-Context-Key": replayed})
    case("key replayed", replayed, keys.KEY_REPLAYED)

    Grant.objects.filter(relying_party__slug="border-authority",
                         context__slug="immigration").update(is_active=False)
    case("grant revoked after issuance",
         key_for("border-authority", "immigration"), keys.CONTEXT_NOT_GRANTED)
    Grant.objects.filter(relying_party__slug="border-authority",
                         context__slug="immigration").update(is_active=True)

    Context.objects.filter(slug="immigration").update(is_active=False)
    case("context revoked after issuance",
         key_for("border-authority", "immigration"), keys.CONTEXT_INACTIVE)
    Context.objects.filter(slug="immigration").update(is_active=True)

    RelyingParty.objects.filter(slug="border-authority").update(is_active=False)
    case("relying party deactivated",
         key_for("border-authority", "immigration"), keys.RP_INACTIVE)
    RelyingParty.objects.filter(slug="border-authority").update(is_active=True)

    status, _ = request("GET", "/profile/nobody-here",
                        headers={"X-Context-Key": key_for("border-authority",
                                                          "immigration")})
    cases.append({
        "case": "probe for a non-existent citizen",
        "expected_status": 404, "actual_status": status,
        "expected_reason": "CITIZEN_UNKNOWN",
        "actual_reason": AuditEntry.objects.latest("sequence").reason_code,
        "result": "pass" if status == 404 else "FAIL",
    })

    passes = sum(c["result"] == "pass" for c in cases)
    return {"cases": len(cases), "passes": passes,
            "failures": len(cases) - passes, "rows": cases}


# --- Strand 3: minimisation --------------------------------------------------

def measure_minimisation():
    schema_size = Attribute.objects.count()
    rows = []
    for ctx_slug in EXPECTED:
        _, body = disclose(HOLDER[ctx_slug], ctx_slug)
        rows.append({
            "context": ctx_slug,
            "disclosed": body["fields_permitted"],
            "withheld": body["fields_withheld"],
            "percent_withheld": round(body["minimisation_ratio"] * 100, 1),
            "derived": len(body.get("derived_fields", [])),
        })
    mean_disclosed = statistics.mean(r["disclosed"] for r in rows)
    return {
        "schema_size": schema_size,
        "mean_fields_disclosed": round(mean_disclosed, 2),
        "mean_percent_withheld": round(
            100 * (1 - mean_disclosed / schema_size), 1
        ),
        "rows": rows,
    }


# --- Strand 4: audit integrity ----------------------------------------------

def measure_audit_integrity():
    before_status, before = request("GET", "/audit/verify")

    target = AuditEntry.objects.order_by("sequence")[2]
    original = target.context_slug
    # The mutation must be guaranteed different from the stored value.
    # Choosing a fixed replacement risks picking an entry that already holds
    # it, in which case nothing is altered and the test silently passes.
    target.context_slug = f"tampered-{original or 'blank'}"[:64]
    target.save(update_fields=["context_slug"])

    after_status, after = request("GET", "/audit/verify")

    # Restore, then recompute the hash so the chain is left intact for any
    # later strand. Order matters: recomputing before restoring would bake the
    # tampered value into a now-valid hash.
    target.context_slug = original
    target.entry_hash = target.compute_hash()
    target.save(update_fields=["context_slug", "entry_hash"])

    restored_status, restored = request("GET", "/audit/verify")

    return {
        "entries": before.get("entries"),
        "before_tamper": {"status": before_status, "intact": before["intact"]},
        "after_tamper": {"status": after_status, "intact": after["intact"],
                         "broken_at": after["broken_at_sequence"],
                         "detail": after["detail"]},
        "after_restore": {"status": restored_status,
                          "intact": restored["intact"]},
        "tampered_sequence": target.sequence,
        "detected": (after["intact"] is False
                     and after["broken_at_sequence"] == target.sequence),
    }


# --- Strand 5: latency -------------------------------------------------------

def measure_latency(samples=300):
    def timed(fn):
        values = []
        for _ in range(samples):
            start = time.perf_counter()
            fn()
            values.append((time.perf_counter() - start) * 1000)
        return values

    contextual = timed(lambda: disclose("border-authority", "immigration"))
    baseline = timed(lambda: request("GET", f"/profile/{CITIZEN}/full"))

    def summarise(values):
        ordered = sorted(values)
        return {
            "n": len(values),
            "mean_ms": round(statistics.mean(values), 2),
            "p50_ms": round(statistics.median(values), 2),
            "p95_ms": round(ordered[int(0.95 * len(ordered)) - 1], 2),
            "p99_ms": round(ordered[int(0.99 * len(ordered)) - 1], 2),
        }

    ctx, base = summarise(contextual), summarise(baseline)
    return {
        "contextual": ctx,
        "unprotected_baseline": base,
        "overhead_p50_ms": round(ctx["p50_ms"] - base["p50_ms"], 2),
        "overhead_percent": round(
            100 * (ctx["p50_ms"] - base["p50_ms"]) / base["p50_ms"], 1
        ),
    }


def write_csv(path, rows):
    if not rows:
        return
    columns = list(rows[0])
    lines = [",".join(columns)]
    for row in rows:
        lines.append(",".join(str(row[c]) for c in columns))
    path.write_text("\n".join(lines) + "\n")


def main():
    status, _ = request("GET", "/contexts")
    if status != 200:
        sys.exit("API not reachable. Start the server first.")

    RESULTS.mkdir(exist_ok=True)
    results = {}

    print("1/5 disclosure correctness ...", flush=True)
    results["correctness"] = measure_correctness()
    print("2/5 security refusals ...", flush=True)
    results["refusals"] = measure_refusals()
    print("3/5 minimisation ...", flush=True)
    results["minimisation"] = measure_minimisation()
    print("4/5 audit integrity ...", flush=True)
    results["audit"] = measure_audit_integrity()
    print("5/5 latency ...", flush=True)
    results["latency"] = measure_latency()

    (RESULTS / "results.json").write_text(json.dumps(results, indent=2))
    write_csv(RESULTS / "correctness.csv", results["correctness"]["rows"])
    write_csv(RESULTS / "refusals.csv", results["refusals"]["rows"])
    write_csv(RESULTS / "minimisation.csv", results["minimisation"]["rows"])

    c, r, m = results["correctness"], results["refusals"], results["minimisation"]
    a, l = results["audit"], results["latency"]
    print()
    print("=" * 66)
    print(f"Disclosure correctness : {c['passes']}/{c['cases']} "
          f"({c['failures']} failures)")
    print(f"Security refusals      : {r['passes']}/{r['cases']} "
          f"({r['failures']} failures)")
    print(f"Mean disclosure        : {m['mean_fields_disclosed']}"
          f"/{m['schema_size']} fields "
          f"({m['mean_percent_withheld']}% withheld)")
    print(f"Tamper detection       : {'detected' if a['detected'] else 'MISSED'}"
          f" at entry #{a['after_tamper']['broken_at']}")
    print(f"Latency p50            : {l['contextual']['p50_ms']} ms contextual "
          f"vs {l['unprotected_baseline']['p50_ms']} ms baseline "
          f"({l['overhead_percent']:+}%)")
    print(f"Latency p95            : {l['contextual']['p95_ms']} ms")
    print("=" * 66)
    print(f"Written to {RESULTS}/")


if __name__ == "__main__":
    main()
