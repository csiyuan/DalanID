"""
API surface.

Three endpoints matter for the argument the project is making:

``/api/v1/profile/<public_id>``
    The contextual endpoint. Requires a verified Context-Key and returns only
    what the named context permits.

``/api/v1/profile/<public_id>/full``
    The unprotected baseline, returning the whole record. It exists so the
    evaluation can quantify what contextual disclosure withholds, and so the
    interface can show the two side by side. It is disabled unless explicitly
    switched on in settings, because an always-available full-record endpoint
    would undo the property the rest of the system exists to provide.

``/api/v1/audit/verify``
    Walks the hash chain and reports whether the disclosure history has been
    altered.
"""

from django.conf import settings
from django.db import transaction
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView

from . import auth, keys, subject
from .disclosure import build_disclosure
from .models import (
    Attribute,
    AuditEntry,
    Citizen,
    Context,
    ContextAttribute,
    Grant,
    RelyingParty,
)
from .permissions import CanCreateContexts, HasValidContextKey
from .serializers import ContextCreateSerializer, GrantCreateSerializer


class ContextualProfileView(APIView):
    """Disclose one citizen record through the context named in the key."""

    permission_classes = [HasValidContextKey]

    def get(self, request, public_id):
        context = request.disclosure_context

        # A lookup for a citizen who does not exist is still an attempt to
        # obtain someone's record, and is the shape a probe for valid
        # identifiers takes. Logging only successful lookups would leave
        # enumeration invisible to the audit trail.
        citizen = Citizen.objects.filter(public_id=public_id).first()
        if citizen is None:
            AuditEntry.record(
                relying_party_slug=request.relying_party.slug,
                context_slug=context.slug,
                citizen_public_id=public_id[:64],
                disclosed_codes=[],
                withheld_count=0,
                outcome="refused",
                reason_code="CITIZEN_UNKNOWN",
            )
            return Response(
                {"error": "not_found",
                 "detail": "No such citizen record."},
                status=status.HTTP_404_NOT_FOUND,
            )

        body = build_disclosure(citizen, context)

        AuditEntry.record(
            relying_party_slug=request.relying_party.slug,
            context_slug=context.slug,
            citizen_public_id=citizen.public_id,
            disclosed_codes=sorted(body["disclosed"].keys()),
            withheld_count=body["fields_withheld"],
            outcome="disclosed",
            reason_code="",
        )

        return Response(body, status=status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes([])
def full_record(request, public_id):
    """Unprotected baseline. Off by default; used for evaluation only."""
    if not getattr(settings, "DALANID_ALLOW_FULL_RECORD", False):
        return Response(
            {
                "error": "full_record_disabled",
                "detail": "The unprotected full-record endpoint is disabled.",
            },
            status=status.HTTP_403_FORBIDDEN,
        )

    citizen = get_object_or_404(Citizen, public_id=public_id)
    held = citizen.values_map()

    AuditEntry.record(
        relying_party_slug="",
        context_slug="__full__",
        citizen_public_id=citizen.public_id,
        disclosed_codes=sorted(held.keys()),
        withheld_count=0,
        outcome="disclosed",
        reason_code="BASELINE",
    )

    return Response(
        {
            "citizen": citizen.public_id,
            "context": {"slug": "__full__", "name": "Full record",
                        "tier": "Unprotected"},
            "fields_permitted": len(held),
            "fields_withheld": 0,
            "schema_size": Attribute.objects.count(),
            "minimisation_ratio": 0.0,
            "derived_fields": [],
            "disclosed": held,
        }
    )


@api_view(["GET"])
@permission_classes([])
def verify_audit_chain(request):
    """Report whether the disclosure log has been tampered with."""
    ok, broken_at, detail = AuditEntry.verify_chain()
    return Response(
        {
            "intact": ok,
            "entries": AuditEntry.objects.count(),
            "broken_at_sequence": broken_at,
            "detail": detail,
        },
        status=status.HTTP_200_OK if ok else status.HTTP_409_CONFLICT,
    )


@api_view(["GET"])
@permission_classes([])
def list_contexts(request):
    """Public catalogue of active contexts and what each may see.

    Publishing this is a privacy feature, not a leak: a citizen cannot reason
    about what a context will disclose unless the mapping is inspectable.
    """
    schema = [
        {"code": a.code, "label": a.label, "sensitivity": a.sensitivity,
         "derivation": a.derivation}
        for a in Attribute.objects.order_by("code")
    ]
    return Response(
        {
            "schema": schema,
            "schema_size": len(schema),
            "contexts": [
                {
                    "slug": context.slug,
                    "name": context.name,
                    "tier": context.tier,
                    "purpose": context.purpose,
                    "permitted": context.permitted_codes(),
                    "field_count": len(context.permitted_codes()),
                    # Which parties may invoke this context. The interface uses
                    # this to request a key as a party that actually holds a
                    # grant, rather than assuming any party may use any
                    # context.
                    "grant_holders": list(
                        Grant.objects.filter(
                            context=context, is_active=True,
                            relying_party__is_active=True,
                        ).values_list("relying_party__slug", flat=True)
                    ),
                }
                for context in Context.objects.filter(is_active=True)
            ],
        }
    )


class ContextCreateView(APIView):
    """Create a new disclosure context at runtime.

    This is the endpoint that makes the extensibility claim real: contexts are
    rows, so a new purpose can be introduced without redeploying the service.

    Authorisation is deliberately doubled. The caller must present a valid
    Context-Key for the ``context-administration`` context - administration is
    itself a context, so the same verification path guards it as guards
    disclosure - *and* hold the ``can_create_contexts`` role. Either check
    alone would be weaker: a stolen administrative key is useless without the
    role, and the role is useless without a live grant.

    Creation does not confer use. A party that defines a context receives no
    grant for it, so it cannot define a context and immediately read through
    it. Authorising a party is a separate, separately audited act.
    """

    permission_classes = [HasValidContextKey, CanCreateContexts]

    def post(self, request):
        serializer = ContextCreateSerializer(data=request.data)
        if not serializer.is_valid():
            AuditEntry.record(
                relying_party_slug=request.relying_party.slug,
                context_slug="",
                disclosed_codes=[],
                withheld_count=0,
                outcome="refused",
                reason_code="CONTEXT_INVALID",
            )
            return Response(
                {"error": "context_invalid", "detail": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

        data = serializer.validated_data
        with transaction.atomic():
            context = Context.objects.create(
                slug=data["slug"],
                name=data["name"],
                tier=data.get("tier", "Custom"),
                purpose=data["purpose"],
                created_by=request.relying_party,
            )
            for code in data["attributes"]:
                ContextAttribute.objects.create(
                    context=context,
                    attribute=Attribute.objects.get(code=code),
                )

        AuditEntry.record(
            relying_party_slug=request.relying_party.slug,
            context_slug=context.slug,
            disclosed_codes=[],
            withheld_count=0,
            outcome="context_created",
            reason_code="",
        )

        return Response(
            {
                "slug": context.slug,
                "name": context.name,
                "tier": context.tier,
                "purpose": context.purpose,
                "permitted": context.permitted_codes(),
                "field_count": len(context.permitted_codes()),
                "created_by": request.relying_party.slug,
                "note": "No grant was created. Authorise a relying party "
                        "separately before this context can be used.",
            },
            status=status.HTTP_201_CREATED,
        )


class GrantCreateView(APIView):
    """Authorise a relying party to invoke a context.

    Separated from context creation so that defining a purpose and being
    permitted to act on it are distinct, individually auditable decisions.
    """

    permission_classes = [HasValidContextKey, CanCreateContexts]

    def post(self, request, slug):
        context = get_object_or_404(Context, slug=slug)
        serializer = GrantCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"error": "grant_invalid", "detail": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

        party = RelyingParty.objects.get(
            slug=serializer.validated_data["relying_party"]
        )
        grant, created = Grant.objects.get_or_create(
            relying_party=party, context=context
        )
        if not created and not grant.is_active:
            grant.is_active = True
            grant.save()

        AuditEntry.record(
            relying_party_slug=request.relying_party.slug,
            context_slug=context.slug,
            disclosed_codes=[],
            withheld_count=0,
            outcome="grant_created",
            reason_code=party.slug,
        )

        return Response(
            {"context": context.slug, "relying_party": party.slug,
             "active": True},
            status=status.HTTP_201_CREATED,
        )


@api_view(["POST"])
@permission_classes([])
def issue_key(request):
    """Mint a Context-Key. Demonstration affordance only.

    In deployment this endpoint would not exist. A relying party holds its own
    signing secret and signs keys locally; sending that secret to the service,
    or having the service sign on the party's behalf, would defeat the point of
    per-party secrets. It exists so the browser interface and the evaluation
    harness can obtain keys without embedding secrets in client-side code, and
    it is disabled unless explicitly switched on.
    """
    if not getattr(settings, "DALANID_ALLOW_KEY_ISSUANCE", False):
        return Response(
            {"error": "issuance_disabled",
             "detail": "Key issuance over HTTP is disabled."},
            status=status.HTTP_403_FORBIDDEN,
        )

    party = RelyingParty.objects.filter(
        slug=request.data.get("relying_party", "")
    ).first()
    context = Context.objects.filter(
        slug=request.data.get("context", "")
    ).first()
    if party is None or context is None:
        return Response(
            {"error": "unknown_party_or_context"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # issue_context_key clamps this itself, but parsing here lets the caller
    # be told their input was rejected rather than silently substituted.
    raw_ttl = request.data.get("ttl_seconds", keys.DEFAULT_TTL_SECONDS)
    try:
        ttl = int(raw_ttl)
    except (TypeError, ValueError):
        return Response(
            {"error": "invalid_ttl",
             "detail": "ttl_seconds must be an integer number of seconds."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if not 1 <= ttl <= keys.MAX_TTL_SECONDS:
        return Response(
            {"error": "invalid_ttl",
             "detail": f"ttl_seconds must be between 1 and "
                       f"{keys.MAX_TTL_SECONDS}."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    return Response(
        {
            "context_key": keys.issue_context_key(party, context, ttl),
            "relying_party": party.slug,
            "context": context.slug,
            "expires_in": ttl,
        }
    )


@api_view(["GET"])
@permission_classes([])
def my_disclosures(request, public_id):
    """Let a citizen read the record of who has seen their data.

    This is the counterpart to the disclosure endpoint. Where that answers "may
    this organisation see this field?", this answers "who has seen mine?" - and
    without it, the audit chain is a control that serves operators while the
    person it is nominally about remains in the dark.

    Refusals are included. A citizen has a legitimate interest in knowing that
    someone attempted access, not only that someone succeeded.
    """
    citizen, reason = subject.verify_subject_token(
        request.META.get("HTTP_X_SUBJECT_TOKEN"), public_id
    )
    if citizen is None:
        return Response(
            {"error": "subject_access_refused", "reason": reason,
             "detail": subject.DETAIL.get(reason, "Refused.")},
            status=status.HTTP_401_UNAUTHORIZED,
        )

    entries = AuditEntry.objects.filter(
        citizen_public_id=citizen.public_id
    ).order_by("-sequence")[:200]

    ok, broken_at, detail = AuditEntry.verify_chain()

    return Response(
        {
            "citizen": citizen.public_id,
            "log_integrity": {
                "intact": ok,
                "broken_at_sequence": broken_at,
                "detail": detail,
            },
            "total": AuditEntry.objects.filter(
                citizen_public_id=citizen.public_id
            ).count(),
            "disclosures": [
                {
                    "sequence": e.sequence,
                    "at": e.occurred_at.isoformat(),
                    "relying_party": e.relying_party_slug or None,
                    "context": e.context_slug or None,
                    "outcome": e.outcome,
                    "reason": e.reason_code or None,
                    "fields": e.disclosed_codes,
                    "withheld": e.withheld_count,
                }
                for e in entries
            ],
        }
    )


@api_view(["POST"])
@permission_classes([])
def issue_subject_token(request):
    """Mint a subject token. Demonstration affordance, as with key issuance.

    A deployment would issue this off the citizen's authenticated session
    rather than on request; see identity/subject.py.
    """
    # Superseded by /auth/login and /auth/verify. Retained only for the
    # evaluation harness, behind its own flag, and off by default: an
    # unauthenticated route to a subject token would defeat the two-factor
    # flow that now guards it.
    if not getattr(settings, "DALANID_ALLOW_UNAUTHENTICATED_SUBJECT_TOKEN", False):
        return Response(
            {"error": "issuance_disabled",
             "detail": "Use /auth/login and /auth/verify."},
            status=status.HTTP_403_FORBIDDEN,
        )
    citizen = Citizen.objects.filter(
        public_id=request.data.get("citizen", "")
    ).first()
    if citizen is None or not citizen.access_secret:
        return Response(
            {"error": "unknown_citizen"}, status=status.HTTP_400_BAD_REQUEST
        )
    return Response(
        {
            "subject_token": subject.issue_subject_token(citizen),
            "citizen": citizen.public_id,
            "expires_in": subject.TOKEN_TTL_SECONDS,
        }
    )


@api_view(["POST"])
@permission_classes([])
def auth_login(request):
    """First factor: identifier and password, returning a login challenge."""
    challenge, reason = auth.begin_login(
        request.data.get("citizen", ""), request.data.get("password", "")
    )
    if challenge is None:
        public = auth.public_reason(reason)
        AuditEntry.record(
            relying_party_slug="", context_slug="__subject__",
            citizen_public_id=str(request.data.get("citizen", ""))[:64],
            disclosed_codes=[], withheld_count=0,
            outcome="refused", reason_code=reason,
        )
        return Response(
            {"error": "auth_refused", "reason": public,
             "detail": auth.DETAIL.get(public, "Refused.")},
            status=status.HTTP_423_LOCKED if reason == auth.LOCKED
            else status.HTTP_401_UNAUTHORIZED,
        )
    return Response(
        {"challenge": challenge, "requires": "totp",
         "expires_in": auth.CHALLENGE_TTL_SECONDS},
        status=status.HTTP_200_OK,
    )


@api_view(["POST"])
@permission_classes([])
def auth_verify(request):
    """Second factor: the time-based code, returning a subject token."""
    citizen, reason = auth.complete_login(
        request.data.get("challenge", ""), request.data.get("code", "")
    )
    if citizen is None:
        AuditEntry.record(
            relying_party_slug="", context_slug="__subject__",
            citizen_public_id="", disclosed_codes=[], withheld_count=0,
            outcome="refused", reason_code=reason,
        )
        return Response(
            {"error": "auth_refused", "reason": reason,
             "detail": auth.DETAIL.get(reason, "Refused.")},
            status=status.HTTP_423_LOCKED if reason == auth.LOCKED
            else status.HTTP_401_UNAUTHORIZED,
        )

    AuditEntry.record(
        relying_party_slug="", context_slug="__subject__",
        citizen_public_id=citizen.public_id,
        disclosed_codes=[], withheld_count=0,
        outcome="subject_authenticated", reason_code="",
    )
    return Response(
        {"subject_token": subject.issue_subject_token(citizen),
         "citizen": citizen.public_id,
         "expires_in": subject.TOKEN_TTL_SECONDS},
        status=status.HTTP_200_OK,
    )
