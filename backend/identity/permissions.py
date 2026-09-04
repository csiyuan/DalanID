"""
Request-level enforcement of Context-Key verification.

The verification itself lives in :mod:`identity.keys`; this module is the thin
bridge that runs it for every incoming request and refuses the ones that fail.
Keeping the two apart means the security logic is testable without constructing
HTTP requests, and the same verifier can be reused by a future gRPC or message
consumer without dragging DRF along with it.

Every refusal is written to the audit chain before the response is returned. A
log that records only successful disclosures cannot answer the question an
investigator actually asks after a breach, which is who *attempted* access.
"""

from rest_framework.exceptions import APIException
from rest_framework.permissions import BasePermission

from . import keys
from .models import AuditEntry

HEADER = "HTTP_X_CONTEXT_KEY"


class ContextKeyRefused(APIException):
    """401 carrying the specific reason the key was refused."""

    status_code = 401
    default_code = "context_key_refused"

    def __init__(self, verification: keys.KeyVerification):
        # The response carries the *public* reason, which may be coarser than
        # the audited one. See keys.PUBLIC_REASON for why.
        self.reason = verification.public_reason or verification.reason
        super().__init__(
            {
                "error": "context_key_refused",
                "reason": self.reason,
                "detail": verification.detail,
            }
        )


class HasValidContextKey(BasePermission):
    """Require a Context-Key that passes all five verification layers.

    On success the resolved relying party and context are attached to the
    request, so views never re-read the header and cannot accidentally trust an
    unverified claim.
    """

    def has_permission(self, request, view):
        # consume, not merely verify: presenting a key spends it.
        verification = keys.consume_context_key(request.META.get(HEADER))

        if not verification.ok:
            claims = verification.claims or {}
            AuditEntry.record(
                relying_party_slug=str(claims.get("rp", ""))[:64],
                context_slug=str(claims.get("ctx", ""))[:64],
                citizen_public_id=str(
                    view.kwargs.get("public_id", "")
                )[:64] if hasattr(view, "kwargs") else "",
                disclosed_codes=[],
                withheld_count=0,
                outcome="refused",
                reason_code=verification.reason,
            )
            raise ContextKeyRefused(verification)

        request.relying_party = verification.relying_party
        request.disclosure_context = verification.context
        return True


class CanCreateContexts(BasePermission):
    """Restrict context creation to relying parties holding that role.

    Context creation is the one operation that changes what the system will
    disclose in future, so it is gated separately from disclosure itself. An
    airline able to read passport data must not thereby be able to define a new
    context granting itself vaccination records.
    """

    message = "This relying party may not create contexts."

    def has_permission(self, request, view):
        relying_party = getattr(request, "relying_party", None)
        if relying_party is None or not relying_party.can_create_contexts:
            AuditEntry.record(
                relying_party_slug=(
                    relying_party.slug if relying_party else ""
                ),
                context_slug="",
                disclosed_codes=[],
                withheld_count=0,
                outcome="refused",
                reason_code="ROLE_NOT_PERMITTED",
            )
            return False
        return True
