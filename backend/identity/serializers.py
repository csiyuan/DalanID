"""
Input validation for the administrative endpoints.

Validation here is a privacy control, not a formality. The extensibility
claim, that new contexts are data and can be added at runtime, is only
defensible if creating a context cannot be used to reconstruct the full
record. Three rules enforce that:

*A purpose is mandatory.* A context is a declared reason for disclosure. One
created without a stated purpose cannot afterwards be audited against the
purpose it claimed, so the field is required and must be substantive.

*Breadth is capped.* Without a ceiling, an authorised party could define a
context permitting all eight attributes and obtain the unprotected record
through a legitimate-looking route. ``DALANID_MAX_CONTEXT_FIELDS`` bounds this.

*Sensitivity is bounded.* Combining several high-sensitivity attributes is more
revealing than the count alone suggests. A context whose summed sensitivity
exceeds ``DALANID_MAX_CONTEXT_SENSITIVITY`` is refused even if it is within the
field cap, so three maximally sensitive fields cannot slip through a rule that
only counts to five.
"""

from django.conf import settings
from rest_framework import serializers

from .models import Attribute, Context, RelyingParty

MAX_FIELDS_DEFAULT = 5
MAX_SENSITIVITY_DEFAULT = 12


class ContextCreateSerializer(serializers.Serializer):
    """Validate a proposed new disclosure context."""

    slug = serializers.SlugField(max_length=64)
    name = serializers.CharField(max_length=128)
    tier = serializers.CharField(max_length=32, required=False,
                                 default="Custom")
    purpose = serializers.CharField(min_length=20, max_length=500)
    attributes = serializers.ListField(
        child=serializers.SlugField(max_length=64),
        allow_empty=False,
    )

    def validate_slug(self, value):
        if Context.objects.filter(slug=value).exists():
            raise serializers.ValidationError(
                "A context with this slug already exists."
            )
        return value

    def validate_attributes(self, value):
        codes = list(dict.fromkeys(value))  # de-duplicate, preserve order

        max_fields = getattr(
            settings, "DALANID_MAX_CONTEXT_FIELDS", MAX_FIELDS_DEFAULT
        )
        if len(codes) > max_fields:
            raise serializers.ValidationError(
                f"A context may permit at most {max_fields} attributes; "
                f"{len(codes)} were requested."
            )

        known = {
            attribute.code: attribute
            for attribute in Attribute.objects.filter(code__in=codes)
        }
        unknown = [code for code in codes if code not in known]
        if unknown:
            raise serializers.ValidationError(
                f"Unknown attributes: {', '.join(sorted(unknown))}."
            )

        max_sensitivity = getattr(
            settings,
            "DALANID_MAX_CONTEXT_SENSITIVITY",
            MAX_SENSITIVITY_DEFAULT,
        )
        total = sum(known[code].sensitivity for code in codes)
        if total > max_sensitivity:
            raise serializers.ValidationError(
                f"Combined sensitivity {total} exceeds the permitted maximum "
                f"of {max_sensitivity} for a single context."
            )

        return codes


class GrantCreateSerializer(serializers.Serializer):
    """Validate authorisation of one relying party for one context."""

    relying_party = serializers.SlugField(max_length=64)

    def validate_relying_party(self, value):
        party = RelyingParty.objects.filter(slug=value).first()
        if party is None:
            raise serializers.ValidationError(
                "No such relying party is registered."
            )
        if not party.is_active:
            raise serializers.ValidationError(
                "That relying party is not active."
            )
        return value
