"""
Field-level disclosure projection.

This is the server-side successor to ``buildResponse()`` in the browser
prototype. The shape of the output is deliberately unchanged, so the existing
React interface can be repointed at the live API without redesign, but the
authority for the decision has moved: the permitted attribute set is now read
from the database and the caller cannot influence it.

Two properties matter for the privacy argument.

*Whitelist, not blacklist.* The projection iterates over the attributes the
context permits and pulls each from the citizen record. It never starts with
the full record and removes fields. A field newly added to the citizen schema
is therefore invisible to every existing context until someone explicitly
grants it — the system fails closed as it grows.

*Minimisation within a field, not only between fields.* An insurance assessor
needs to know an applicant's age band, not their birth date. Returning a raw
date because "date of birth was permitted" discloses more than the purpose
requires. Attributes carrying a ``derivation`` are transformed on the way out,
and the raw value never leaves the process.
"""

from datetime import date

from .models import Attribute

AGE_BANDS = ((18, "under-18"), (25, "18-24"), (35, "25-34"), (50, "35-49"),
             (65, "50-64"), (200, "65-plus"))


def _parse_iso_date(value: str) -> date | None:
    try:
        return date.fromisoformat(value.strip()[:10])
    except (ValueError, AttributeError):
        return None


def _age_on(born: date, today: date) -> int:
    """Whole years elapsed, correcting for birthdays not yet reached."""
    return today.year - born.year - (
        (today.month, today.day) < (born.month, born.day)
    )


def derive(value: str, derivation: str, today: date | None = None) -> str:
    """Apply an attribute's derivation rule to its raw stored value.

    Unknown or unparseable values collapse to ``"unavailable"`` rather than
    falling through to the raw value: a derivation that cannot be computed must
    not silently disclose the thing it was meant to suppress.
    """
    if derivation == Attribute.Derivation.NONE:
        return value

    if derivation == Attribute.Derivation.PRESENCE:
        return "on-file" if value else "absent"

    born = _parse_iso_date(value)
    if born is None:
        return "unavailable"

    if derivation == Attribute.Derivation.YEAR_ONLY:
        return str(born.year)

    if derivation == Attribute.Derivation.AGE_BAND:
        age = _age_on(born, today or date.today())
        for ceiling, label in AGE_BANDS:
            if age < ceiling:
                return label
        return AGE_BANDS[-1][1]

    return "unavailable"


def build_disclosure(citizen, context, today: date | None = None) -> dict:
    """Project a citizen record through a context into a response body."""
    held = citizen.values_map()
    permitted = context.attributes.order_by("code")

    disclosed = {}
    derived_codes = []
    for attribute in permitted:
        if attribute.code not in held:
            # The context permits a field this citizen has no value for.
            # Omit it rather than emitting null, so absence is not itself a
            # disclosure about the citizen.
            continue
        raw = held[attribute.code]
        disclosed[attribute.code] = derive(raw, attribute.derivation, today)
        if attribute.derivation != Attribute.Derivation.NONE:
            derived_codes.append(attribute.code)

    total_schema = Attribute.objects.count()
    return {
        "citizen": citizen.public_id,
        "context": {
            "slug": context.slug,
            "name": context.name,
            "tier": context.tier,
        },
        "fields_permitted": len(disclosed),
        "fields_withheld": total_schema - len(disclosed),
        "schema_size": total_schema,
        "minimisation_ratio": round(
            1 - (len(disclosed) / total_schema), 4
        ) if total_schema else 0.0,
        "derived_fields": sorted(derived_codes),
        "disclosed": disclosed,
    }
