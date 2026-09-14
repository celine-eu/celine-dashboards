"""
Dataset access tags — the format `governance sync` writes and the plugin enforces.

No superset imports: the CLI writes these tags and the tests exercise the decision
without installing Superset.

A synced dataset carries in its `extra` JSON:

  celine_access = "open"       any authenticated Superset user
  celine_access = "org"        cross-org realm roles, and org:<slug>:* for a slug in org_slugs
  celine_access = "operators"  Admin only

Anything else — no `celine_access`, an unknown value, unparseable `extra` — is
untagged, and untagged is Admin only. A legacy `org_slugs` without `celine_access`
is deliberately not honoured: a tag the current sync did not write may be stale.
"""
from __future__ import annotations

import json
from typing import Any, Iterable, Optional

ACCESS_KEY = "celine_access"
ORG_SLUGS_KEY = "org_slugs"

ACCESS_OPEN = "open"
ACCESS_ORG = "org"
ACCESS_OPERATORS = "operators"
ACCESS_VALUES = frozenset({ACCESS_OPEN, ACCESS_ORG, ACCESS_OPERATORS})

# Operators see every dataset, tagged or not.
OPERATOR_ROLES = frozenset({"Admin"})
# Realm-level roles: every org's `org` datasets, never `operators` ones.
CROSS_ORG_ROLES = frozenset(
    {"celine:admins", "celine:managers", "celine:editors", "celine:viewers"}
)


def parse_extra(extra: Any) -> dict:
    """Return a dataset's `extra` as a dict; anything unparseable is `{}`."""
    if isinstance(extra, dict):
        return extra
    if not extra:
        return {}
    try:
        parsed = json.loads(extra)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def is_operator(role_names: Iterable[str]) -> bool:
    return any(name in OPERATOR_ROLES for name in role_names)


def is_cross_org(role_names: Iterable[str]) -> bool:
    return any(name in CROSS_ORG_ROLES for name in role_names)


def org_slugs_from_roles(role_names: Iterable[str]) -> set[str]:
    """Slugs of every `org:<slug>:<level>` role."""
    return {
        parts[1]
        for name in role_names
        if len(parts := name.split(":")) == 3 and parts[0] == "org"
    }


def can_see_dataset(extra: Any, role_names: Iterable[str]) -> bool:
    """Whether a user holding `role_names` may read a dataset with this `extra`."""
    role_names = list(role_names)
    if is_operator(role_names):
        return True

    tag = parse_extra(extra)
    access = tag.get(ACCESS_KEY)
    if access == ACCESS_OPEN:
        return True
    if access != ACCESS_ORG:
        return False

    # An org tag naming no org is malformed — the sync writes `operators` instead.
    org_slugs = tag.get(ORG_SLUGS_KEY)
    if not isinstance(org_slugs, list) or not org_slugs:
        return False
    if is_cross_org(role_names):
        return True
    return bool(org_slugs_from_roles(role_names).intersection(org_slugs))


def dataset_filter_sql(
    table_name: str, role_names: Iterable[str]
) -> Optional[tuple[str, dict[str, str]]]:
    """SQL predicate (and bind params) listing the datasets `can_see_dataset` allows.

    Returns None for operators, who need no filter. PostgreSQL only, like the
    Superset metadata database this plugin is deployed against.
    """
    role_names = list(role_names)
    if is_operator(role_names):
        return None

    access = f"({table_name}.extra::jsonb ->> '{ACCESS_KEY}')"
    org_slugs = f"{table_name}.extra::jsonb -> '{ORG_SLUGS_KEY}'"
    conds = [f"{access} = '{ACCESS_OPEN}'"]
    params: dict[str, str] = {}

    if is_cross_org(role_names):
        conds.append(
            # No jsonb_array_length: PostgreSQL does not promise AND short-circuits,
            # and it raises on a scalar.
            f"{access} = '{ACCESS_ORG}' AND jsonb_typeof({org_slugs}) = 'array'"
            f" AND {org_slugs} <> '[]'::jsonb"
        )
    else:
        slug_conds = []
        for i, slug in enumerate(sorted(org_slugs_from_roles(role_names))):
            param = f"slug_{i}"
            params[param] = json.dumps([slug])
            slug_conds.append(f"{org_slugs} @> CAST(:{param} AS jsonb)")
        if slug_conds:
            conds.append(f"({access} = '{ACCESS_ORG}' AND ({' OR '.join(slug_conds)}))")

    return " OR ".join(f"({c})" for c in conds), params
