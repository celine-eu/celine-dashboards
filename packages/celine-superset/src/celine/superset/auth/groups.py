"""
Map Keycloak group paths to Superset roles and extract org membership.

KC group path conventions:
  Realm-level:  /<group>           e.g. /realm_admin, /realm_manager
  Org-level:    /<org-slug>/<role>  e.g. /rec-rome/admin, /rec-rome/viewer

Superset role mapping:
  Admin  — realm admin/manager: full RW, can bind resources to any org
  Alpha  — org admin/manager: create & edit within org (differentiated by RLS)
  Gamma  — org operator/viewer: read-only on org-bound resources (differentiated by RLS)
  Public — fallback when no group matches
"""
from dataclasses import dataclass, field

DEFAULT_ROLE = "Public"

_REALM_ADMIN_GROUPS = frozenset({"realm_admin", "realm_manager", "admins", "managers"})
_ORG_EDITOR_ROLES = frozenset({"admin", "manager"})
_ORG_READER_ROLES = frozenset({"operator", "viewer"})


@dataclass
class ResolvedAccess:
    superset_roles: list[str] = field(default_factory=list)
    org_slugs: list[str] = field(default_factory=list)


def resolve_access(groups: list[str] | str) -> ResolvedAccess:
    """
    Parse a list of KC group paths into Superset role names and org slugs.

    org_slugs is populated for future RLS filter setup — callers may store it
    on the user record to scope dataset access per organisation.
    """
    if isinstance(groups, str):
        groups = [groups]

    roles: set[str] = set()
    org_slugs: list[str] = []

    for group in groups:
        parts = [p for p in group.strip("/").split("/") if p]
        if not parts:
            continue

        if len(parts) == 1:
            if parts[0] in _REALM_ADMIN_GROUPS:
                roles.add("Admin")

        elif len(parts) == 2:
            org_slug, role_name = parts
            org_slugs.append(org_slug)
            if role_name in _ORG_EDITOR_ROLES:
                roles.add("Alpha")
            elif role_name in _ORG_READER_ROLES:
                roles.add("Gamma")

    return ResolvedAccess(
        superset_roles=sorted(roles) if roles else [DEFAULT_ROLE],
        org_slugs=org_slugs,
    )
