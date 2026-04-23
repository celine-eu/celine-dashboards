"""
Map Keycloak claims to Superset roles and extract org membership.

KC claim structure:
  claims.groups                         — realm-level groups (or None)
  claims.organization.<slug>.groups     — org-level groups per org

Role mapping:
  Realm  admin | manager (+ plurals)  → Admin             (sysadmin, full bypass)
  Realm  editor | editors             → celine:managers   (cross-org power user)
  Realm  viewers | *                  → celine:viewers    (cross-org read-only)
  Org    admins                       → org:<slug>:admins
  Org    managers                     → org:<slug>:managers
  Org    editors                      → org:<slug>:editors
  Org    viewers | *                  → org:<slug>:viewers
  Org member, no group                → org:<slug>:viewers
  No matching claim                   → denied

Org users receive only their org:<slug>:<level> role — never a celine:* base role.
celine:* roles are reserved for realm-level (cross-org) users.
Permissions for org:<slug>:* roles are seeded by `governance sync` from the
corresponding celine:* role (Gamma for viewers, Alpha for editors/managers/admins).
"""
from dataclasses import dataclass, field

_REALM_ADMIN_ROLES = frozenset({"admin", "realm_admin", "admins", "manager", "realm_manager", "managers"})
_REALM_MANAGER_GROUPS = frozenset({"editor", "editors"})

# KC org group name → org role level suffix
_ORG_LEVEL_MAP = {"admins": "admins", "managers": "managers", "editors": "editors"}

CELINE_BASE_ROLES = ("celine:viewers", "celine:editors", "celine:managers", "celine:admins")


@dataclass
class ResolvedAccess:
    superset_roles: list[str] = field(default_factory=list)
    org_slugs: list[str] = field(default_factory=list)
    org_role_names: list[str] = field(default_factory=list)


def _group_name(group: str) -> str:
    """Return terminal path segment: '/admins' → 'admins', 'viewers' → 'viewers'."""
    return group.strip("/").rsplit("/", 1)[-1] if group else ""


def resolve_access(claims: dict) -> ResolvedAccess:
    """
    Parse KC JWT claims into Superset role names, org slugs, and org-level role names.

    Reads realm groups from claims.groups and org groups from
    claims.organization.<slug>.groups.
    """
    raw_realm = claims.get("groups") or []
    if isinstance(raw_realm, str):
        raw_realm = [raw_realm]

    organization: dict = claims.get("organization") or {}

    roles: set[str] = set()
    org_slugs: list[str] = []
    org_role_names: list[str] = []

    # Realm-level groups → cross-org Superset role
    for group in raw_realm:
        name = _group_name(group)
        if not name:
            continue
        if name in _REALM_ADMIN_ROLES:
            roles.add("Admin")
        elif name in _REALM_MANAGER_GROUPS:
            roles.add("celine:managers")
        else:
            roles.add("celine:viewers")

    # Org-level groups → org:<slug>:<level> scoping role only (no celine:* base)
    for org_slug, org_data in organization.items():
        if org_slug not in org_slugs:
            org_slugs.append(org_slug)

        org_groups = (org_data or {}).get("groups") or []
        if isinstance(org_groups, str):
            org_groups = [org_groups]

        if org_groups:
            for group in org_groups:
                name = _group_name(group)
                if not name:
                    continue
                level = _ORG_LEVEL_MAP.get(name, "viewers")
                org_role_name = f"org:{org_slug}:{level}"
                if org_role_name not in org_role_names:
                    org_role_names.append(org_role_name)
        else:
            # Org member with no explicit group → minimum read access
            org_role_name = f"org:{org_slug}:viewers"
            if org_role_name not in org_role_names:
                org_role_names.append(org_role_name)

    return ResolvedAccess(
        superset_roles=sorted(roles),
        org_slugs=org_slugs,
        org_role_names=org_role_names,
    )
