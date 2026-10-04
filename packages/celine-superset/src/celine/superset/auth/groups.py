"""
Map Keycloak claims to Superset roles and extract org membership.

There are exactly two levels of authority, and they are read from two different claims:

  claims.realm_access.roles             — platform level: realm roles
  claims.organization.<slug>.groups     — organisation level: valid in that org only

Role mapping:
  Realm role  platform-admin            → Admin             (sysadmin, full bypass)
  Org    admins                         → org:<slug>:admins
  Org    managers                       → org:<slug>:managers
  Org    editors                        → org:<slug>:editors
  Org    viewers | *                    → org:<slug>:viewers
  Org member, no group                  → org:<slug>:viewers
  Anything else                         → denied

The top-level `groups` claim (realm groups such as `/admins`) is never read: a realm group
still present in a token grants nothing. Neither do realm roles other than
`platform-admin` (the retired `admin`/`manager`/`editor`/`viewer` included), nor
`resource_access.<client>.roles`.

An organisation's `admins` is that organisation's admin, never a platform admin, and no
organisation group reaches another organisation: there is no cross-organisation role.
The celine:* roles are only the permission templates `governance sync` copies onto
org:<slug>:* roles (Gamma for viewers, Alpha for editors/managers/admins); nobody is
granted one at login.

Why not celine-sdk: this module runs inside Superset's own interpreter, and
apache-superset 6.0.0 pins `cryptography<45` while celine-sdk needs `>=46`. The two
readers below mirror `celine.sdk.auth.realm_roles` and `organization_groups`; keep them
in step.
"""
from dataclasses import dataclass, field
from typing import Any

#: The one platform-wide grant: a Keycloak realm role. Same value as
#: `celine.sdk.auth.PLATFORM_ADMIN_ROLE`.
PLATFORM_ADMIN_ROLE = "platform-admin"

# KC org group name → org role level suffix
_ORG_LEVEL_MAP = {"admins": "admins", "managers": "managers", "editors": "editors"}

CELINE_BASE_ROLES = ("celine:viewers", "celine:editors", "celine:managers", "celine:admins")


@dataclass
class ResolvedAccess:
    superset_roles: list[str] = field(default_factory=list)
    org_slugs: list[str] = field(default_factory=list)
    org_role_names: list[str] = field(default_factory=list)


def realm_roles(claims: dict) -> list[str]:
    """Realm roles from `realm_access.roles` only. Deduplicated, order kept.

    Never `groups`, a top-level `roles`, or `resource_access`. Anything of the wrong
    shape gives [].
    """
    access = claims.get("realm_access") if isinstance(claims, dict) else None
    if not isinstance(access, dict):
        return []
    roles = access.get("roles")
    if not isinstance(roles, (list, tuple)):
        return []
    out: list[str] = []
    for role in roles:
        if isinstance(role, str) and role and role not in out:
            out.append(role)
    return out


def is_platform_admin(claims: dict) -> bool:
    """True exactly when the caller holds the realm role `platform-admin`."""
    return PLATFORM_ADMIN_ROLE in realm_roles(claims)


def _group_name(group: str) -> str:
    """Return terminal path segment: '/admins' → 'admins', 'viewers' → 'viewers'."""
    return group.strip("/").rsplit("/", 1)[-1] if group else ""


def _org_groups(org_data: Any) -> list[str]:
    """Group names held inside one organisation. A non-list `groups` is ignored."""
    if not isinstance(org_data, dict):
        return []
    groups = org_data.get("groups")
    if not isinstance(groups, (list, tuple)):
        return []
    out: list[str] = []
    for group in groups:
        if not isinstance(group, str):
            continue
        name = _group_name(group)
        if name and name not in out:
            out.append(name)
    return out


def resolve_access(claims: dict) -> ResolvedAccess:
    """
    Parse KC JWT claims into Superset role names, org slugs, and org-level role names.

    Platform level from `realm_access.roles` (`platform-admin` only); organisation level
    from `organization.<slug>.groups`, each scoped to its own slug.
    """
    roles: set[str] = set()
    org_slugs: list[str] = []
    org_role_names: list[str] = []

    if is_platform_admin(claims):
        roles.add("Admin")

    organization = claims.get("organization") if isinstance(claims, dict) else None
    if not isinstance(organization, dict):
        organization = {}

    # Org-level groups → org:<slug>:<level> scoping role only (no celine:* base)
    for org_slug in sorted(str(slug) for slug in organization):
        org_slugs.append(org_slug)
        names = _org_groups(organization.get(org_slug))
        # Org member with no explicit group → minimum read access
        levels = [_ORG_LEVEL_MAP.get(name, "viewers") for name in names] or ["viewers"]
        for level in levels:
            org_role_name = f"org:{org_slug}:{level}"
            if org_role_name not in org_role_names:
                org_role_names.append(org_role_name)

    return ResolvedAccess(
        superset_roles=sorted(roles),
        org_slugs=org_slugs,
        org_role_names=org_role_names,
    )
