"""
User resolution logic — no superset imports at module level.

SecurityManagerProtocol lets tests inject a plain Mock without installing
apache-superset as a test dependency.
"""

import json
import logging
import os
from typing import Any, Protocol

from celine.superset.auth.groups import resolve_access

logger = logging.getLogger(__name__)

# Comma-separated KC client_id values whose service-account tokens receive
# Admin role unconditionally (no groups claim required).
# These are trusted machine clients (e.g. the CLI) — not end users.
_CLI_ADMIN_AZP: frozenset[str] = frozenset(
    c.strip()
    for c in os.getenv("CUSTOM_SECURITY_MANAGER_CLI_ADMIN_AZP", "celine-cli").split(",")
    if c.strip()
)


class SecurityManagerProtocol(Protocol):
    @property
    def auth_roles_sync_at_login(self) -> bool: ...
    @property
    def auth_user_registration(self) -> bool: ...

    def find_user(self, username: str) -> Any: ...
    def find_role(self, name: str) -> Any: ...
    def add_user(
        self, username: str, first_name: str, last_name: str, email: str, role: list
    ) -> Any: ...
    def update_user(self, user: Any) -> None: ...
    def update_user_auth_stat(self, user: Any) -> None: ...


def resolve_superset_user(sm: SecurityManagerProtocol, claims: dict) -> Any:
    """
    Upsert a Superset user from verified KC JWT claims.

    - KC service accounts (azp in CLI_ADMIN_AZP) always get Admin role.
    - Other users: Superset roles resolved from KC group paths via resolve_access().
    - Users with no matching KC group are denied (returns None).
    - Stores org_slugs as JSON in user.extra for downstream RLS setup.
    """
    username = (
        claims.get("preferred_username")
        or claims.get("email")
        or claims.get("azp")
        or claims.get("sub")
    )
    if not username:
        logger.warning(
            "resolve_superset_user: no username in claims (sub=%s)", claims.get("sub")
        )
        return None

    azp = claims.get("azp")
    if azp in _CLI_ADMIN_AZP:
        # Trusted machine client — give Admin unconditionally
        access_roles = ["Admin"]
        org_slugs: list[str] = []
        org_role_names: list[str] = []
    else:
        access = resolve_access(claims)
        access_roles = access.superset_roles
        org_slugs = access.org_slugs
        org_role_names = access.org_role_names

    roles = [r for name in access_roles if (r := sm.find_role(name)) is not None]

    # org:<slug>:<level> roles are provisioned by `governance sync`; silently skipped if absent
    for org_role_name in org_role_names:
        org_role = sm.find_role(org_role_name)
        if org_role is not None and org_role not in roles:
            roles.append(org_role)

    logger.debug(
        "resolve_superset_user: username=%s azp=%s access_roles=%s org_slugs=%s org_role_names=%s resolved_roles=%s",
        username,
        azp,
        access_roles,
        org_slugs,
        org_role_names,
        [r.name for r in roles],
    )
    if not roles:
        logger.warning(
            "resolve_superset_user: username=%s has no matching Superset roles — access denied",
            username,
        )
        return None

    user = sm.find_user(username=username)

    if user:
        if sm.auth_roles_sync_at_login:
            user.roles = roles
            if org_slugs:
                user.extra = json.dumps({"org_slugs": org_slugs})
            sm.update_user(user)
        sm.update_user_auth_stat(user)
        return user

    if not sm.auth_user_registration:
        logger.warning(
            "resolve_superset_user: user %s not found and registration disabled",
            username,
        )
        return None

    logger.info(
        "resolve_superset_user: creating new user username=%s email=%s roles=%s",
        username,
        claims.get("email", f"{username}@local"),
        [r.name for r in roles],
    )
    user = sm.add_user(
        username=username,
        first_name=claims.get("given_name", "Service"),
        last_name=claims.get("family_name", "Account"),
        email=claims.get("email", f"{username}@local"),
        role=roles,
    )

    if user:
        if org_slugs:
            user.extra = json.dumps({"org_slugs": org_slugs})
            sm.update_user(user)
        sm.update_user_auth_stat(user)
    else:
        logger.error(
            "resolve_superset_user: add_user returned falsy for username=%s — DB error?",
            username,
        )

    return user
