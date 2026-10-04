"""What a caller may do on the Jupyter server: everything if a platform administrator, else nothing."""

from __future__ import annotations

from typing import Any

from jupyter_server.auth.authorizer import Authorizer

from celine.jupyter.identity import JWTIdentityProvider


class JWTAuthorizer(Authorizer):
    """All-or-nothing access for platform administrators.

    Access is granted exactly when the request's access token, verified against the one
    trusted issuer by :class:`~celine.jupyter.identity.JWTIdentityProvider`, carries the
    Keycloak realm role ``platform-admin`` (``realm_access.roles``). Nothing else grants it:
    not an organisation's ``admins`` group, not a realm group such as ``/admins`` still
    present in the ``groups`` claim, not any other realm or client role, not Jupyter's own
    server token.

    It works only together with that identity provider and refuses every request otherwise.
    """

    def is_authorized(self, handler: Any, user: Any, action: str, resource: str) -> bool:
        if user is None:
            return False
        identity = self.identity_provider
        if not isinstance(identity, JWTIdentityProvider):
            self.log.error(
                "JWTAuthorizer needs celine.jupyter.identity.JWTIdentityProvider, not %s: request refused",
                type(identity).__name__,
            )
            return False
        # Platform administrators: full access (including terminals). No access for others.
        return identity.platform_admin_claims(handler) is not None
