# ADR-0001 — authority comes from the platform role and from one organisation, nothing else

**Date:** 2026-10-03
**Status:** accepted

## Context

Superset and Jupyter used to grant on Keycloak **realm groups**. Superset mapped realm
`admin(s)`/`manager(s)` to `Admin` and realm `editor(s)` to `celine:managers`, a
cross-organisation role that read every organisation's `org`-tagged datasets. Jupyter let in
anyone in a configured group list, `/admins` by default.

The platform now runs many organisations in one realm, and each organisation has groups with
the same names (`admins`, `managers`, `editors`, `viewers`). A token therefore carried
`admins` at two levels with two meanings, and any reader that flattened them, or guessed
between `admin`, `admins` and `/admins`, could read one organisation's admin as a platform
admin. The platform decided (`celine-policies`) on exactly two levels: the realm **role**
`platform-admin` is the only platform-wide grant, and an organisation's groups are valid only
inside that organisation. Realm groups and the realm roles `admin`/`manager`/`editor`/`viewer`
are removed.

The Superset plugin cannot use `celine-sdk` to read the claims: it runs in Superset's own
interpreter, and apache-superset 6.0.0 pins `cryptography<45` while `celine-sdk` needs
`>=46`.

## Decision

- Superset: `platform-admin` (`realm_access.roles`) maps to `Admin`; an organisation's
  groups (`organization.<slug>.groups`) map to `org:<slug>:<level>` for that slug only. No
  login grants a `celine:*` role; those stay permission templates that `governance sync`
  copies onto `org:<slug>:*`. There is no cross-organisation role.
- Jupyter: access, all or nothing, only for `platform-admin`, read with
  `celine.sdk.auth.is_platform_admin`. It is not configurable.
- Neither reads the top-level `groups` claim. A realm group still present in a token grants
  nothing; so does any realm role other than `platform-admin` and any client role.
- The Superset plugin mirrors `celine.sdk.auth.realm_roles` and `organization_groups` in
  `auth/groups.py`, with the same `PLATFORM_ADMIN_ROLE` value, instead of importing the SDK.
- There is no compatibility path for tokens minted before the change.

## Consequences

- The images must ship with the realm change. Before it, the plugin and authorizer at the
  previous version deny the platform admin, who no longer carries a realm group.
- The mirrored readers can drift from the SDK. They are kept in step by hand; nothing in
  this repository fails when the SDK's readers change.
- The `celine-cli` service account still gets `Admin` by `azp`
  (`CUSTOM_SECURITY_MANAGER_CLI_ADMIN_AZP`): service tokens carry no realm roles, so it has
  no `platform-admin` to carry. It is the one `Admin` grant not made by the role.
- A `celine:*` role assigned by hand in the Superset UI still holds Alpha's
  `all_datasource_access`, and Superset paths that check that permission directly honour it.
  Nothing grants one at login.
- Re-adding a cross-organisation role, or reading `groups` "for convenience", reopens the
  ambiguity this record closes. It would need a new ADR that supersedes this one.
