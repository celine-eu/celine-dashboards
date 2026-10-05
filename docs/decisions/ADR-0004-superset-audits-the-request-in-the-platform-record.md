# ADR-0004 — Superset audits each request after its response, in the platform's record, emitted by the plugin

**Date:** 2026-10-05
**Status:** accepted

## Context

The platform records who read what, and who was refused, in one record shape on the logger
`celine.audit` (`celine.sdk.audit`), so one log query answers the question for every service.
The SDK's helpers read a Starlette request and hook FastAPI; Superset is Flask, and its plugin
does not import `celine-sdk` (ADR-0003).

Superset already has an event logger (`EVENT_LOGGER`, written to the `logs` table). It runs
only around the handlers Superset decorated, never for a request `before_request` refuses; it
is skipped when a handler raises; it does not know the response status; and its payload holds
the request body, SQL text included, and the Superset user id, whose username is the token's
`preferred_username` or email.

## Decision

- The plugin emits the record itself (`celine.superset.plugin.audit`), field for field the
  SDK's: same logger, same fields in the same order, same backstops (email-shaped values
  pseudonymised, control characters dropped, 256-character cap).
- `before_request` keeps the verified claims for the request and registers one
  `after_this_request` callback, which writes at most one record from the response status: an
  allowed read from a fixed list of endpoints, any 401/403 with a verified caller, a listed read
  that failed. A refusal `before_request` answers itself is recorded there, with a reason code.
- The dataset tag check only notes its reason: Superset also runs it to decide what to show and
  turns the refusal into `False`, so only the response says whether the request was refused.
- The caller is `sub` and `azp`. SQL Lab is recorded as the database id and a SHA-256 of the
  statement, never the text.
- The event logger and its `logs` table are left as they are.

## Consequences

- The record shape exists twice. A change to `celine.sdk.audit` must be made in the plugin
  too; depending on the SDK from the plugin would remove the copy, but the SDK's request
  helpers would still need a Flask variant.
- An endpoint missing from the list is recorded only when it refuses. New Superset versions
  add and rename endpoints; the list is checked against `superset routes` on an upgrade.
- A request refused before the security manager runs (Flask-WTF's CSRF check, answered `400`)
  is not recorded: there is no verified caller yet.
- The hash of a statement names it without carrying it; whoever holds Superset's `query`
  table can still match it, which is the point.
