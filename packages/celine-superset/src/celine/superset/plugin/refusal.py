"""What a request `before_request` will not let through is answered with.

No superset imports, so the tests exercise it without installing Superset (as `access.py`).

A refusal is *returned* from `before_request`, never raised. It used to `abort()` inside a
`try` whose `except Exception` caught the abort and aborted again; Superset's error handler
then read `g.user`, which nothing had set, and every refused API call answered `500`
(`AttributeError: user`) instead of `401` or `403`.
"""

from __future__ import annotations

import urllib.parse

from flask import Response, jsonify, redirect, request


def is_api_request() -> bool:
    return request.path.startswith("/api/")


def _json(status: int, message: str) -> Response:
    response = jsonify({"message": message})
    response.status_code = status
    return response


def unauthenticated() -> Response:
    """No verifiable identity: a page goes to sign-in, an API call is told `401`."""
    if is_api_request():
        return _json(401, "Not authenticated")
    next_url = urllib.parse.quote(request.full_path.rstrip("?"), safe="")
    return redirect(f"/login/?next={next_url}")


def forbidden() -> Response:
    """A verified identity this Superset grants no role: `403` for a page and an API call
    alike. Sending it back to sign-in cannot change the answer, and would loop."""
    if is_api_request():
        return _json(403, "Access denied")
    return Response(
        "Your account has no access to this Superset.", status=403, mimetype="text/plain"
    )
