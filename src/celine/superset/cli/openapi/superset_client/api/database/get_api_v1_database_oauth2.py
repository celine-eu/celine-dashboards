from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_database_oauth_2_response_400 import GetApiV1DatabaseOauth2Response400
from ...models.get_api_v1_database_oauth_2_response_404 import GetApiV1DatabaseOauth2Response404
from ...models.get_api_v1_database_oauth_2_response_500 import GetApiV1DatabaseOauth2Response500
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    state: str | Unset = UNSET,
    code: str | Unset = UNSET,
    scope: str | Unset = UNSET,
    error: str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["state"] = state

    params["code"] = code

    params["scope"] = scope

    params["error"] = error

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/database/oauth2/",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetApiV1DatabaseOauth2Response400
    | GetApiV1DatabaseOauth2Response404
    | GetApiV1DatabaseOauth2Response500
    | str
    | None
):
    if response.status_code == 200:
        response_200 = response.text
        return response_200

    if response.status_code == 400:
        response_400 = GetApiV1DatabaseOauth2Response400.from_dict(response.json())

        return response_400

    if response.status_code == 404:
        response_404 = GetApiV1DatabaseOauth2Response404.from_dict(response.json())

        return response_404

    if response.status_code == 500:
        response_500 = GetApiV1DatabaseOauth2Response500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    GetApiV1DatabaseOauth2Response400 | GetApiV1DatabaseOauth2Response404 | GetApiV1DatabaseOauth2Response500 | str
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    state: str | Unset = UNSET,
    code: str | Unset = UNSET,
    scope: str | Unset = UNSET,
    error: str | Unset = UNSET,
) -> Response[
    GetApiV1DatabaseOauth2Response400 | GetApiV1DatabaseOauth2Response404 | GetApiV1DatabaseOauth2Response500 | str
]:
    """Receive personal access tokens from OAuth2

     -> Receive and store personal access tokens from OAuth for user-level authorization

    Args:
        state (str | Unset):
        code (str | Unset):
        scope (str | Unset):
        error (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1DatabaseOauth2Response400 | GetApiV1DatabaseOauth2Response404 | GetApiV1DatabaseOauth2Response500 | str]
    """

    kwargs = _get_kwargs(
        state=state,
        code=code,
        scope=scope,
        error=error,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    state: str | Unset = UNSET,
    code: str | Unset = UNSET,
    scope: str | Unset = UNSET,
    error: str | Unset = UNSET,
) -> (
    GetApiV1DatabaseOauth2Response400
    | GetApiV1DatabaseOauth2Response404
    | GetApiV1DatabaseOauth2Response500
    | str
    | None
):
    """Receive personal access tokens from OAuth2

     -> Receive and store personal access tokens from OAuth for user-level authorization

    Args:
        state (str | Unset):
        code (str | Unset):
        scope (str | Unset):
        error (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1DatabaseOauth2Response400 | GetApiV1DatabaseOauth2Response404 | GetApiV1DatabaseOauth2Response500 | str
    """

    return sync_detailed(
        client=client,
        state=state,
        code=code,
        scope=scope,
        error=error,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    state: str | Unset = UNSET,
    code: str | Unset = UNSET,
    scope: str | Unset = UNSET,
    error: str | Unset = UNSET,
) -> Response[
    GetApiV1DatabaseOauth2Response400 | GetApiV1DatabaseOauth2Response404 | GetApiV1DatabaseOauth2Response500 | str
]:
    """Receive personal access tokens from OAuth2

     -> Receive and store personal access tokens from OAuth for user-level authorization

    Args:
        state (str | Unset):
        code (str | Unset):
        scope (str | Unset):
        error (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1DatabaseOauth2Response400 | GetApiV1DatabaseOauth2Response404 | GetApiV1DatabaseOauth2Response500 | str]
    """

    kwargs = _get_kwargs(
        state=state,
        code=code,
        scope=scope,
        error=error,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    state: str | Unset = UNSET,
    code: str | Unset = UNSET,
    scope: str | Unset = UNSET,
    error: str | Unset = UNSET,
) -> (
    GetApiV1DatabaseOauth2Response400
    | GetApiV1DatabaseOauth2Response404
    | GetApiV1DatabaseOauth2Response500
    | str
    | None
):
    """Receive personal access tokens from OAuth2

     -> Receive and store personal access tokens from OAuth for user-level authorization

    Args:
        state (str | Unset):
        code (str | Unset):
        scope (str | Unset):
        error (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1DatabaseOauth2Response400 | GetApiV1DatabaseOauth2Response404 | GetApiV1DatabaseOauth2Response500 | str
    """

    return (
        await asyncio_detailed(
            client=client,
            state=state,
            code=code,
            scope=scope,
            error=error,
        )
    ).parsed
