from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_security_csrf_token_response_200 import GetApiV1SecurityCsrfTokenResponse200
from ...models.get_api_v1_security_csrf_token_response_401 import GetApiV1SecurityCsrfTokenResponse401
from ...models.get_api_v1_security_csrf_token_response_500 import GetApiV1SecurityCsrfTokenResponse500
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/security/csrf_token/",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetApiV1SecurityCsrfTokenResponse200
    | GetApiV1SecurityCsrfTokenResponse401
    | GetApiV1SecurityCsrfTokenResponse500
    | None
):
    if response.status_code == 200:
        response_200 = GetApiV1SecurityCsrfTokenResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 401:
        response_401 = GetApiV1SecurityCsrfTokenResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 500:
        response_500 = GetApiV1SecurityCsrfTokenResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    GetApiV1SecurityCsrfTokenResponse200 | GetApiV1SecurityCsrfTokenResponse401 | GetApiV1SecurityCsrfTokenResponse500
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
) -> Response[
    GetApiV1SecurityCsrfTokenResponse200 | GetApiV1SecurityCsrfTokenResponse401 | GetApiV1SecurityCsrfTokenResponse500
]:
    """Get the CSRF token

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1SecurityCsrfTokenResponse200 | GetApiV1SecurityCsrfTokenResponse401 | GetApiV1SecurityCsrfTokenResponse500]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> (
    GetApiV1SecurityCsrfTokenResponse200
    | GetApiV1SecurityCsrfTokenResponse401
    | GetApiV1SecurityCsrfTokenResponse500
    | None
):
    """Get the CSRF token

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1SecurityCsrfTokenResponse200 | GetApiV1SecurityCsrfTokenResponse401 | GetApiV1SecurityCsrfTokenResponse500
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[
    GetApiV1SecurityCsrfTokenResponse200 | GetApiV1SecurityCsrfTokenResponse401 | GetApiV1SecurityCsrfTokenResponse500
]:
    """Get the CSRF token

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1SecurityCsrfTokenResponse200 | GetApiV1SecurityCsrfTokenResponse401 | GetApiV1SecurityCsrfTokenResponse500]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> (
    GetApiV1SecurityCsrfTokenResponse200
    | GetApiV1SecurityCsrfTokenResponse401
    | GetApiV1SecurityCsrfTokenResponse500
    | None
):
    """Get the CSRF token

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1SecurityCsrfTokenResponse200 | GetApiV1SecurityCsrfTokenResponse401 | GetApiV1SecurityCsrfTokenResponse500
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
