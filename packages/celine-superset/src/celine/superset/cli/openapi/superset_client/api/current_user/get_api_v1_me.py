from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_me_response_200 import GetApiV1MeResponse200
from ...models.get_api_v1_me_response_401 import GetApiV1MeResponse401
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/me/",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GetApiV1MeResponse200 | GetApiV1MeResponse401 | None:
    if response.status_code == 200:
        response_200 = GetApiV1MeResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 401:
        response_401 = GetApiV1MeResponse401.from_dict(response.json())

        return response_401

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[GetApiV1MeResponse200 | GetApiV1MeResponse401]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient | Client,
) -> Response[GetApiV1MeResponse200 | GetApiV1MeResponse401]:
    """Get the user object

     Gets the user object corresponding to the agent making the request, or returns a 401 error if the
    user is unauthenticated.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1MeResponse200 | GetApiV1MeResponse401]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient | Client,
) -> GetApiV1MeResponse200 | GetApiV1MeResponse401 | None:
    """Get the user object

     Gets the user object corresponding to the agent making the request, or returns a 401 error if the
    user is unauthenticated.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1MeResponse200 | GetApiV1MeResponse401
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient | Client,
) -> Response[GetApiV1MeResponse200 | GetApiV1MeResponse401]:
    """Get the user object

     Gets the user object corresponding to the agent making the request, or returns a 401 error if the
    user is unauthenticated.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1MeResponse200 | GetApiV1MeResponse401]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient | Client,
) -> GetApiV1MeResponse200 | GetApiV1MeResponse401 | None:
    """Get the user object

     Gets the user object corresponding to the agent making the request, or returns a 401 error if the
    user is unauthenticated.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1MeResponse200 | GetApiV1MeResponse401
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
