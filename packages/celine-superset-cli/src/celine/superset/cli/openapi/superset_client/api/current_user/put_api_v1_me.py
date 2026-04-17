from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.current_user_put_schema import CurrentUserPutSchema
from ...models.put_api_v1_me_response_200 import PutApiV1MeResponse200
from ...models.put_api_v1_me_response_400 import PutApiV1MeResponse400
from ...models.put_api_v1_me_response_401 import PutApiV1MeResponse401
from ...types import Response


def _get_kwargs(
    *,
    body: CurrentUserPutSchema,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "put",
        "url": "/api/v1/me/",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> PutApiV1MeResponse200 | PutApiV1MeResponse400 | PutApiV1MeResponse401 | None:
    if response.status_code == 200:
        response_200 = PutApiV1MeResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = PutApiV1MeResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PutApiV1MeResponse401.from_dict(response.json())

        return response_401

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[PutApiV1MeResponse200 | PutApiV1MeResponse400 | PutApiV1MeResponse401]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient | Client,
    body: CurrentUserPutSchema,
) -> Response[PutApiV1MeResponse200 | PutApiV1MeResponse400 | PutApiV1MeResponse401]:
    """Update the current user

     Updates the current user's first name, last name, or password.

    Args:
        body (CurrentUserPutSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PutApiV1MeResponse200 | PutApiV1MeResponse400 | PutApiV1MeResponse401]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient | Client,
    body: CurrentUserPutSchema,
) -> PutApiV1MeResponse200 | PutApiV1MeResponse400 | PutApiV1MeResponse401 | None:
    """Update the current user

     Updates the current user's first name, last name, or password.

    Args:
        body (CurrentUserPutSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PutApiV1MeResponse200 | PutApiV1MeResponse400 | PutApiV1MeResponse401
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient | Client,
    body: CurrentUserPutSchema,
) -> Response[PutApiV1MeResponse200 | PutApiV1MeResponse400 | PutApiV1MeResponse401]:
    """Update the current user

     Updates the current user's first name, last name, or password.

    Args:
        body (CurrentUserPutSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PutApiV1MeResponse200 | PutApiV1MeResponse400 | PutApiV1MeResponse401]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient | Client,
    body: CurrentUserPutSchema,
) -> PutApiV1MeResponse200 | PutApiV1MeResponse400 | PutApiV1MeResponse401 | None:
    """Update the current user

     Updates the current user's first name, last name, or password.

    Args:
        body (CurrentUserPutSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PutApiV1MeResponse200 | PutApiV1MeResponse400 | PutApiV1MeResponse401
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
