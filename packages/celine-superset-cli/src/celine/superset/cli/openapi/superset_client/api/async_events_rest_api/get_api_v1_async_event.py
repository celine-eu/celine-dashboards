from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_async_event_response_200 import GetApiV1AsyncEventResponse200
from ...models.get_api_v1_async_event_response_401 import GetApiV1AsyncEventResponse401
from ...models.get_api_v1_async_event_response_500 import GetApiV1AsyncEventResponse500
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    last_id: str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["last_id"] = last_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/async_event/",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GetApiV1AsyncEventResponse200 | GetApiV1AsyncEventResponse401 | GetApiV1AsyncEventResponse500 | None:
    if response.status_code == 200:
        response_200 = GetApiV1AsyncEventResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 401:
        response_401 = GetApiV1AsyncEventResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 500:
        response_500 = GetApiV1AsyncEventResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[GetApiV1AsyncEventResponse200 | GetApiV1AsyncEventResponse401 | GetApiV1AsyncEventResponse500]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    last_id: str | Unset = UNSET,
) -> Response[GetApiV1AsyncEventResponse200 | GetApiV1AsyncEventResponse401 | GetApiV1AsyncEventResponse500]:
    """Read off of the Redis events stream

     Reads off of the Redis events stream, using the user's JWT token and optional query params for last
    event received.

    Args:
        last_id (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1AsyncEventResponse200 | GetApiV1AsyncEventResponse401 | GetApiV1AsyncEventResponse500]
    """

    kwargs = _get_kwargs(
        last_id=last_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    last_id: str | Unset = UNSET,
) -> GetApiV1AsyncEventResponse200 | GetApiV1AsyncEventResponse401 | GetApiV1AsyncEventResponse500 | None:
    """Read off of the Redis events stream

     Reads off of the Redis events stream, using the user's JWT token and optional query params for last
    event received.

    Args:
        last_id (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1AsyncEventResponse200 | GetApiV1AsyncEventResponse401 | GetApiV1AsyncEventResponse500
    """

    return sync_detailed(
        client=client,
        last_id=last_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    last_id: str | Unset = UNSET,
) -> Response[GetApiV1AsyncEventResponse200 | GetApiV1AsyncEventResponse401 | GetApiV1AsyncEventResponse500]:
    """Read off of the Redis events stream

     Reads off of the Redis events stream, using the user's JWT token and optional query params for last
    event received.

    Args:
        last_id (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1AsyncEventResponse200 | GetApiV1AsyncEventResponse401 | GetApiV1AsyncEventResponse500]
    """

    kwargs = _get_kwargs(
        last_id=last_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    last_id: str | Unset = UNSET,
) -> GetApiV1AsyncEventResponse200 | GetApiV1AsyncEventResponse401 | GetApiV1AsyncEventResponse500 | None:
    """Read off of the Redis events stream

     Reads off of the Redis events stream, using the user's JWT token and optional query params for last
    event received.

    Args:
        last_id (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1AsyncEventResponse200 | GetApiV1AsyncEventResponse401 | GetApiV1AsyncEventResponse500
    """

    return (
        await asyncio_detailed(
            client=client,
            last_id=last_id,
        )
    ).parsed
