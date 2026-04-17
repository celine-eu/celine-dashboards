from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_database_available_response_200_item import GetApiV1DatabaseAvailableResponse200Item
from ...models.get_api_v1_database_available_response_400 import GetApiV1DatabaseAvailableResponse400
from ...models.get_api_v1_database_available_response_500 import GetApiV1DatabaseAvailableResponse500
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/database/available/",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetApiV1DatabaseAvailableResponse400
    | GetApiV1DatabaseAvailableResponse500
    | list[GetApiV1DatabaseAvailableResponse200Item]
    | None
):
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = GetApiV1DatabaseAvailableResponse200Item.from_dict(response_200_item_data)

            response_200.append(response_200_item)

        return response_200

    if response.status_code == 400:
        response_400 = GetApiV1DatabaseAvailableResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 500:
        response_500 = GetApiV1DatabaseAvailableResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    GetApiV1DatabaseAvailableResponse400
    | GetApiV1DatabaseAvailableResponse500
    | list[GetApiV1DatabaseAvailableResponse200Item]
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
    GetApiV1DatabaseAvailableResponse400
    | GetApiV1DatabaseAvailableResponse500
    | list[GetApiV1DatabaseAvailableResponse200Item]
]:
    """Get names of databases currently available

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1DatabaseAvailableResponse400 | GetApiV1DatabaseAvailableResponse500 | list[GetApiV1DatabaseAvailableResponse200Item]]
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
    GetApiV1DatabaseAvailableResponse400
    | GetApiV1DatabaseAvailableResponse500
    | list[GetApiV1DatabaseAvailableResponse200Item]
    | None
):
    """Get names of databases currently available

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1DatabaseAvailableResponse400 | GetApiV1DatabaseAvailableResponse500 | list[GetApiV1DatabaseAvailableResponse200Item]
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[
    GetApiV1DatabaseAvailableResponse400
    | GetApiV1DatabaseAvailableResponse500
    | list[GetApiV1DatabaseAvailableResponse200Item]
]:
    """Get names of databases currently available

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1DatabaseAvailableResponse400 | GetApiV1DatabaseAvailableResponse500 | list[GetApiV1DatabaseAvailableResponse200Item]]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> (
    GetApiV1DatabaseAvailableResponse400
    | GetApiV1DatabaseAvailableResponse500
    | list[GetApiV1DatabaseAvailableResponse200Item]
    | None
):
    """Get names of databases currently available

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1DatabaseAvailableResponse400 | GetApiV1DatabaseAvailableResponse500 | list[GetApiV1DatabaseAvailableResponse200Item]
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
