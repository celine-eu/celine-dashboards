from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_query_response_200 import GetApiV1QueryResponse200
from ...models.get_api_v1_query_response_400 import GetApiV1QueryResponse400
from ...models.get_api_v1_query_response_401 import GetApiV1QueryResponse401
from ...models.get_api_v1_query_response_422 import GetApiV1QueryResponse422
from ...models.get_api_v1_query_response_500 import GetApiV1QueryResponse500
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/query/",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetApiV1QueryResponse200
    | GetApiV1QueryResponse400
    | GetApiV1QueryResponse401
    | GetApiV1QueryResponse422
    | GetApiV1QueryResponse500
    | None
):
    if response.status_code == 200:
        response_200 = GetApiV1QueryResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = GetApiV1QueryResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = GetApiV1QueryResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 422:
        response_422 = GetApiV1QueryResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = GetApiV1QueryResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    GetApiV1QueryResponse200
    | GetApiV1QueryResponse400
    | GetApiV1QueryResponse401
    | GetApiV1QueryResponse422
    | GetApiV1QueryResponse500
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
    GetApiV1QueryResponse200
    | GetApiV1QueryResponse400
    | GetApiV1QueryResponse401
    | GetApiV1QueryResponse422
    | GetApiV1QueryResponse500
]:
    """Get a list of queries

     Gets a list of queries, use Rison or JSON query parameters for filtering, sorting, pagination and
    for selecting specific columns and metadata.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1QueryResponse200 | GetApiV1QueryResponse400 | GetApiV1QueryResponse401 | GetApiV1QueryResponse422 | GetApiV1QueryResponse500]
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
    GetApiV1QueryResponse200
    | GetApiV1QueryResponse400
    | GetApiV1QueryResponse401
    | GetApiV1QueryResponse422
    | GetApiV1QueryResponse500
    | None
):
    """Get a list of queries

     Gets a list of queries, use Rison or JSON query parameters for filtering, sorting, pagination and
    for selecting specific columns and metadata.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1QueryResponse200 | GetApiV1QueryResponse400 | GetApiV1QueryResponse401 | GetApiV1QueryResponse422 | GetApiV1QueryResponse500
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[
    GetApiV1QueryResponse200
    | GetApiV1QueryResponse400
    | GetApiV1QueryResponse401
    | GetApiV1QueryResponse422
    | GetApiV1QueryResponse500
]:
    """Get a list of queries

     Gets a list of queries, use Rison or JSON query parameters for filtering, sorting, pagination and
    for selecting specific columns and metadata.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1QueryResponse200 | GetApiV1QueryResponse400 | GetApiV1QueryResponse401 | GetApiV1QueryResponse422 | GetApiV1QueryResponse500]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> (
    GetApiV1QueryResponse200
    | GetApiV1QueryResponse400
    | GetApiV1QueryResponse401
    | GetApiV1QueryResponse422
    | GetApiV1QueryResponse500
    | None
):
    """Get a list of queries

     Gets a list of queries, use Rison or JSON query parameters for filtering, sorting, pagination and
    for selecting specific columns and metadata.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1QueryResponse200 | GetApiV1QueryResponse400 | GetApiV1QueryResponse401 | GetApiV1QueryResponse422 | GetApiV1QueryResponse500
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
