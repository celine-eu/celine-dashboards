from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.chart_data_response_schema import ChartDataResponseSchema
from ...models.get_api_v1_chart_data_cache_key_response_400 import GetApiV1ChartDataCacheKeyResponse400
from ...models.get_api_v1_chart_data_cache_key_response_401 import GetApiV1ChartDataCacheKeyResponse401
from ...models.get_api_v1_chart_data_cache_key_response_404 import GetApiV1ChartDataCacheKeyResponse404
from ...models.get_api_v1_chart_data_cache_key_response_422 import GetApiV1ChartDataCacheKeyResponse422
from ...models.get_api_v1_chart_data_cache_key_response_500 import GetApiV1ChartDataCacheKeyResponse500
from ...types import Response


def _get_kwargs(
    cache_key: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/chart/data/{cache_key}".format(
            cache_key=quote(str(cache_key), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    ChartDataResponseSchema
    | GetApiV1ChartDataCacheKeyResponse400
    | GetApiV1ChartDataCacheKeyResponse401
    | GetApiV1ChartDataCacheKeyResponse404
    | GetApiV1ChartDataCacheKeyResponse422
    | GetApiV1ChartDataCacheKeyResponse500
    | None
):
    if response.status_code == 200:
        response_200 = ChartDataResponseSchema.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = GetApiV1ChartDataCacheKeyResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = GetApiV1ChartDataCacheKeyResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = GetApiV1ChartDataCacheKeyResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 422:
        response_422 = GetApiV1ChartDataCacheKeyResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = GetApiV1ChartDataCacheKeyResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    ChartDataResponseSchema
    | GetApiV1ChartDataCacheKeyResponse400
    | GetApiV1ChartDataCacheKeyResponse401
    | GetApiV1ChartDataCacheKeyResponse404
    | GetApiV1ChartDataCacheKeyResponse422
    | GetApiV1ChartDataCacheKeyResponse500
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    cache_key: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    ChartDataResponseSchema
    | GetApiV1ChartDataCacheKeyResponse400
    | GetApiV1ChartDataCacheKeyResponse401
    | GetApiV1ChartDataCacheKeyResponse404
    | GetApiV1ChartDataCacheKeyResponse422
    | GetApiV1ChartDataCacheKeyResponse500
]:
    """Return payload data response for the given query

     Takes a query context cache key and returns payload data response for the given query.

    Args:
        cache_key (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ChartDataResponseSchema | GetApiV1ChartDataCacheKeyResponse400 | GetApiV1ChartDataCacheKeyResponse401 | GetApiV1ChartDataCacheKeyResponse404 | GetApiV1ChartDataCacheKeyResponse422 | GetApiV1ChartDataCacheKeyResponse500]
    """

    kwargs = _get_kwargs(
        cache_key=cache_key,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    cache_key: str,
    *,
    client: AuthenticatedClient,
) -> (
    ChartDataResponseSchema
    | GetApiV1ChartDataCacheKeyResponse400
    | GetApiV1ChartDataCacheKeyResponse401
    | GetApiV1ChartDataCacheKeyResponse404
    | GetApiV1ChartDataCacheKeyResponse422
    | GetApiV1ChartDataCacheKeyResponse500
    | None
):
    """Return payload data response for the given query

     Takes a query context cache key and returns payload data response for the given query.

    Args:
        cache_key (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ChartDataResponseSchema | GetApiV1ChartDataCacheKeyResponse400 | GetApiV1ChartDataCacheKeyResponse401 | GetApiV1ChartDataCacheKeyResponse404 | GetApiV1ChartDataCacheKeyResponse422 | GetApiV1ChartDataCacheKeyResponse500
    """

    return sync_detailed(
        cache_key=cache_key,
        client=client,
    ).parsed


async def asyncio_detailed(
    cache_key: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    ChartDataResponseSchema
    | GetApiV1ChartDataCacheKeyResponse400
    | GetApiV1ChartDataCacheKeyResponse401
    | GetApiV1ChartDataCacheKeyResponse404
    | GetApiV1ChartDataCacheKeyResponse422
    | GetApiV1ChartDataCacheKeyResponse500
]:
    """Return payload data response for the given query

     Takes a query context cache key and returns payload data response for the given query.

    Args:
        cache_key (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ChartDataResponseSchema | GetApiV1ChartDataCacheKeyResponse400 | GetApiV1ChartDataCacheKeyResponse401 | GetApiV1ChartDataCacheKeyResponse404 | GetApiV1ChartDataCacheKeyResponse422 | GetApiV1ChartDataCacheKeyResponse500]
    """

    kwargs = _get_kwargs(
        cache_key=cache_key,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    cache_key: str,
    *,
    client: AuthenticatedClient,
) -> (
    ChartDataResponseSchema
    | GetApiV1ChartDataCacheKeyResponse400
    | GetApiV1ChartDataCacheKeyResponse401
    | GetApiV1ChartDataCacheKeyResponse404
    | GetApiV1ChartDataCacheKeyResponse422
    | GetApiV1ChartDataCacheKeyResponse500
    | None
):
    """Return payload data response for the given query

     Takes a query context cache key and returns payload data response for the given query.

    Args:
        cache_key (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ChartDataResponseSchema | GetApiV1ChartDataCacheKeyResponse400 | GetApiV1ChartDataCacheKeyResponse401 | GetApiV1ChartDataCacheKeyResponse404 | GetApiV1ChartDataCacheKeyResponse422 | GetApiV1ChartDataCacheKeyResponse500
    """

    return (
        await asyncio_detailed(
            cache_key=cache_key,
            client=client,
        )
    ).parsed
