from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.dataset_cache_warm_up_request_schema import DatasetCacheWarmUpRequestSchema
from ...models.dataset_cache_warm_up_response_schema import DatasetCacheWarmUpResponseSchema
from ...models.put_api_v1_dataset_warm_up_cache_response_400 import PutApiV1DatasetWarmUpCacheResponse400
from ...models.put_api_v1_dataset_warm_up_cache_response_404 import PutApiV1DatasetWarmUpCacheResponse404
from ...models.put_api_v1_dataset_warm_up_cache_response_500 import PutApiV1DatasetWarmUpCacheResponse500
from ...types import Response


def _get_kwargs(
    *,
    body: DatasetCacheWarmUpRequestSchema,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "put",
        "url": "/api/v1/dataset/warm_up_cache",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    DatasetCacheWarmUpResponseSchema
    | PutApiV1DatasetWarmUpCacheResponse400
    | PutApiV1DatasetWarmUpCacheResponse404
    | PutApiV1DatasetWarmUpCacheResponse500
    | None
):
    if response.status_code == 200:
        response_200 = DatasetCacheWarmUpResponseSchema.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = PutApiV1DatasetWarmUpCacheResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 404:
        response_404 = PutApiV1DatasetWarmUpCacheResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 500:
        response_500 = PutApiV1DatasetWarmUpCacheResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    DatasetCacheWarmUpResponseSchema
    | PutApiV1DatasetWarmUpCacheResponse400
    | PutApiV1DatasetWarmUpCacheResponse404
    | PutApiV1DatasetWarmUpCacheResponse500
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
    body: DatasetCacheWarmUpRequestSchema,
) -> Response[
    DatasetCacheWarmUpResponseSchema
    | PutApiV1DatasetWarmUpCacheResponse400
    | PutApiV1DatasetWarmUpCacheResponse404
    | PutApiV1DatasetWarmUpCacheResponse500
]:
    """Warm up the cache for each chart powered by the given table

     Warms up the cache for the table. Note for slices a force refresh occurs. In terms of the
    `extra_filters` these can be obtained from records in the JSON encoded `logs.json` column associated
    with the `explore_json` action.

    Args:
        body (DatasetCacheWarmUpRequestSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DatasetCacheWarmUpResponseSchema | PutApiV1DatasetWarmUpCacheResponse400 | PutApiV1DatasetWarmUpCacheResponse404 | PutApiV1DatasetWarmUpCacheResponse500]
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
    client: AuthenticatedClient,
    body: DatasetCacheWarmUpRequestSchema,
) -> (
    DatasetCacheWarmUpResponseSchema
    | PutApiV1DatasetWarmUpCacheResponse400
    | PutApiV1DatasetWarmUpCacheResponse404
    | PutApiV1DatasetWarmUpCacheResponse500
    | None
):
    """Warm up the cache for each chart powered by the given table

     Warms up the cache for the table. Note for slices a force refresh occurs. In terms of the
    `extra_filters` these can be obtained from records in the JSON encoded `logs.json` column associated
    with the `explore_json` action.

    Args:
        body (DatasetCacheWarmUpRequestSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DatasetCacheWarmUpResponseSchema | PutApiV1DatasetWarmUpCacheResponse400 | PutApiV1DatasetWarmUpCacheResponse404 | PutApiV1DatasetWarmUpCacheResponse500
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: DatasetCacheWarmUpRequestSchema,
) -> Response[
    DatasetCacheWarmUpResponseSchema
    | PutApiV1DatasetWarmUpCacheResponse400
    | PutApiV1DatasetWarmUpCacheResponse404
    | PutApiV1DatasetWarmUpCacheResponse500
]:
    """Warm up the cache for each chart powered by the given table

     Warms up the cache for the table. Note for slices a force refresh occurs. In terms of the
    `extra_filters` these can be obtained from records in the JSON encoded `logs.json` column associated
    with the `explore_json` action.

    Args:
        body (DatasetCacheWarmUpRequestSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DatasetCacheWarmUpResponseSchema | PutApiV1DatasetWarmUpCacheResponse400 | PutApiV1DatasetWarmUpCacheResponse404 | PutApiV1DatasetWarmUpCacheResponse500]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: DatasetCacheWarmUpRequestSchema,
) -> (
    DatasetCacheWarmUpResponseSchema
    | PutApiV1DatasetWarmUpCacheResponse400
    | PutApiV1DatasetWarmUpCacheResponse404
    | PutApiV1DatasetWarmUpCacheResponse500
    | None
):
    """Warm up the cache for each chart powered by the given table

     Warms up the cache for the table. Note for slices a force refresh occurs. In terms of the
    `extra_filters` these can be obtained from records in the JSON encoded `logs.json` column associated
    with the `explore_json` action.

    Args:
        body (DatasetCacheWarmUpRequestSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DatasetCacheWarmUpResponseSchema | PutApiV1DatasetWarmUpCacheResponse400 | PutApiV1DatasetWarmUpCacheResponse404 | PutApiV1DatasetWarmUpCacheResponse500
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
