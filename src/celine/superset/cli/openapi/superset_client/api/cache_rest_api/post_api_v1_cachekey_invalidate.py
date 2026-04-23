from http import HTTPStatus
from typing import Any, cast

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.cache_invalidation_request_schema import CacheInvalidationRequestSchema
from ...models.post_api_v1_cachekey_invalidate_response_400 import PostApiV1CachekeyInvalidateResponse400
from ...models.post_api_v1_cachekey_invalidate_response_500 import PostApiV1CachekeyInvalidateResponse500
from ...types import Response


def _get_kwargs(
    *,
    body: CacheInvalidationRequestSchema,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/cachekey/invalidate",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | PostApiV1CachekeyInvalidateResponse400 | PostApiV1CachekeyInvalidateResponse500 | None:
    if response.status_code == 201:
        response_201 = cast(Any, None)
        return response_201

    if response.status_code == 400:
        response_400 = PostApiV1CachekeyInvalidateResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 500:
        response_500 = PostApiV1CachekeyInvalidateResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[Any | PostApiV1CachekeyInvalidateResponse400 | PostApiV1CachekeyInvalidateResponse500]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: CacheInvalidationRequestSchema,
) -> Response[Any | PostApiV1CachekeyInvalidateResponse400 | PostApiV1CachekeyInvalidateResponse500]:
    """Invalidate cache records and remove the database records

     Takes a list of datasources, finds and invalidates the associated cache records and removes the
    database records.

    Args:
        body (CacheInvalidationRequestSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | PostApiV1CachekeyInvalidateResponse400 | PostApiV1CachekeyInvalidateResponse500]
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
    body: CacheInvalidationRequestSchema,
) -> Any | PostApiV1CachekeyInvalidateResponse400 | PostApiV1CachekeyInvalidateResponse500 | None:
    """Invalidate cache records and remove the database records

     Takes a list of datasources, finds and invalidates the associated cache records and removes the
    database records.

    Args:
        body (CacheInvalidationRequestSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | PostApiV1CachekeyInvalidateResponse400 | PostApiV1CachekeyInvalidateResponse500
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: CacheInvalidationRequestSchema,
) -> Response[Any | PostApiV1CachekeyInvalidateResponse400 | PostApiV1CachekeyInvalidateResponse500]:
    """Invalidate cache records and remove the database records

     Takes a list of datasources, finds and invalidates the associated cache records and removes the
    database records.

    Args:
        body (CacheInvalidationRequestSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | PostApiV1CachekeyInvalidateResponse400 | PostApiV1CachekeyInvalidateResponse500]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: CacheInvalidationRequestSchema,
) -> Any | PostApiV1CachekeyInvalidateResponse400 | PostApiV1CachekeyInvalidateResponse500 | None:
    """Invalidate cache records and remove the database records

     Takes a list of datasources, finds and invalidates the associated cache records and removes the
    database records.

    Args:
        body (CacheInvalidationRequestSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | PostApiV1CachekeyInvalidateResponse400 | PostApiV1CachekeyInvalidateResponse500
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
