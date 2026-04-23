from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_chart_pk_thumbnail_digest_response_400 import GetApiV1ChartPkThumbnailDigestResponse400
from ...models.get_api_v1_chart_pk_thumbnail_digest_response_401 import GetApiV1ChartPkThumbnailDigestResponse401
from ...models.get_api_v1_chart_pk_thumbnail_digest_response_404 import GetApiV1ChartPkThumbnailDigestResponse404
from ...models.get_api_v1_chart_pk_thumbnail_digest_response_500 import GetApiV1ChartPkThumbnailDigestResponse500
from ...types import Response


def _get_kwargs(
    pk: int,
    digest: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/chart/{pk}/thumbnail/{digest}/".format(
            pk=quote(str(pk), safe=""),
            digest=quote(str(digest), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    Any
    | GetApiV1ChartPkThumbnailDigestResponse400
    | GetApiV1ChartPkThumbnailDigestResponse401
    | GetApiV1ChartPkThumbnailDigestResponse404
    | GetApiV1ChartPkThumbnailDigestResponse500
    | None
):
    if response.status_code == 302:
        response_302 = cast(Any, None)
        return response_302

    if response.status_code == 400:
        response_400 = GetApiV1ChartPkThumbnailDigestResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = GetApiV1ChartPkThumbnailDigestResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = GetApiV1ChartPkThumbnailDigestResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 500:
        response_500 = GetApiV1ChartPkThumbnailDigestResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    Any
    | GetApiV1ChartPkThumbnailDigestResponse400
    | GetApiV1ChartPkThumbnailDigestResponse401
    | GetApiV1ChartPkThumbnailDigestResponse404
    | GetApiV1ChartPkThumbnailDigestResponse500
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    pk: int,
    digest: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    Any
    | GetApiV1ChartPkThumbnailDigestResponse400
    | GetApiV1ChartPkThumbnailDigestResponse401
    | GetApiV1ChartPkThumbnailDigestResponse404
    | GetApiV1ChartPkThumbnailDigestResponse500
]:
    """Get chart thumbnail

     Compute or get already computed chart thumbnail from cache.

    Args:
        pk (int):
        digest (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | GetApiV1ChartPkThumbnailDigestResponse400 | GetApiV1ChartPkThumbnailDigestResponse401 | GetApiV1ChartPkThumbnailDigestResponse404 | GetApiV1ChartPkThumbnailDigestResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
        digest=digest,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    pk: int,
    digest: str,
    *,
    client: AuthenticatedClient,
) -> (
    Any
    | GetApiV1ChartPkThumbnailDigestResponse400
    | GetApiV1ChartPkThumbnailDigestResponse401
    | GetApiV1ChartPkThumbnailDigestResponse404
    | GetApiV1ChartPkThumbnailDigestResponse500
    | None
):
    """Get chart thumbnail

     Compute or get already computed chart thumbnail from cache.

    Args:
        pk (int):
        digest (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | GetApiV1ChartPkThumbnailDigestResponse400 | GetApiV1ChartPkThumbnailDigestResponse401 | GetApiV1ChartPkThumbnailDigestResponse404 | GetApiV1ChartPkThumbnailDigestResponse500
    """

    return sync_detailed(
        pk=pk,
        digest=digest,
        client=client,
    ).parsed


async def asyncio_detailed(
    pk: int,
    digest: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    Any
    | GetApiV1ChartPkThumbnailDigestResponse400
    | GetApiV1ChartPkThumbnailDigestResponse401
    | GetApiV1ChartPkThumbnailDigestResponse404
    | GetApiV1ChartPkThumbnailDigestResponse500
]:
    """Get chart thumbnail

     Compute or get already computed chart thumbnail from cache.

    Args:
        pk (int):
        digest (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | GetApiV1ChartPkThumbnailDigestResponse400 | GetApiV1ChartPkThumbnailDigestResponse401 | GetApiV1ChartPkThumbnailDigestResponse404 | GetApiV1ChartPkThumbnailDigestResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
        digest=digest,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    pk: int,
    digest: str,
    *,
    client: AuthenticatedClient,
) -> (
    Any
    | GetApiV1ChartPkThumbnailDigestResponse400
    | GetApiV1ChartPkThumbnailDigestResponse401
    | GetApiV1ChartPkThumbnailDigestResponse404
    | GetApiV1ChartPkThumbnailDigestResponse500
    | None
):
    """Get chart thumbnail

     Compute or get already computed chart thumbnail from cache.

    Args:
        pk (int):
        digest (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | GetApiV1ChartPkThumbnailDigestResponse400 | GetApiV1ChartPkThumbnailDigestResponse401 | GetApiV1ChartPkThumbnailDigestResponse404 | GetApiV1ChartPkThumbnailDigestResponse500
    """

    return (
        await asyncio_detailed(
            pk=pk,
            digest=digest,
            client=client,
        )
    ).parsed
