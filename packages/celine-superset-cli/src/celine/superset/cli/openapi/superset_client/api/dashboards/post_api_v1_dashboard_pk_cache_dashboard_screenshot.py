from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.dashboard_cache_screenshot_response_schema import DashboardCacheScreenshotResponseSchema
from ...models.dashboard_screenshot_post_schema import DashboardScreenshotPostSchema
from ...models.post_api_v1_dashboard_pk_cache_dashboard_screenshot_response_400 import (
    PostApiV1DashboardPkCacheDashboardScreenshotResponse400,
)
from ...models.post_api_v1_dashboard_pk_cache_dashboard_screenshot_response_401 import (
    PostApiV1DashboardPkCacheDashboardScreenshotResponse401,
)
from ...models.post_api_v1_dashboard_pk_cache_dashboard_screenshot_response_404 import (
    PostApiV1DashboardPkCacheDashboardScreenshotResponse404,
)
from ...models.post_api_v1_dashboard_pk_cache_dashboard_screenshot_response_500 import (
    PostApiV1DashboardPkCacheDashboardScreenshotResponse500,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    pk: int,
    *,
    body: DashboardScreenshotPostSchema | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/dashboard/{pk}/cache_dashboard_screenshot/".format(
            pk=quote(str(pk), safe=""),
        ),
    }

    if not isinstance(body, Unset):
        _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    DashboardCacheScreenshotResponseSchema
    | PostApiV1DashboardPkCacheDashboardScreenshotResponse400
    | PostApiV1DashboardPkCacheDashboardScreenshotResponse401
    | PostApiV1DashboardPkCacheDashboardScreenshotResponse404
    | PostApiV1DashboardPkCacheDashboardScreenshotResponse500
    | None
):
    if response.status_code == 202:
        response_202 = DashboardCacheScreenshotResponseSchema.from_dict(response.json())

        return response_202

    if response.status_code == 400:
        response_400 = PostApiV1DashboardPkCacheDashboardScreenshotResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PostApiV1DashboardPkCacheDashboardScreenshotResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = PostApiV1DashboardPkCacheDashboardScreenshotResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 500:
        response_500 = PostApiV1DashboardPkCacheDashboardScreenshotResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    DashboardCacheScreenshotResponseSchema
    | PostApiV1DashboardPkCacheDashboardScreenshotResponse400
    | PostApiV1DashboardPkCacheDashboardScreenshotResponse401
    | PostApiV1DashboardPkCacheDashboardScreenshotResponse404
    | PostApiV1DashboardPkCacheDashboardScreenshotResponse500
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    pk: int,
    *,
    client: AuthenticatedClient,
    body: DashboardScreenshotPostSchema | Unset = UNSET,
) -> Response[
    DashboardCacheScreenshotResponseSchema
    | PostApiV1DashboardPkCacheDashboardScreenshotResponse400
    | PostApiV1DashboardPkCacheDashboardScreenshotResponse401
    | PostApiV1DashboardPkCacheDashboardScreenshotResponse404
    | PostApiV1DashboardPkCacheDashboardScreenshotResponse500
]:
    """Compute and cache a screenshot

    Args:
        pk (int):
        body (DashboardScreenshotPostSchema | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DashboardCacheScreenshotResponseSchema | PostApiV1DashboardPkCacheDashboardScreenshotResponse400 | PostApiV1DashboardPkCacheDashboardScreenshotResponse401 | PostApiV1DashboardPkCacheDashboardScreenshotResponse404 | PostApiV1DashboardPkCacheDashboardScreenshotResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    pk: int,
    *,
    client: AuthenticatedClient,
    body: DashboardScreenshotPostSchema | Unset = UNSET,
) -> (
    DashboardCacheScreenshotResponseSchema
    | PostApiV1DashboardPkCacheDashboardScreenshotResponse400
    | PostApiV1DashboardPkCacheDashboardScreenshotResponse401
    | PostApiV1DashboardPkCacheDashboardScreenshotResponse404
    | PostApiV1DashboardPkCacheDashboardScreenshotResponse500
    | None
):
    """Compute and cache a screenshot

    Args:
        pk (int):
        body (DashboardScreenshotPostSchema | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DashboardCacheScreenshotResponseSchema | PostApiV1DashboardPkCacheDashboardScreenshotResponse400 | PostApiV1DashboardPkCacheDashboardScreenshotResponse401 | PostApiV1DashboardPkCacheDashboardScreenshotResponse404 | PostApiV1DashboardPkCacheDashboardScreenshotResponse500
    """

    return sync_detailed(
        pk=pk,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    pk: int,
    *,
    client: AuthenticatedClient,
    body: DashboardScreenshotPostSchema | Unset = UNSET,
) -> Response[
    DashboardCacheScreenshotResponseSchema
    | PostApiV1DashboardPkCacheDashboardScreenshotResponse400
    | PostApiV1DashboardPkCacheDashboardScreenshotResponse401
    | PostApiV1DashboardPkCacheDashboardScreenshotResponse404
    | PostApiV1DashboardPkCacheDashboardScreenshotResponse500
]:
    """Compute and cache a screenshot

    Args:
        pk (int):
        body (DashboardScreenshotPostSchema | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DashboardCacheScreenshotResponseSchema | PostApiV1DashboardPkCacheDashboardScreenshotResponse400 | PostApiV1DashboardPkCacheDashboardScreenshotResponse401 | PostApiV1DashboardPkCacheDashboardScreenshotResponse404 | PostApiV1DashboardPkCacheDashboardScreenshotResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    pk: int,
    *,
    client: AuthenticatedClient,
    body: DashboardScreenshotPostSchema | Unset = UNSET,
) -> (
    DashboardCacheScreenshotResponseSchema
    | PostApiV1DashboardPkCacheDashboardScreenshotResponse400
    | PostApiV1DashboardPkCacheDashboardScreenshotResponse401
    | PostApiV1DashboardPkCacheDashboardScreenshotResponse404
    | PostApiV1DashboardPkCacheDashboardScreenshotResponse500
    | None
):
    """Compute and cache a screenshot

    Args:
        pk (int):
        body (DashboardScreenshotPostSchema | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DashboardCacheScreenshotResponseSchema | PostApiV1DashboardPkCacheDashboardScreenshotResponse400 | PostApiV1DashboardPkCacheDashboardScreenshotResponse401 | PostApiV1DashboardPkCacheDashboardScreenshotResponse404 | PostApiV1DashboardPkCacheDashboardScreenshotResponse500
    """

    return (
        await asyncio_detailed(
            pk=pk,
            client=client,
            body=body,
        )
    ).parsed
