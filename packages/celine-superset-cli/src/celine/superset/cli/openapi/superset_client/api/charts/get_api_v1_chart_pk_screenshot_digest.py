from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_chart_pk_screenshot_digest_response_400 import GetApiV1ChartPkScreenshotDigestResponse400
from ...models.get_api_v1_chart_pk_screenshot_digest_response_401 import GetApiV1ChartPkScreenshotDigestResponse401
from ...models.get_api_v1_chart_pk_screenshot_digest_response_404 import GetApiV1ChartPkScreenshotDigestResponse404
from ...models.get_api_v1_chart_pk_screenshot_digest_response_500 import GetApiV1ChartPkScreenshotDigestResponse500
from ...types import Response


def _get_kwargs(
    pk: int,
    digest: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/chart/{pk}/screenshot/{digest}/".format(
            pk=quote(str(pk), safe=""),
            digest=quote(str(digest), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetApiV1ChartPkScreenshotDigestResponse400
    | GetApiV1ChartPkScreenshotDigestResponse401
    | GetApiV1ChartPkScreenshotDigestResponse404
    | GetApiV1ChartPkScreenshotDigestResponse500
    | None
):
    if response.status_code == 400:
        response_400 = GetApiV1ChartPkScreenshotDigestResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = GetApiV1ChartPkScreenshotDigestResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = GetApiV1ChartPkScreenshotDigestResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 500:
        response_500 = GetApiV1ChartPkScreenshotDigestResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    GetApiV1ChartPkScreenshotDigestResponse400
    | GetApiV1ChartPkScreenshotDigestResponse401
    | GetApiV1ChartPkScreenshotDigestResponse404
    | GetApiV1ChartPkScreenshotDigestResponse500
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
    GetApiV1ChartPkScreenshotDigestResponse400
    | GetApiV1ChartPkScreenshotDigestResponse401
    | GetApiV1ChartPkScreenshotDigestResponse404
    | GetApiV1ChartPkScreenshotDigestResponse500
]:
    """Get a computed screenshot from cache

    Args:
        pk (int):
        digest (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1ChartPkScreenshotDigestResponse400 | GetApiV1ChartPkScreenshotDigestResponse401 | GetApiV1ChartPkScreenshotDigestResponse404 | GetApiV1ChartPkScreenshotDigestResponse500]
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
    GetApiV1ChartPkScreenshotDigestResponse400
    | GetApiV1ChartPkScreenshotDigestResponse401
    | GetApiV1ChartPkScreenshotDigestResponse404
    | GetApiV1ChartPkScreenshotDigestResponse500
    | None
):
    """Get a computed screenshot from cache

    Args:
        pk (int):
        digest (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1ChartPkScreenshotDigestResponse400 | GetApiV1ChartPkScreenshotDigestResponse401 | GetApiV1ChartPkScreenshotDigestResponse404 | GetApiV1ChartPkScreenshotDigestResponse500
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
    GetApiV1ChartPkScreenshotDigestResponse400
    | GetApiV1ChartPkScreenshotDigestResponse401
    | GetApiV1ChartPkScreenshotDigestResponse404
    | GetApiV1ChartPkScreenshotDigestResponse500
]:
    """Get a computed screenshot from cache

    Args:
        pk (int):
        digest (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1ChartPkScreenshotDigestResponse400 | GetApiV1ChartPkScreenshotDigestResponse401 | GetApiV1ChartPkScreenshotDigestResponse404 | GetApiV1ChartPkScreenshotDigestResponse500]
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
    GetApiV1ChartPkScreenshotDigestResponse400
    | GetApiV1ChartPkScreenshotDigestResponse401
    | GetApiV1ChartPkScreenshotDigestResponse404
    | GetApiV1ChartPkScreenshotDigestResponse500
    | None
):
    """Get a computed screenshot from cache

    Args:
        pk (int):
        digest (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1ChartPkScreenshotDigestResponse400 | GetApiV1ChartPkScreenshotDigestResponse401 | GetApiV1ChartPkScreenshotDigestResponse404 | GetApiV1ChartPkScreenshotDigestResponse500
    """

    return (
        await asyncio_detailed(
            pk=pk,
            digest=digest,
            client=client,
        )
    ).parsed
