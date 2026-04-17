from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.post_api_v1_assets_import_body import PostApiV1AssetsImportBody
from ...models.post_api_v1_assets_import_response_200 import PostApiV1AssetsImportResponse200
from ...models.post_api_v1_assets_import_response_400 import PostApiV1AssetsImportResponse400
from ...models.post_api_v1_assets_import_response_401 import PostApiV1AssetsImportResponse401
from ...models.post_api_v1_assets_import_response_422 import PostApiV1AssetsImportResponse422
from ...models.post_api_v1_assets_import_response_500 import PostApiV1AssetsImportResponse500
from ...types import Response


def _get_kwargs(
    *,
    body: PostApiV1AssetsImportBody,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/assets/import/",
    }

    _kwargs["files"] = body.to_multipart()

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    PostApiV1AssetsImportResponse200
    | PostApiV1AssetsImportResponse400
    | PostApiV1AssetsImportResponse401
    | PostApiV1AssetsImportResponse422
    | PostApiV1AssetsImportResponse500
    | None
):
    if response.status_code == 200:
        response_200 = PostApiV1AssetsImportResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = PostApiV1AssetsImportResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PostApiV1AssetsImportResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 422:
        response_422 = PostApiV1AssetsImportResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = PostApiV1AssetsImportResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PostApiV1AssetsImportResponse200
    | PostApiV1AssetsImportResponse400
    | PostApiV1AssetsImportResponse401
    | PostApiV1AssetsImportResponse422
    | PostApiV1AssetsImportResponse500
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
    body: PostApiV1AssetsImportBody,
) -> Response[
    PostApiV1AssetsImportResponse200
    | PostApiV1AssetsImportResponse400
    | PostApiV1AssetsImportResponse401
    | PostApiV1AssetsImportResponse422
    | PostApiV1AssetsImportResponse500
]:
    """Import multiple assets

    Args:
        body (PostApiV1AssetsImportBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1AssetsImportResponse200 | PostApiV1AssetsImportResponse400 | PostApiV1AssetsImportResponse401 | PostApiV1AssetsImportResponse422 | PostApiV1AssetsImportResponse500]
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
    body: PostApiV1AssetsImportBody,
) -> (
    PostApiV1AssetsImportResponse200
    | PostApiV1AssetsImportResponse400
    | PostApiV1AssetsImportResponse401
    | PostApiV1AssetsImportResponse422
    | PostApiV1AssetsImportResponse500
    | None
):
    """Import multiple assets

    Args:
        body (PostApiV1AssetsImportBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1AssetsImportResponse200 | PostApiV1AssetsImportResponse400 | PostApiV1AssetsImportResponse401 | PostApiV1AssetsImportResponse422 | PostApiV1AssetsImportResponse500
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: PostApiV1AssetsImportBody,
) -> Response[
    PostApiV1AssetsImportResponse200
    | PostApiV1AssetsImportResponse400
    | PostApiV1AssetsImportResponse401
    | PostApiV1AssetsImportResponse422
    | PostApiV1AssetsImportResponse500
]:
    """Import multiple assets

    Args:
        body (PostApiV1AssetsImportBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1AssetsImportResponse200 | PostApiV1AssetsImportResponse400 | PostApiV1AssetsImportResponse401 | PostApiV1AssetsImportResponse422 | PostApiV1AssetsImportResponse500]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: PostApiV1AssetsImportBody,
) -> (
    PostApiV1AssetsImportResponse200
    | PostApiV1AssetsImportResponse400
    | PostApiV1AssetsImportResponse401
    | PostApiV1AssetsImportResponse422
    | PostApiV1AssetsImportResponse500
    | None
):
    """Import multiple assets

    Args:
        body (PostApiV1AssetsImportBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1AssetsImportResponse200 | PostApiV1AssetsImportResponse400 | PostApiV1AssetsImportResponse401 | PostApiV1AssetsImportResponse422 | PostApiV1AssetsImportResponse500
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
