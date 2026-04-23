from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.post_api_v1_database_import_body import PostApiV1DatabaseImportBody
from ...models.post_api_v1_database_import_response_200 import PostApiV1DatabaseImportResponse200
from ...models.post_api_v1_database_import_response_400 import PostApiV1DatabaseImportResponse400
from ...models.post_api_v1_database_import_response_401 import PostApiV1DatabaseImportResponse401
from ...models.post_api_v1_database_import_response_422 import PostApiV1DatabaseImportResponse422
from ...models.post_api_v1_database_import_response_500 import PostApiV1DatabaseImportResponse500
from ...types import Response


def _get_kwargs(
    *,
    body: PostApiV1DatabaseImportBody,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/database/import/",
    }

    _kwargs["files"] = body.to_multipart()

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    PostApiV1DatabaseImportResponse200
    | PostApiV1DatabaseImportResponse400
    | PostApiV1DatabaseImportResponse401
    | PostApiV1DatabaseImportResponse422
    | PostApiV1DatabaseImportResponse500
    | None
):
    if response.status_code == 200:
        response_200 = PostApiV1DatabaseImportResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = PostApiV1DatabaseImportResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PostApiV1DatabaseImportResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 422:
        response_422 = PostApiV1DatabaseImportResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = PostApiV1DatabaseImportResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PostApiV1DatabaseImportResponse200
    | PostApiV1DatabaseImportResponse400
    | PostApiV1DatabaseImportResponse401
    | PostApiV1DatabaseImportResponse422
    | PostApiV1DatabaseImportResponse500
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
    body: PostApiV1DatabaseImportBody,
) -> Response[
    PostApiV1DatabaseImportResponse200
    | PostApiV1DatabaseImportResponse400
    | PostApiV1DatabaseImportResponse401
    | PostApiV1DatabaseImportResponse422
    | PostApiV1DatabaseImportResponse500
]:
    """Import database(s) with associated datasets

    Args:
        body (PostApiV1DatabaseImportBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1DatabaseImportResponse200 | PostApiV1DatabaseImportResponse400 | PostApiV1DatabaseImportResponse401 | PostApiV1DatabaseImportResponse422 | PostApiV1DatabaseImportResponse500]
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
    body: PostApiV1DatabaseImportBody,
) -> (
    PostApiV1DatabaseImportResponse200
    | PostApiV1DatabaseImportResponse400
    | PostApiV1DatabaseImportResponse401
    | PostApiV1DatabaseImportResponse422
    | PostApiV1DatabaseImportResponse500
    | None
):
    """Import database(s) with associated datasets

    Args:
        body (PostApiV1DatabaseImportBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1DatabaseImportResponse200 | PostApiV1DatabaseImportResponse400 | PostApiV1DatabaseImportResponse401 | PostApiV1DatabaseImportResponse422 | PostApiV1DatabaseImportResponse500
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: PostApiV1DatabaseImportBody,
) -> Response[
    PostApiV1DatabaseImportResponse200
    | PostApiV1DatabaseImportResponse400
    | PostApiV1DatabaseImportResponse401
    | PostApiV1DatabaseImportResponse422
    | PostApiV1DatabaseImportResponse500
]:
    """Import database(s) with associated datasets

    Args:
        body (PostApiV1DatabaseImportBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1DatabaseImportResponse200 | PostApiV1DatabaseImportResponse400 | PostApiV1DatabaseImportResponse401 | PostApiV1DatabaseImportResponse422 | PostApiV1DatabaseImportResponse500]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: PostApiV1DatabaseImportBody,
) -> (
    PostApiV1DatabaseImportResponse200
    | PostApiV1DatabaseImportResponse400
    | PostApiV1DatabaseImportResponse401
    | PostApiV1DatabaseImportResponse422
    | PostApiV1DatabaseImportResponse500
    | None
):
    """Import database(s) with associated datasets

    Args:
        body (PostApiV1DatabaseImportBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1DatabaseImportResponse200 | PostApiV1DatabaseImportResponse400 | PostApiV1DatabaseImportResponse401 | PostApiV1DatabaseImportResponse422 | PostApiV1DatabaseImportResponse500
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
