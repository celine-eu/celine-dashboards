from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.post_api_v1_database_pk_upload_response_201 import PostApiV1DatabasePkUploadResponse201
from ...models.post_api_v1_database_pk_upload_response_400 import PostApiV1DatabasePkUploadResponse400
from ...models.post_api_v1_database_pk_upload_response_401 import PostApiV1DatabasePkUploadResponse401
from ...models.post_api_v1_database_pk_upload_response_404 import PostApiV1DatabasePkUploadResponse404
from ...models.post_api_v1_database_pk_upload_response_422 import PostApiV1DatabasePkUploadResponse422
from ...models.post_api_v1_database_pk_upload_response_500 import PostApiV1DatabasePkUploadResponse500
from ...models.upload_post_schema import UploadPostSchema
from ...types import Response


def _get_kwargs(
    pk: int,
    *,
    body: UploadPostSchema,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/database/{pk}/upload/".format(
            pk=quote(str(pk), safe=""),
        ),
    }

    _kwargs["files"] = body.to_multipart()

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    PostApiV1DatabasePkUploadResponse201
    | PostApiV1DatabasePkUploadResponse400
    | PostApiV1DatabasePkUploadResponse401
    | PostApiV1DatabasePkUploadResponse404
    | PostApiV1DatabasePkUploadResponse422
    | PostApiV1DatabasePkUploadResponse500
    | None
):
    if response.status_code == 201:
        response_201 = PostApiV1DatabasePkUploadResponse201.from_dict(response.json())

        return response_201

    if response.status_code == 400:
        response_400 = PostApiV1DatabasePkUploadResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PostApiV1DatabasePkUploadResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = PostApiV1DatabasePkUploadResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 422:
        response_422 = PostApiV1DatabasePkUploadResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = PostApiV1DatabasePkUploadResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PostApiV1DatabasePkUploadResponse201
    | PostApiV1DatabasePkUploadResponse400
    | PostApiV1DatabasePkUploadResponse401
    | PostApiV1DatabasePkUploadResponse404
    | PostApiV1DatabasePkUploadResponse422
    | PostApiV1DatabasePkUploadResponse500
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
    body: UploadPostSchema,
) -> Response[
    PostApiV1DatabasePkUploadResponse201
    | PostApiV1DatabasePkUploadResponse400
    | PostApiV1DatabasePkUploadResponse401
    | PostApiV1DatabasePkUploadResponse404
    | PostApiV1DatabasePkUploadResponse422
    | PostApiV1DatabasePkUploadResponse500
]:
    """Upload a file to a database table

    Args:
        pk (int):
        body (UploadPostSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1DatabasePkUploadResponse201 | PostApiV1DatabasePkUploadResponse400 | PostApiV1DatabasePkUploadResponse401 | PostApiV1DatabasePkUploadResponse404 | PostApiV1DatabasePkUploadResponse422 | PostApiV1DatabasePkUploadResponse500]
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
    body: UploadPostSchema,
) -> (
    PostApiV1DatabasePkUploadResponse201
    | PostApiV1DatabasePkUploadResponse400
    | PostApiV1DatabasePkUploadResponse401
    | PostApiV1DatabasePkUploadResponse404
    | PostApiV1DatabasePkUploadResponse422
    | PostApiV1DatabasePkUploadResponse500
    | None
):
    """Upload a file to a database table

    Args:
        pk (int):
        body (UploadPostSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1DatabasePkUploadResponse201 | PostApiV1DatabasePkUploadResponse400 | PostApiV1DatabasePkUploadResponse401 | PostApiV1DatabasePkUploadResponse404 | PostApiV1DatabasePkUploadResponse422 | PostApiV1DatabasePkUploadResponse500
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
    body: UploadPostSchema,
) -> Response[
    PostApiV1DatabasePkUploadResponse201
    | PostApiV1DatabasePkUploadResponse400
    | PostApiV1DatabasePkUploadResponse401
    | PostApiV1DatabasePkUploadResponse404
    | PostApiV1DatabasePkUploadResponse422
    | PostApiV1DatabasePkUploadResponse500
]:
    """Upload a file to a database table

    Args:
        pk (int):
        body (UploadPostSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1DatabasePkUploadResponse201 | PostApiV1DatabasePkUploadResponse400 | PostApiV1DatabasePkUploadResponse401 | PostApiV1DatabasePkUploadResponse404 | PostApiV1DatabasePkUploadResponse422 | PostApiV1DatabasePkUploadResponse500]
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
    body: UploadPostSchema,
) -> (
    PostApiV1DatabasePkUploadResponse201
    | PostApiV1DatabasePkUploadResponse400
    | PostApiV1DatabasePkUploadResponse401
    | PostApiV1DatabasePkUploadResponse404
    | PostApiV1DatabasePkUploadResponse422
    | PostApiV1DatabasePkUploadResponse500
    | None
):
    """Upload a file to a database table

    Args:
        pk (int):
        body (UploadPostSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1DatabasePkUploadResponse201 | PostApiV1DatabasePkUploadResponse400 | PostApiV1DatabasePkUploadResponse401 | PostApiV1DatabasePkUploadResponse404 | PostApiV1DatabasePkUploadResponse422 | PostApiV1DatabasePkUploadResponse500
    """

    return (
        await asyncio_detailed(
            pk=pk,
            client=client,
            body=body,
        )
    ).parsed
