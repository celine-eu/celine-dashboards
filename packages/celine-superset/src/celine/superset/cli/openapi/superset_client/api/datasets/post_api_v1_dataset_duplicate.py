from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.dataset_duplicate_schema import DatasetDuplicateSchema
from ...models.post_api_v1_dataset_duplicate_response_201 import PostApiV1DatasetDuplicateResponse201
from ...models.post_api_v1_dataset_duplicate_response_400 import PostApiV1DatasetDuplicateResponse400
from ...models.post_api_v1_dataset_duplicate_response_401 import PostApiV1DatasetDuplicateResponse401
from ...models.post_api_v1_dataset_duplicate_response_403 import PostApiV1DatasetDuplicateResponse403
from ...models.post_api_v1_dataset_duplicate_response_404 import PostApiV1DatasetDuplicateResponse404
from ...models.post_api_v1_dataset_duplicate_response_422 import PostApiV1DatasetDuplicateResponse422
from ...models.post_api_v1_dataset_duplicate_response_500 import PostApiV1DatasetDuplicateResponse500
from ...types import Response


def _get_kwargs(
    *,
    body: DatasetDuplicateSchema,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/dataset/duplicate",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    PostApiV1DatasetDuplicateResponse201
    | PostApiV1DatasetDuplicateResponse400
    | PostApiV1DatasetDuplicateResponse401
    | PostApiV1DatasetDuplicateResponse403
    | PostApiV1DatasetDuplicateResponse404
    | PostApiV1DatasetDuplicateResponse422
    | PostApiV1DatasetDuplicateResponse500
    | None
):
    if response.status_code == 201:
        response_201 = PostApiV1DatasetDuplicateResponse201.from_dict(response.json())

        return response_201

    if response.status_code == 400:
        response_400 = PostApiV1DatasetDuplicateResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PostApiV1DatasetDuplicateResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 403:
        response_403 = PostApiV1DatasetDuplicateResponse403.from_dict(response.json())

        return response_403

    if response.status_code == 404:
        response_404 = PostApiV1DatasetDuplicateResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 422:
        response_422 = PostApiV1DatasetDuplicateResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = PostApiV1DatasetDuplicateResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PostApiV1DatasetDuplicateResponse201
    | PostApiV1DatasetDuplicateResponse400
    | PostApiV1DatasetDuplicateResponse401
    | PostApiV1DatasetDuplicateResponse403
    | PostApiV1DatasetDuplicateResponse404
    | PostApiV1DatasetDuplicateResponse422
    | PostApiV1DatasetDuplicateResponse500
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
    body: DatasetDuplicateSchema,
) -> Response[
    PostApiV1DatasetDuplicateResponse201
    | PostApiV1DatasetDuplicateResponse400
    | PostApiV1DatasetDuplicateResponse401
    | PostApiV1DatasetDuplicateResponse403
    | PostApiV1DatasetDuplicateResponse404
    | PostApiV1DatasetDuplicateResponse422
    | PostApiV1DatasetDuplicateResponse500
]:
    """Duplicate a dataset

    Args:
        body (DatasetDuplicateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1DatasetDuplicateResponse201 | PostApiV1DatasetDuplicateResponse400 | PostApiV1DatasetDuplicateResponse401 | PostApiV1DatasetDuplicateResponse403 | PostApiV1DatasetDuplicateResponse404 | PostApiV1DatasetDuplicateResponse422 | PostApiV1DatasetDuplicateResponse500]
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
    body: DatasetDuplicateSchema,
) -> (
    PostApiV1DatasetDuplicateResponse201
    | PostApiV1DatasetDuplicateResponse400
    | PostApiV1DatasetDuplicateResponse401
    | PostApiV1DatasetDuplicateResponse403
    | PostApiV1DatasetDuplicateResponse404
    | PostApiV1DatasetDuplicateResponse422
    | PostApiV1DatasetDuplicateResponse500
    | None
):
    """Duplicate a dataset

    Args:
        body (DatasetDuplicateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1DatasetDuplicateResponse201 | PostApiV1DatasetDuplicateResponse400 | PostApiV1DatasetDuplicateResponse401 | PostApiV1DatasetDuplicateResponse403 | PostApiV1DatasetDuplicateResponse404 | PostApiV1DatasetDuplicateResponse422 | PostApiV1DatasetDuplicateResponse500
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: DatasetDuplicateSchema,
) -> Response[
    PostApiV1DatasetDuplicateResponse201
    | PostApiV1DatasetDuplicateResponse400
    | PostApiV1DatasetDuplicateResponse401
    | PostApiV1DatasetDuplicateResponse403
    | PostApiV1DatasetDuplicateResponse404
    | PostApiV1DatasetDuplicateResponse422
    | PostApiV1DatasetDuplicateResponse500
]:
    """Duplicate a dataset

    Args:
        body (DatasetDuplicateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1DatasetDuplicateResponse201 | PostApiV1DatasetDuplicateResponse400 | PostApiV1DatasetDuplicateResponse401 | PostApiV1DatasetDuplicateResponse403 | PostApiV1DatasetDuplicateResponse404 | PostApiV1DatasetDuplicateResponse422 | PostApiV1DatasetDuplicateResponse500]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: DatasetDuplicateSchema,
) -> (
    PostApiV1DatasetDuplicateResponse201
    | PostApiV1DatasetDuplicateResponse400
    | PostApiV1DatasetDuplicateResponse401
    | PostApiV1DatasetDuplicateResponse403
    | PostApiV1DatasetDuplicateResponse404
    | PostApiV1DatasetDuplicateResponse422
    | PostApiV1DatasetDuplicateResponse500
    | None
):
    """Duplicate a dataset

    Args:
        body (DatasetDuplicateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1DatasetDuplicateResponse201 | PostApiV1DatasetDuplicateResponse400 | PostApiV1DatasetDuplicateResponse401 | PostApiV1DatasetDuplicateResponse403 | PostApiV1DatasetDuplicateResponse404 | PostApiV1DatasetDuplicateResponse422 | PostApiV1DatasetDuplicateResponse500
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
