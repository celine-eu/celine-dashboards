from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_or_create_dataset_schema import GetOrCreateDatasetSchema
from ...models.post_api_v1_dataset_get_or_create_response_200 import PostApiV1DatasetGetOrCreateResponse200
from ...models.post_api_v1_dataset_get_or_create_response_400 import PostApiV1DatasetGetOrCreateResponse400
from ...models.post_api_v1_dataset_get_or_create_response_401 import PostApiV1DatasetGetOrCreateResponse401
from ...models.post_api_v1_dataset_get_or_create_response_422 import PostApiV1DatasetGetOrCreateResponse422
from ...models.post_api_v1_dataset_get_or_create_response_500 import PostApiV1DatasetGetOrCreateResponse500
from ...types import Response


def _get_kwargs(
    *,
    body: GetOrCreateDatasetSchema,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/dataset/get_or_create/",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    PostApiV1DatasetGetOrCreateResponse200
    | PostApiV1DatasetGetOrCreateResponse400
    | PostApiV1DatasetGetOrCreateResponse401
    | PostApiV1DatasetGetOrCreateResponse422
    | PostApiV1DatasetGetOrCreateResponse500
    | None
):
    if response.status_code == 200:
        response_200 = PostApiV1DatasetGetOrCreateResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = PostApiV1DatasetGetOrCreateResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PostApiV1DatasetGetOrCreateResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 422:
        response_422 = PostApiV1DatasetGetOrCreateResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = PostApiV1DatasetGetOrCreateResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PostApiV1DatasetGetOrCreateResponse200
    | PostApiV1DatasetGetOrCreateResponse400
    | PostApiV1DatasetGetOrCreateResponse401
    | PostApiV1DatasetGetOrCreateResponse422
    | PostApiV1DatasetGetOrCreateResponse500
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
    body: GetOrCreateDatasetSchema,
) -> Response[
    PostApiV1DatasetGetOrCreateResponse200
    | PostApiV1DatasetGetOrCreateResponse400
    | PostApiV1DatasetGetOrCreateResponse401
    | PostApiV1DatasetGetOrCreateResponse422
    | PostApiV1DatasetGetOrCreateResponse500
]:
    """Retrieve a table by name, or create it if it does not exist

    Args:
        body (GetOrCreateDatasetSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1DatasetGetOrCreateResponse200 | PostApiV1DatasetGetOrCreateResponse400 | PostApiV1DatasetGetOrCreateResponse401 | PostApiV1DatasetGetOrCreateResponse422 | PostApiV1DatasetGetOrCreateResponse500]
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
    body: GetOrCreateDatasetSchema,
) -> (
    PostApiV1DatasetGetOrCreateResponse200
    | PostApiV1DatasetGetOrCreateResponse400
    | PostApiV1DatasetGetOrCreateResponse401
    | PostApiV1DatasetGetOrCreateResponse422
    | PostApiV1DatasetGetOrCreateResponse500
    | None
):
    """Retrieve a table by name, or create it if it does not exist

    Args:
        body (GetOrCreateDatasetSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1DatasetGetOrCreateResponse200 | PostApiV1DatasetGetOrCreateResponse400 | PostApiV1DatasetGetOrCreateResponse401 | PostApiV1DatasetGetOrCreateResponse422 | PostApiV1DatasetGetOrCreateResponse500
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: GetOrCreateDatasetSchema,
) -> Response[
    PostApiV1DatasetGetOrCreateResponse200
    | PostApiV1DatasetGetOrCreateResponse400
    | PostApiV1DatasetGetOrCreateResponse401
    | PostApiV1DatasetGetOrCreateResponse422
    | PostApiV1DatasetGetOrCreateResponse500
]:
    """Retrieve a table by name, or create it if it does not exist

    Args:
        body (GetOrCreateDatasetSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1DatasetGetOrCreateResponse200 | PostApiV1DatasetGetOrCreateResponse400 | PostApiV1DatasetGetOrCreateResponse401 | PostApiV1DatasetGetOrCreateResponse422 | PostApiV1DatasetGetOrCreateResponse500]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: GetOrCreateDatasetSchema,
) -> (
    PostApiV1DatasetGetOrCreateResponse200
    | PostApiV1DatasetGetOrCreateResponse400
    | PostApiV1DatasetGetOrCreateResponse401
    | PostApiV1DatasetGetOrCreateResponse422
    | PostApiV1DatasetGetOrCreateResponse500
    | None
):
    """Retrieve a table by name, or create it if it does not exist

    Args:
        body (GetOrCreateDatasetSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1DatasetGetOrCreateResponse200 | PostApiV1DatasetGetOrCreateResponse400 | PostApiV1DatasetGetOrCreateResponse401 | PostApiV1DatasetGetOrCreateResponse422 | PostApiV1DatasetGetOrCreateResponse500
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
