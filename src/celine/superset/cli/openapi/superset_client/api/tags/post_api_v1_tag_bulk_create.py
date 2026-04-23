from http import HTTPStatus
from typing import Any, cast

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.post_api_v1_tag_bulk_create_response_400 import PostApiV1TagBulkCreateResponse400
from ...models.post_api_v1_tag_bulk_create_response_401 import PostApiV1TagBulkCreateResponse401
from ...models.post_api_v1_tag_bulk_create_response_404 import PostApiV1TagBulkCreateResponse404
from ...models.post_api_v1_tag_bulk_create_response_500 import PostApiV1TagBulkCreateResponse500
from ...models.tag_post_bulk_response_schema import TagPostBulkResponseSchema
from ...models.tag_post_bulk_schema import TagPostBulkSchema
from ...types import Response


def _get_kwargs(
    *,
    body: TagPostBulkSchema,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/tag/bulk_create",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    Any
    | PostApiV1TagBulkCreateResponse400
    | PostApiV1TagBulkCreateResponse401
    | PostApiV1TagBulkCreateResponse404
    | PostApiV1TagBulkCreateResponse500
    | TagPostBulkResponseSchema
    | None
):
    if response.status_code == 200:
        response_200 = TagPostBulkResponseSchema.from_dict(response.json())

        return response_200

    if response.status_code == 302:
        response_302 = cast(Any, None)
        return response_302

    if response.status_code == 400:
        response_400 = PostApiV1TagBulkCreateResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PostApiV1TagBulkCreateResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = PostApiV1TagBulkCreateResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 500:
        response_500 = PostApiV1TagBulkCreateResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    Any
    | PostApiV1TagBulkCreateResponse400
    | PostApiV1TagBulkCreateResponse401
    | PostApiV1TagBulkCreateResponse404
    | PostApiV1TagBulkCreateResponse500
    | TagPostBulkResponseSchema
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
    body: TagPostBulkSchema,
) -> Response[
    Any
    | PostApiV1TagBulkCreateResponse400
    | PostApiV1TagBulkCreateResponse401
    | PostApiV1TagBulkCreateResponse404
    | PostApiV1TagBulkCreateResponse500
    | TagPostBulkResponseSchema
]:
    """Bulk create tags and tagged objects

    Args:
        body (TagPostBulkSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | PostApiV1TagBulkCreateResponse400 | PostApiV1TagBulkCreateResponse401 | PostApiV1TagBulkCreateResponse404 | PostApiV1TagBulkCreateResponse500 | TagPostBulkResponseSchema]
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
    body: TagPostBulkSchema,
) -> (
    Any
    | PostApiV1TagBulkCreateResponse400
    | PostApiV1TagBulkCreateResponse401
    | PostApiV1TagBulkCreateResponse404
    | PostApiV1TagBulkCreateResponse500
    | TagPostBulkResponseSchema
    | None
):
    """Bulk create tags and tagged objects

    Args:
        body (TagPostBulkSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | PostApiV1TagBulkCreateResponse400 | PostApiV1TagBulkCreateResponse401 | PostApiV1TagBulkCreateResponse404 | PostApiV1TagBulkCreateResponse500 | TagPostBulkResponseSchema
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: TagPostBulkSchema,
) -> Response[
    Any
    | PostApiV1TagBulkCreateResponse400
    | PostApiV1TagBulkCreateResponse401
    | PostApiV1TagBulkCreateResponse404
    | PostApiV1TagBulkCreateResponse500
    | TagPostBulkResponseSchema
]:
    """Bulk create tags and tagged objects

    Args:
        body (TagPostBulkSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | PostApiV1TagBulkCreateResponse400 | PostApiV1TagBulkCreateResponse401 | PostApiV1TagBulkCreateResponse404 | PostApiV1TagBulkCreateResponse500 | TagPostBulkResponseSchema]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: TagPostBulkSchema,
) -> (
    Any
    | PostApiV1TagBulkCreateResponse400
    | PostApiV1TagBulkCreateResponse401
    | PostApiV1TagBulkCreateResponse404
    | PostApiV1TagBulkCreateResponse500
    | TagPostBulkResponseSchema
    | None
):
    """Bulk create tags and tagged objects

    Args:
        body (TagPostBulkSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | PostApiV1TagBulkCreateResponse400 | PostApiV1TagBulkCreateResponse401 | PostApiV1TagBulkCreateResponse404 | PostApiV1TagBulkCreateResponse500 | TagPostBulkResponseSchema
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
