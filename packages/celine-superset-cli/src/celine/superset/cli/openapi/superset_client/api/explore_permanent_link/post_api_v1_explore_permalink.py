from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.explore_permalink_state_schema import ExplorePermalinkStateSchema
from ...models.post_api_v1_explore_permalink_response_201 import PostApiV1ExplorePermalinkResponse201
from ...models.post_api_v1_explore_permalink_response_400 import PostApiV1ExplorePermalinkResponse400
from ...models.post_api_v1_explore_permalink_response_401 import PostApiV1ExplorePermalinkResponse401
from ...models.post_api_v1_explore_permalink_response_422 import PostApiV1ExplorePermalinkResponse422
from ...models.post_api_v1_explore_permalink_response_500 import PostApiV1ExplorePermalinkResponse500
from ...types import Response


def _get_kwargs(
    *,
    body: ExplorePermalinkStateSchema,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/explore/permalink",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    PostApiV1ExplorePermalinkResponse201
    | PostApiV1ExplorePermalinkResponse400
    | PostApiV1ExplorePermalinkResponse401
    | PostApiV1ExplorePermalinkResponse422
    | PostApiV1ExplorePermalinkResponse500
    | None
):
    if response.status_code == 201:
        response_201 = PostApiV1ExplorePermalinkResponse201.from_dict(response.json())

        return response_201

    if response.status_code == 400:
        response_400 = PostApiV1ExplorePermalinkResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PostApiV1ExplorePermalinkResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 422:
        response_422 = PostApiV1ExplorePermalinkResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = PostApiV1ExplorePermalinkResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PostApiV1ExplorePermalinkResponse201
    | PostApiV1ExplorePermalinkResponse400
    | PostApiV1ExplorePermalinkResponse401
    | PostApiV1ExplorePermalinkResponse422
    | PostApiV1ExplorePermalinkResponse500
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
    body: ExplorePermalinkStateSchema,
) -> Response[
    PostApiV1ExplorePermalinkResponse201
    | PostApiV1ExplorePermalinkResponse400
    | PostApiV1ExplorePermalinkResponse401
    | PostApiV1ExplorePermalinkResponse422
    | PostApiV1ExplorePermalinkResponse500
]:
    """Create a new permanent link

    Args:
        body (ExplorePermalinkStateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1ExplorePermalinkResponse201 | PostApiV1ExplorePermalinkResponse400 | PostApiV1ExplorePermalinkResponse401 | PostApiV1ExplorePermalinkResponse422 | PostApiV1ExplorePermalinkResponse500]
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
    body: ExplorePermalinkStateSchema,
) -> (
    PostApiV1ExplorePermalinkResponse201
    | PostApiV1ExplorePermalinkResponse400
    | PostApiV1ExplorePermalinkResponse401
    | PostApiV1ExplorePermalinkResponse422
    | PostApiV1ExplorePermalinkResponse500
    | None
):
    """Create a new permanent link

    Args:
        body (ExplorePermalinkStateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1ExplorePermalinkResponse201 | PostApiV1ExplorePermalinkResponse400 | PostApiV1ExplorePermalinkResponse401 | PostApiV1ExplorePermalinkResponse422 | PostApiV1ExplorePermalinkResponse500
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: ExplorePermalinkStateSchema,
) -> Response[
    PostApiV1ExplorePermalinkResponse201
    | PostApiV1ExplorePermalinkResponse400
    | PostApiV1ExplorePermalinkResponse401
    | PostApiV1ExplorePermalinkResponse422
    | PostApiV1ExplorePermalinkResponse500
]:
    """Create a new permanent link

    Args:
        body (ExplorePermalinkStateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1ExplorePermalinkResponse201 | PostApiV1ExplorePermalinkResponse400 | PostApiV1ExplorePermalinkResponse401 | PostApiV1ExplorePermalinkResponse422 | PostApiV1ExplorePermalinkResponse500]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: ExplorePermalinkStateSchema,
) -> (
    PostApiV1ExplorePermalinkResponse201
    | PostApiV1ExplorePermalinkResponse400
    | PostApiV1ExplorePermalinkResponse401
    | PostApiV1ExplorePermalinkResponse422
    | PostApiV1ExplorePermalinkResponse500
    | None
):
    """Create a new permanent link

    Args:
        body (ExplorePermalinkStateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1ExplorePermalinkResponse201 | PostApiV1ExplorePermalinkResponse400 | PostApiV1ExplorePermalinkResponse401 | PostApiV1ExplorePermalinkResponse422 | PostApiV1ExplorePermalinkResponse500
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
