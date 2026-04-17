from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.post_api_v1_tag_pk_favorites_response_200 import PostApiV1TagPkFavoritesResponse200
from ...models.post_api_v1_tag_pk_favorites_response_401 import PostApiV1TagPkFavoritesResponse401
from ...models.post_api_v1_tag_pk_favorites_response_404 import PostApiV1TagPkFavoritesResponse404
from ...models.post_api_v1_tag_pk_favorites_response_422 import PostApiV1TagPkFavoritesResponse422
from ...models.post_api_v1_tag_pk_favorites_response_500 import PostApiV1TagPkFavoritesResponse500
from ...types import Response


def _get_kwargs(
    pk: int,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/tag/{pk}/favorites/".format(
            pk=quote(str(pk), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    PostApiV1TagPkFavoritesResponse200
    | PostApiV1TagPkFavoritesResponse401
    | PostApiV1TagPkFavoritesResponse404
    | PostApiV1TagPkFavoritesResponse422
    | PostApiV1TagPkFavoritesResponse500
    | None
):
    if response.status_code == 200:
        response_200 = PostApiV1TagPkFavoritesResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 401:
        response_401 = PostApiV1TagPkFavoritesResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = PostApiV1TagPkFavoritesResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 422:
        response_422 = PostApiV1TagPkFavoritesResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = PostApiV1TagPkFavoritesResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PostApiV1TagPkFavoritesResponse200
    | PostApiV1TagPkFavoritesResponse401
    | PostApiV1TagPkFavoritesResponse404
    | PostApiV1TagPkFavoritesResponse422
    | PostApiV1TagPkFavoritesResponse500
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
) -> Response[
    PostApiV1TagPkFavoritesResponse200
    | PostApiV1TagPkFavoritesResponse401
    | PostApiV1TagPkFavoritesResponse404
    | PostApiV1TagPkFavoritesResponse422
    | PostApiV1TagPkFavoritesResponse500
]:
    """Marks the tag as favorite for the current user

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1TagPkFavoritesResponse200 | PostApiV1TagPkFavoritesResponse401 | PostApiV1TagPkFavoritesResponse404 | PostApiV1TagPkFavoritesResponse422 | PostApiV1TagPkFavoritesResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    pk: int,
    *,
    client: AuthenticatedClient,
) -> (
    PostApiV1TagPkFavoritesResponse200
    | PostApiV1TagPkFavoritesResponse401
    | PostApiV1TagPkFavoritesResponse404
    | PostApiV1TagPkFavoritesResponse422
    | PostApiV1TagPkFavoritesResponse500
    | None
):
    """Marks the tag as favorite for the current user

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1TagPkFavoritesResponse200 | PostApiV1TagPkFavoritesResponse401 | PostApiV1TagPkFavoritesResponse404 | PostApiV1TagPkFavoritesResponse422 | PostApiV1TagPkFavoritesResponse500
    """

    return sync_detailed(
        pk=pk,
        client=client,
    ).parsed


async def asyncio_detailed(
    pk: int,
    *,
    client: AuthenticatedClient,
) -> Response[
    PostApiV1TagPkFavoritesResponse200
    | PostApiV1TagPkFavoritesResponse401
    | PostApiV1TagPkFavoritesResponse404
    | PostApiV1TagPkFavoritesResponse422
    | PostApiV1TagPkFavoritesResponse500
]:
    """Marks the tag as favorite for the current user

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1TagPkFavoritesResponse200 | PostApiV1TagPkFavoritesResponse401 | PostApiV1TagPkFavoritesResponse404 | PostApiV1TagPkFavoritesResponse422 | PostApiV1TagPkFavoritesResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    pk: int,
    *,
    client: AuthenticatedClient,
) -> (
    PostApiV1TagPkFavoritesResponse200
    | PostApiV1TagPkFavoritesResponse401
    | PostApiV1TagPkFavoritesResponse404
    | PostApiV1TagPkFavoritesResponse422
    | PostApiV1TagPkFavoritesResponse500
    | None
):
    """Marks the tag as favorite for the current user

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1TagPkFavoritesResponse200 | PostApiV1TagPkFavoritesResponse401 | PostApiV1TagPkFavoritesResponse404 | PostApiV1TagPkFavoritesResponse422 | PostApiV1TagPkFavoritesResponse500
    """

    return (
        await asyncio_detailed(
            pk=pk,
            client=client,
        )
    ).parsed
