from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.post_api_v1_theme_response_201 import PostApiV1ThemeResponse201
from ...models.post_api_v1_theme_response_400 import PostApiV1ThemeResponse400
from ...models.post_api_v1_theme_response_401 import PostApiV1ThemeResponse401
from ...models.post_api_v1_theme_response_422 import PostApiV1ThemeResponse422
from ...models.post_api_v1_theme_response_500 import PostApiV1ThemeResponse500
from ...models.theme_rest_api_post import ThemeRestApiPost
from ...types import Response


def _get_kwargs(
    *,
    body: ThemeRestApiPost,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/theme/",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    PostApiV1ThemeResponse201
    | PostApiV1ThemeResponse400
    | PostApiV1ThemeResponse401
    | PostApiV1ThemeResponse422
    | PostApiV1ThemeResponse500
    | None
):
    if response.status_code == 201:
        response_201 = PostApiV1ThemeResponse201.from_dict(response.json())

        return response_201

    if response.status_code == 400:
        response_400 = PostApiV1ThemeResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PostApiV1ThemeResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 422:
        response_422 = PostApiV1ThemeResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = PostApiV1ThemeResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PostApiV1ThemeResponse201
    | PostApiV1ThemeResponse400
    | PostApiV1ThemeResponse401
    | PostApiV1ThemeResponse422
    | PostApiV1ThemeResponse500
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
    body: ThemeRestApiPost,
) -> Response[
    PostApiV1ThemeResponse201
    | PostApiV1ThemeResponse400
    | PostApiV1ThemeResponse401
    | PostApiV1ThemeResponse422
    | PostApiV1ThemeResponse500
]:
    """Create a theme

    Args:
        body (ThemeRestApiPost):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1ThemeResponse201 | PostApiV1ThemeResponse400 | PostApiV1ThemeResponse401 | PostApiV1ThemeResponse422 | PostApiV1ThemeResponse500]
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
    body: ThemeRestApiPost,
) -> (
    PostApiV1ThemeResponse201
    | PostApiV1ThemeResponse400
    | PostApiV1ThemeResponse401
    | PostApiV1ThemeResponse422
    | PostApiV1ThemeResponse500
    | None
):
    """Create a theme

    Args:
        body (ThemeRestApiPost):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1ThemeResponse201 | PostApiV1ThemeResponse400 | PostApiV1ThemeResponse401 | PostApiV1ThemeResponse422 | PostApiV1ThemeResponse500
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: ThemeRestApiPost,
) -> Response[
    PostApiV1ThemeResponse201
    | PostApiV1ThemeResponse400
    | PostApiV1ThemeResponse401
    | PostApiV1ThemeResponse422
    | PostApiV1ThemeResponse500
]:
    """Create a theme

    Args:
        body (ThemeRestApiPost):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1ThemeResponse201 | PostApiV1ThemeResponse400 | PostApiV1ThemeResponse401 | PostApiV1ThemeResponse422 | PostApiV1ThemeResponse500]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: ThemeRestApiPost,
) -> (
    PostApiV1ThemeResponse201
    | PostApiV1ThemeResponse400
    | PostApiV1ThemeResponse401
    | PostApiV1ThemeResponse422
    | PostApiV1ThemeResponse500
    | None
):
    """Create a theme

    Args:
        body (ThemeRestApiPost):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1ThemeResponse201 | PostApiV1ThemeResponse400 | PostApiV1ThemeResponse401 | PostApiV1ThemeResponse422 | PostApiV1ThemeResponse500
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
