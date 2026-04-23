from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.post_api_v1_security_users_response_201 import PostApiV1SecurityUsersResponse201
from ...models.post_api_v1_security_users_response_400 import PostApiV1SecurityUsersResponse400
from ...models.post_api_v1_security_users_response_401 import PostApiV1SecurityUsersResponse401
from ...models.post_api_v1_security_users_response_404 import PostApiV1SecurityUsersResponse404
from ...models.post_api_v1_security_users_response_422 import PostApiV1SecurityUsersResponse422
from ...models.post_api_v1_security_users_response_500 import PostApiV1SecurityUsersResponse500
from ...models.superset_user_api_post import SupersetUserApiPost
from ...types import Response


def _get_kwargs(
    *,
    body: SupersetUserApiPost,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/security/users/",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    PostApiV1SecurityUsersResponse201
    | PostApiV1SecurityUsersResponse400
    | PostApiV1SecurityUsersResponse401
    | PostApiV1SecurityUsersResponse404
    | PostApiV1SecurityUsersResponse422
    | PostApiV1SecurityUsersResponse500
    | None
):
    if response.status_code == 201:
        response_201 = PostApiV1SecurityUsersResponse201.from_dict(response.json())

        return response_201

    if response.status_code == 400:
        response_400 = PostApiV1SecurityUsersResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PostApiV1SecurityUsersResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = PostApiV1SecurityUsersResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 422:
        response_422 = PostApiV1SecurityUsersResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = PostApiV1SecurityUsersResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PostApiV1SecurityUsersResponse201
    | PostApiV1SecurityUsersResponse400
    | PostApiV1SecurityUsersResponse401
    | PostApiV1SecurityUsersResponse404
    | PostApiV1SecurityUsersResponse422
    | PostApiV1SecurityUsersResponse500
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
    body: SupersetUserApiPost,
) -> Response[
    PostApiV1SecurityUsersResponse201
    | PostApiV1SecurityUsersResponse400
    | PostApiV1SecurityUsersResponse401
    | PostApiV1SecurityUsersResponse404
    | PostApiV1SecurityUsersResponse422
    | PostApiV1SecurityUsersResponse500
]:
    """
    Args:
        body (SupersetUserApiPost):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1SecurityUsersResponse201 | PostApiV1SecurityUsersResponse400 | PostApiV1SecurityUsersResponse401 | PostApiV1SecurityUsersResponse404 | PostApiV1SecurityUsersResponse422 | PostApiV1SecurityUsersResponse500]
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
    body: SupersetUserApiPost,
) -> (
    PostApiV1SecurityUsersResponse201
    | PostApiV1SecurityUsersResponse400
    | PostApiV1SecurityUsersResponse401
    | PostApiV1SecurityUsersResponse404
    | PostApiV1SecurityUsersResponse422
    | PostApiV1SecurityUsersResponse500
    | None
):
    """
    Args:
        body (SupersetUserApiPost):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1SecurityUsersResponse201 | PostApiV1SecurityUsersResponse400 | PostApiV1SecurityUsersResponse401 | PostApiV1SecurityUsersResponse404 | PostApiV1SecurityUsersResponse422 | PostApiV1SecurityUsersResponse500
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: SupersetUserApiPost,
) -> Response[
    PostApiV1SecurityUsersResponse201
    | PostApiV1SecurityUsersResponse400
    | PostApiV1SecurityUsersResponse401
    | PostApiV1SecurityUsersResponse404
    | PostApiV1SecurityUsersResponse422
    | PostApiV1SecurityUsersResponse500
]:
    """
    Args:
        body (SupersetUserApiPost):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1SecurityUsersResponse201 | PostApiV1SecurityUsersResponse400 | PostApiV1SecurityUsersResponse401 | PostApiV1SecurityUsersResponse404 | PostApiV1SecurityUsersResponse422 | PostApiV1SecurityUsersResponse500]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: SupersetUserApiPost,
) -> (
    PostApiV1SecurityUsersResponse201
    | PostApiV1SecurityUsersResponse400
    | PostApiV1SecurityUsersResponse401
    | PostApiV1SecurityUsersResponse404
    | PostApiV1SecurityUsersResponse422
    | PostApiV1SecurityUsersResponse500
    | None
):
    """
    Args:
        body (SupersetUserApiPost):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1SecurityUsersResponse201 | PostApiV1SecurityUsersResponse400 | PostApiV1SecurityUsersResponse401 | PostApiV1SecurityUsersResponse404 | PostApiV1SecurityUsersResponse422 | PostApiV1SecurityUsersResponse500
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
