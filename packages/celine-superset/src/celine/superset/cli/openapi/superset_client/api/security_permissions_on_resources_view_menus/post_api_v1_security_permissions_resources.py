from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.permission_view_menu_api_post import PermissionViewMenuApiPost
from ...models.post_api_v1_security_permissions_resources_response_201 import (
    PostApiV1SecurityPermissionsResourcesResponse201,
)
from ...models.post_api_v1_security_permissions_resources_response_400 import (
    PostApiV1SecurityPermissionsResourcesResponse400,
)
from ...models.post_api_v1_security_permissions_resources_response_401 import (
    PostApiV1SecurityPermissionsResourcesResponse401,
)
from ...models.post_api_v1_security_permissions_resources_response_422 import (
    PostApiV1SecurityPermissionsResourcesResponse422,
)
from ...models.post_api_v1_security_permissions_resources_response_500 import (
    PostApiV1SecurityPermissionsResourcesResponse500,
)
from ...types import Response


def _get_kwargs(
    *,
    body: PermissionViewMenuApiPost,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/security/permissions-resources/",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    PostApiV1SecurityPermissionsResourcesResponse201
    | PostApiV1SecurityPermissionsResourcesResponse400
    | PostApiV1SecurityPermissionsResourcesResponse401
    | PostApiV1SecurityPermissionsResourcesResponse422
    | PostApiV1SecurityPermissionsResourcesResponse500
    | None
):
    if response.status_code == 201:
        response_201 = PostApiV1SecurityPermissionsResourcesResponse201.from_dict(response.json())

        return response_201

    if response.status_code == 400:
        response_400 = PostApiV1SecurityPermissionsResourcesResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PostApiV1SecurityPermissionsResourcesResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 422:
        response_422 = PostApiV1SecurityPermissionsResourcesResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = PostApiV1SecurityPermissionsResourcesResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PostApiV1SecurityPermissionsResourcesResponse201
    | PostApiV1SecurityPermissionsResourcesResponse400
    | PostApiV1SecurityPermissionsResourcesResponse401
    | PostApiV1SecurityPermissionsResourcesResponse422
    | PostApiV1SecurityPermissionsResourcesResponse500
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
    body: PermissionViewMenuApiPost,
) -> Response[
    PostApiV1SecurityPermissionsResourcesResponse201
    | PostApiV1SecurityPermissionsResourcesResponse400
    | PostApiV1SecurityPermissionsResourcesResponse401
    | PostApiV1SecurityPermissionsResourcesResponse422
    | PostApiV1SecurityPermissionsResourcesResponse500
]:
    """
    Args:
        body (PermissionViewMenuApiPost):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1SecurityPermissionsResourcesResponse201 | PostApiV1SecurityPermissionsResourcesResponse400 | PostApiV1SecurityPermissionsResourcesResponse401 | PostApiV1SecurityPermissionsResourcesResponse422 | PostApiV1SecurityPermissionsResourcesResponse500]
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
    body: PermissionViewMenuApiPost,
) -> (
    PostApiV1SecurityPermissionsResourcesResponse201
    | PostApiV1SecurityPermissionsResourcesResponse400
    | PostApiV1SecurityPermissionsResourcesResponse401
    | PostApiV1SecurityPermissionsResourcesResponse422
    | PostApiV1SecurityPermissionsResourcesResponse500
    | None
):
    """
    Args:
        body (PermissionViewMenuApiPost):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1SecurityPermissionsResourcesResponse201 | PostApiV1SecurityPermissionsResourcesResponse400 | PostApiV1SecurityPermissionsResourcesResponse401 | PostApiV1SecurityPermissionsResourcesResponse422 | PostApiV1SecurityPermissionsResourcesResponse500
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: PermissionViewMenuApiPost,
) -> Response[
    PostApiV1SecurityPermissionsResourcesResponse201
    | PostApiV1SecurityPermissionsResourcesResponse400
    | PostApiV1SecurityPermissionsResourcesResponse401
    | PostApiV1SecurityPermissionsResourcesResponse422
    | PostApiV1SecurityPermissionsResourcesResponse500
]:
    """
    Args:
        body (PermissionViewMenuApiPost):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1SecurityPermissionsResourcesResponse201 | PostApiV1SecurityPermissionsResourcesResponse400 | PostApiV1SecurityPermissionsResourcesResponse401 | PostApiV1SecurityPermissionsResourcesResponse422 | PostApiV1SecurityPermissionsResourcesResponse500]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: PermissionViewMenuApiPost,
) -> (
    PostApiV1SecurityPermissionsResourcesResponse201
    | PostApiV1SecurityPermissionsResourcesResponse400
    | PostApiV1SecurityPermissionsResourcesResponse401
    | PostApiV1SecurityPermissionsResourcesResponse422
    | PostApiV1SecurityPermissionsResourcesResponse500
    | None
):
    """
    Args:
        body (PermissionViewMenuApiPost):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1SecurityPermissionsResourcesResponse201 | PostApiV1SecurityPermissionsResourcesResponse400 | PostApiV1SecurityPermissionsResourcesResponse401 | PostApiV1SecurityPermissionsResourcesResponse422 | PostApiV1SecurityPermissionsResourcesResponse500
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
