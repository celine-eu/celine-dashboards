from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.post_api_v1_security_roles_role_id_permissions_response_200 import (
    PostApiV1SecurityRolesRoleIdPermissionsResponse200,
)
from ...models.post_api_v1_security_roles_role_id_permissions_response_400 import (
    PostApiV1SecurityRolesRoleIdPermissionsResponse400,
)
from ...models.post_api_v1_security_roles_role_id_permissions_response_401 import (
    PostApiV1SecurityRolesRoleIdPermissionsResponse401,
)
from ...models.post_api_v1_security_roles_role_id_permissions_response_404 import (
    PostApiV1SecurityRolesRoleIdPermissionsResponse404,
)
from ...models.post_api_v1_security_roles_role_id_permissions_response_422 import (
    PostApiV1SecurityRolesRoleIdPermissionsResponse422,
)
from ...models.post_api_v1_security_roles_role_id_permissions_response_500 import (
    PostApiV1SecurityRolesRoleIdPermissionsResponse500,
)
from ...models.role_permission_post_schema import RolePermissionPostSchema
from ...types import Response


def _get_kwargs(
    role_id: int,
    *,
    body: RolePermissionPostSchema,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/security/roles/{role_id}/permissions".format(
            role_id=quote(str(role_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    PostApiV1SecurityRolesRoleIdPermissionsResponse200
    | PostApiV1SecurityRolesRoleIdPermissionsResponse400
    | PostApiV1SecurityRolesRoleIdPermissionsResponse401
    | PostApiV1SecurityRolesRoleIdPermissionsResponse404
    | PostApiV1SecurityRolesRoleIdPermissionsResponse422
    | PostApiV1SecurityRolesRoleIdPermissionsResponse500
    | None
):
    if response.status_code == 200:
        response_200 = PostApiV1SecurityRolesRoleIdPermissionsResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = PostApiV1SecurityRolesRoleIdPermissionsResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PostApiV1SecurityRolesRoleIdPermissionsResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = PostApiV1SecurityRolesRoleIdPermissionsResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 422:
        response_422 = PostApiV1SecurityRolesRoleIdPermissionsResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = PostApiV1SecurityRolesRoleIdPermissionsResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PostApiV1SecurityRolesRoleIdPermissionsResponse200
    | PostApiV1SecurityRolesRoleIdPermissionsResponse400
    | PostApiV1SecurityRolesRoleIdPermissionsResponse401
    | PostApiV1SecurityRolesRoleIdPermissionsResponse404
    | PostApiV1SecurityRolesRoleIdPermissionsResponse422
    | PostApiV1SecurityRolesRoleIdPermissionsResponse500
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    role_id: int,
    *,
    client: AuthenticatedClient,
    body: RolePermissionPostSchema,
) -> Response[
    PostApiV1SecurityRolesRoleIdPermissionsResponse200
    | PostApiV1SecurityRolesRoleIdPermissionsResponse400
    | PostApiV1SecurityRolesRoleIdPermissionsResponse401
    | PostApiV1SecurityRolesRoleIdPermissionsResponse404
    | PostApiV1SecurityRolesRoleIdPermissionsResponse422
    | PostApiV1SecurityRolesRoleIdPermissionsResponse500
]:
    """
    Args:
        role_id (int):
        body (RolePermissionPostSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1SecurityRolesRoleIdPermissionsResponse200 | PostApiV1SecurityRolesRoleIdPermissionsResponse400 | PostApiV1SecurityRolesRoleIdPermissionsResponse401 | PostApiV1SecurityRolesRoleIdPermissionsResponse404 | PostApiV1SecurityRolesRoleIdPermissionsResponse422 | PostApiV1SecurityRolesRoleIdPermissionsResponse500]
    """

    kwargs = _get_kwargs(
        role_id=role_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    role_id: int,
    *,
    client: AuthenticatedClient,
    body: RolePermissionPostSchema,
) -> (
    PostApiV1SecurityRolesRoleIdPermissionsResponse200
    | PostApiV1SecurityRolesRoleIdPermissionsResponse400
    | PostApiV1SecurityRolesRoleIdPermissionsResponse401
    | PostApiV1SecurityRolesRoleIdPermissionsResponse404
    | PostApiV1SecurityRolesRoleIdPermissionsResponse422
    | PostApiV1SecurityRolesRoleIdPermissionsResponse500
    | None
):
    """
    Args:
        role_id (int):
        body (RolePermissionPostSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1SecurityRolesRoleIdPermissionsResponse200 | PostApiV1SecurityRolesRoleIdPermissionsResponse400 | PostApiV1SecurityRolesRoleIdPermissionsResponse401 | PostApiV1SecurityRolesRoleIdPermissionsResponse404 | PostApiV1SecurityRolesRoleIdPermissionsResponse422 | PostApiV1SecurityRolesRoleIdPermissionsResponse500
    """

    return sync_detailed(
        role_id=role_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    role_id: int,
    *,
    client: AuthenticatedClient,
    body: RolePermissionPostSchema,
) -> Response[
    PostApiV1SecurityRolesRoleIdPermissionsResponse200
    | PostApiV1SecurityRolesRoleIdPermissionsResponse400
    | PostApiV1SecurityRolesRoleIdPermissionsResponse401
    | PostApiV1SecurityRolesRoleIdPermissionsResponse404
    | PostApiV1SecurityRolesRoleIdPermissionsResponse422
    | PostApiV1SecurityRolesRoleIdPermissionsResponse500
]:
    """
    Args:
        role_id (int):
        body (RolePermissionPostSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1SecurityRolesRoleIdPermissionsResponse200 | PostApiV1SecurityRolesRoleIdPermissionsResponse400 | PostApiV1SecurityRolesRoleIdPermissionsResponse401 | PostApiV1SecurityRolesRoleIdPermissionsResponse404 | PostApiV1SecurityRolesRoleIdPermissionsResponse422 | PostApiV1SecurityRolesRoleIdPermissionsResponse500]
    """

    kwargs = _get_kwargs(
        role_id=role_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    role_id: int,
    *,
    client: AuthenticatedClient,
    body: RolePermissionPostSchema,
) -> (
    PostApiV1SecurityRolesRoleIdPermissionsResponse200
    | PostApiV1SecurityRolesRoleIdPermissionsResponse400
    | PostApiV1SecurityRolesRoleIdPermissionsResponse401
    | PostApiV1SecurityRolesRoleIdPermissionsResponse404
    | PostApiV1SecurityRolesRoleIdPermissionsResponse422
    | PostApiV1SecurityRolesRoleIdPermissionsResponse500
    | None
):
    """
    Args:
        role_id (int):
        body (RolePermissionPostSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1SecurityRolesRoleIdPermissionsResponse200 | PostApiV1SecurityRolesRoleIdPermissionsResponse400 | PostApiV1SecurityRolesRoleIdPermissionsResponse401 | PostApiV1SecurityRolesRoleIdPermissionsResponse404 | PostApiV1SecurityRolesRoleIdPermissionsResponse422 | PostApiV1SecurityRolesRoleIdPermissionsResponse500
    """

    return (
        await asyncio_detailed(
            role_id=role_id,
            client=client,
            body=body,
        )
    ).parsed
