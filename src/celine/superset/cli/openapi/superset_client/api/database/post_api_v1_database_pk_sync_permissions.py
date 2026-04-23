from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.post_api_v1_database_pk_sync_permissions_response_200 import (
    PostApiV1DatabasePkSyncPermissionsResponse200,
)
from ...models.post_api_v1_database_pk_sync_permissions_response_400 import (
    PostApiV1DatabasePkSyncPermissionsResponse400,
)
from ...models.post_api_v1_database_pk_sync_permissions_response_401 import (
    PostApiV1DatabasePkSyncPermissionsResponse401,
)
from ...models.post_api_v1_database_pk_sync_permissions_response_404 import (
    PostApiV1DatabasePkSyncPermissionsResponse404,
)
from ...models.post_api_v1_database_pk_sync_permissions_response_500 import (
    PostApiV1DatabasePkSyncPermissionsResponse500,
)
from ...types import Response


def _get_kwargs(
    pk: int,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/database/{pk}/sync_permissions/".format(
            pk=quote(str(pk), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    PostApiV1DatabasePkSyncPermissionsResponse200
    | PostApiV1DatabasePkSyncPermissionsResponse400
    | PostApiV1DatabasePkSyncPermissionsResponse401
    | PostApiV1DatabasePkSyncPermissionsResponse404
    | PostApiV1DatabasePkSyncPermissionsResponse500
    | None
):
    if response.status_code == 200:
        response_200 = PostApiV1DatabasePkSyncPermissionsResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = PostApiV1DatabasePkSyncPermissionsResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PostApiV1DatabasePkSyncPermissionsResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = PostApiV1DatabasePkSyncPermissionsResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 500:
        response_500 = PostApiV1DatabasePkSyncPermissionsResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PostApiV1DatabasePkSyncPermissionsResponse200
    | PostApiV1DatabasePkSyncPermissionsResponse400
    | PostApiV1DatabasePkSyncPermissionsResponse401
    | PostApiV1DatabasePkSyncPermissionsResponse404
    | PostApiV1DatabasePkSyncPermissionsResponse500
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
    PostApiV1DatabasePkSyncPermissionsResponse200
    | PostApiV1DatabasePkSyncPermissionsResponse400
    | PostApiV1DatabasePkSyncPermissionsResponse401
    | PostApiV1DatabasePkSyncPermissionsResponse404
    | PostApiV1DatabasePkSyncPermissionsResponse500
]:
    """Re-sync all permissions for a database connection

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1DatabasePkSyncPermissionsResponse200 | PostApiV1DatabasePkSyncPermissionsResponse400 | PostApiV1DatabasePkSyncPermissionsResponse401 | PostApiV1DatabasePkSyncPermissionsResponse404 | PostApiV1DatabasePkSyncPermissionsResponse500]
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
    PostApiV1DatabasePkSyncPermissionsResponse200
    | PostApiV1DatabasePkSyncPermissionsResponse400
    | PostApiV1DatabasePkSyncPermissionsResponse401
    | PostApiV1DatabasePkSyncPermissionsResponse404
    | PostApiV1DatabasePkSyncPermissionsResponse500
    | None
):
    """Re-sync all permissions for a database connection

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1DatabasePkSyncPermissionsResponse200 | PostApiV1DatabasePkSyncPermissionsResponse400 | PostApiV1DatabasePkSyncPermissionsResponse401 | PostApiV1DatabasePkSyncPermissionsResponse404 | PostApiV1DatabasePkSyncPermissionsResponse500
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
    PostApiV1DatabasePkSyncPermissionsResponse200
    | PostApiV1DatabasePkSyncPermissionsResponse400
    | PostApiV1DatabasePkSyncPermissionsResponse401
    | PostApiV1DatabasePkSyncPermissionsResponse404
    | PostApiV1DatabasePkSyncPermissionsResponse500
]:
    """Re-sync all permissions for a database connection

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1DatabasePkSyncPermissionsResponse200 | PostApiV1DatabasePkSyncPermissionsResponse400 | PostApiV1DatabasePkSyncPermissionsResponse401 | PostApiV1DatabasePkSyncPermissionsResponse404 | PostApiV1DatabasePkSyncPermissionsResponse500]
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
    PostApiV1DatabasePkSyncPermissionsResponse200
    | PostApiV1DatabasePkSyncPermissionsResponse400
    | PostApiV1DatabasePkSyncPermissionsResponse401
    | PostApiV1DatabasePkSyncPermissionsResponse404
    | PostApiV1DatabasePkSyncPermissionsResponse500
    | None
):
    """Re-sync all permissions for a database connection

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1DatabasePkSyncPermissionsResponse200 | PostApiV1DatabasePkSyncPermissionsResponse400 | PostApiV1DatabasePkSyncPermissionsResponse401 | PostApiV1DatabasePkSyncPermissionsResponse404 | PostApiV1DatabasePkSyncPermissionsResponse500
    """

    return (
        await asyncio_detailed(
            pk=pk,
            client=client,
        )
    ).parsed
