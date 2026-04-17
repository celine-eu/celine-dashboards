from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_user_user_id_avatar_png_response_401 import GetApiV1UserUserIdAvatarPngResponse401
from ...models.get_api_v1_user_user_id_avatar_png_response_404 import GetApiV1UserUserIdAvatarPngResponse404
from ...types import Response


def _get_kwargs(
    user_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/user/{user_id}/avatar.png".format(
            user_id=quote(str(user_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | GetApiV1UserUserIdAvatarPngResponse401 | GetApiV1UserUserIdAvatarPngResponse404 | None:
    if response.status_code == 301:
        response_301 = cast(Any, None)
        return response_301

    if response.status_code == 401:
        response_401 = GetApiV1UserUserIdAvatarPngResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = GetApiV1UserUserIdAvatarPngResponse404.from_dict(response.json())

        return response_404

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[Any | GetApiV1UserUserIdAvatarPngResponse401 | GetApiV1UserUserIdAvatarPngResponse404]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    user_id: str,
    *,
    client: AuthenticatedClient | Client,
) -> Response[Any | GetApiV1UserUserIdAvatarPngResponse401 | GetApiV1UserUserIdAvatarPngResponse404]:
    """Get the user avatar

     Gets the avatar URL for the user with the given ID, or returns a 401 error if the user is
    unauthenticated.

    Args:
        user_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | GetApiV1UserUserIdAvatarPngResponse401 | GetApiV1UserUserIdAvatarPngResponse404]
    """

    kwargs = _get_kwargs(
        user_id=user_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    user_id: str,
    *,
    client: AuthenticatedClient | Client,
) -> Any | GetApiV1UserUserIdAvatarPngResponse401 | GetApiV1UserUserIdAvatarPngResponse404 | None:
    """Get the user avatar

     Gets the avatar URL for the user with the given ID, or returns a 401 error if the user is
    unauthenticated.

    Args:
        user_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | GetApiV1UserUserIdAvatarPngResponse401 | GetApiV1UserUserIdAvatarPngResponse404
    """

    return sync_detailed(
        user_id=user_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    user_id: str,
    *,
    client: AuthenticatedClient | Client,
) -> Response[Any | GetApiV1UserUserIdAvatarPngResponse401 | GetApiV1UserUserIdAvatarPngResponse404]:
    """Get the user avatar

     Gets the avatar URL for the user with the given ID, or returns a 401 error if the user is
    unauthenticated.

    Args:
        user_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | GetApiV1UserUserIdAvatarPngResponse401 | GetApiV1UserUserIdAvatarPngResponse404]
    """

    kwargs = _get_kwargs(
        user_id=user_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    user_id: str,
    *,
    client: AuthenticatedClient | Client,
) -> Any | GetApiV1UserUserIdAvatarPngResponse401 | GetApiV1UserUserIdAvatarPngResponse404 | None:
    """Get the user avatar

     Gets the avatar URL for the user with the given ID, or returns a 401 error if the user is
    unauthenticated.

    Args:
        user_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | GetApiV1UserUserIdAvatarPngResponse401 | GetApiV1UserUserIdAvatarPngResponse404
    """

    return (
        await asyncio_detailed(
            user_id=user_id,
            client=client,
        )
    ).parsed
