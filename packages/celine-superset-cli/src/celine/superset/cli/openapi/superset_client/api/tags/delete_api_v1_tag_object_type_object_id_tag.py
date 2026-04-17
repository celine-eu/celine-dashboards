from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.delete_api_v1_tag_object_type_object_id_tag_response_200 import (
    DeleteApiV1TagObjectTypeObjectIdTagResponse200,
)
from ...models.delete_api_v1_tag_object_type_object_id_tag_response_401 import (
    DeleteApiV1TagObjectTypeObjectIdTagResponse401,
)
from ...models.delete_api_v1_tag_object_type_object_id_tag_response_403 import (
    DeleteApiV1TagObjectTypeObjectIdTagResponse403,
)
from ...models.delete_api_v1_tag_object_type_object_id_tag_response_404 import (
    DeleteApiV1TagObjectTypeObjectIdTagResponse404,
)
from ...models.delete_api_v1_tag_object_type_object_id_tag_response_422 import (
    DeleteApiV1TagObjectTypeObjectIdTagResponse422,
)
from ...models.delete_api_v1_tag_object_type_object_id_tag_response_500 import (
    DeleteApiV1TagObjectTypeObjectIdTagResponse500,
)
from ...types import Response


def _get_kwargs(
    object_type: int,
    object_id: int,
    tag: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "delete",
        "url": "/api/v1/tag/{object_type}/{object_id}/{tag}/".format(
            object_type=quote(str(object_type), safe=""),
            object_id=quote(str(object_id), safe=""),
            tag=quote(str(tag), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    DeleteApiV1TagObjectTypeObjectIdTagResponse200
    | DeleteApiV1TagObjectTypeObjectIdTagResponse401
    | DeleteApiV1TagObjectTypeObjectIdTagResponse403
    | DeleteApiV1TagObjectTypeObjectIdTagResponse404
    | DeleteApiV1TagObjectTypeObjectIdTagResponse422
    | DeleteApiV1TagObjectTypeObjectIdTagResponse500
    | None
):
    if response.status_code == 200:
        response_200 = DeleteApiV1TagObjectTypeObjectIdTagResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 401:
        response_401 = DeleteApiV1TagObjectTypeObjectIdTagResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 403:
        response_403 = DeleteApiV1TagObjectTypeObjectIdTagResponse403.from_dict(response.json())

        return response_403

    if response.status_code == 404:
        response_404 = DeleteApiV1TagObjectTypeObjectIdTagResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 422:
        response_422 = DeleteApiV1TagObjectTypeObjectIdTagResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = DeleteApiV1TagObjectTypeObjectIdTagResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    DeleteApiV1TagObjectTypeObjectIdTagResponse200
    | DeleteApiV1TagObjectTypeObjectIdTagResponse401
    | DeleteApiV1TagObjectTypeObjectIdTagResponse403
    | DeleteApiV1TagObjectTypeObjectIdTagResponse404
    | DeleteApiV1TagObjectTypeObjectIdTagResponse422
    | DeleteApiV1TagObjectTypeObjectIdTagResponse500
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    object_type: int,
    object_id: int,
    tag: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    DeleteApiV1TagObjectTypeObjectIdTagResponse200
    | DeleteApiV1TagObjectTypeObjectIdTagResponse401
    | DeleteApiV1TagObjectTypeObjectIdTagResponse403
    | DeleteApiV1TagObjectTypeObjectIdTagResponse404
    | DeleteApiV1TagObjectTypeObjectIdTagResponse422
    | DeleteApiV1TagObjectTypeObjectIdTagResponse500
]:
    """Delete a tagged object

    Args:
        object_type (int):
        object_id (int):
        tag (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeleteApiV1TagObjectTypeObjectIdTagResponse200 | DeleteApiV1TagObjectTypeObjectIdTagResponse401 | DeleteApiV1TagObjectTypeObjectIdTagResponse403 | DeleteApiV1TagObjectTypeObjectIdTagResponse404 | DeleteApiV1TagObjectTypeObjectIdTagResponse422 | DeleteApiV1TagObjectTypeObjectIdTagResponse500]
    """

    kwargs = _get_kwargs(
        object_type=object_type,
        object_id=object_id,
        tag=tag,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    object_type: int,
    object_id: int,
    tag: str,
    *,
    client: AuthenticatedClient,
) -> (
    DeleteApiV1TagObjectTypeObjectIdTagResponse200
    | DeleteApiV1TagObjectTypeObjectIdTagResponse401
    | DeleteApiV1TagObjectTypeObjectIdTagResponse403
    | DeleteApiV1TagObjectTypeObjectIdTagResponse404
    | DeleteApiV1TagObjectTypeObjectIdTagResponse422
    | DeleteApiV1TagObjectTypeObjectIdTagResponse500
    | None
):
    """Delete a tagged object

    Args:
        object_type (int):
        object_id (int):
        tag (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeleteApiV1TagObjectTypeObjectIdTagResponse200 | DeleteApiV1TagObjectTypeObjectIdTagResponse401 | DeleteApiV1TagObjectTypeObjectIdTagResponse403 | DeleteApiV1TagObjectTypeObjectIdTagResponse404 | DeleteApiV1TagObjectTypeObjectIdTagResponse422 | DeleteApiV1TagObjectTypeObjectIdTagResponse500
    """

    return sync_detailed(
        object_type=object_type,
        object_id=object_id,
        tag=tag,
        client=client,
    ).parsed


async def asyncio_detailed(
    object_type: int,
    object_id: int,
    tag: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    DeleteApiV1TagObjectTypeObjectIdTagResponse200
    | DeleteApiV1TagObjectTypeObjectIdTagResponse401
    | DeleteApiV1TagObjectTypeObjectIdTagResponse403
    | DeleteApiV1TagObjectTypeObjectIdTagResponse404
    | DeleteApiV1TagObjectTypeObjectIdTagResponse422
    | DeleteApiV1TagObjectTypeObjectIdTagResponse500
]:
    """Delete a tagged object

    Args:
        object_type (int):
        object_id (int):
        tag (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeleteApiV1TagObjectTypeObjectIdTagResponse200 | DeleteApiV1TagObjectTypeObjectIdTagResponse401 | DeleteApiV1TagObjectTypeObjectIdTagResponse403 | DeleteApiV1TagObjectTypeObjectIdTagResponse404 | DeleteApiV1TagObjectTypeObjectIdTagResponse422 | DeleteApiV1TagObjectTypeObjectIdTagResponse500]
    """

    kwargs = _get_kwargs(
        object_type=object_type,
        object_id=object_id,
        tag=tag,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    object_type: int,
    object_id: int,
    tag: str,
    *,
    client: AuthenticatedClient,
) -> (
    DeleteApiV1TagObjectTypeObjectIdTagResponse200
    | DeleteApiV1TagObjectTypeObjectIdTagResponse401
    | DeleteApiV1TagObjectTypeObjectIdTagResponse403
    | DeleteApiV1TagObjectTypeObjectIdTagResponse404
    | DeleteApiV1TagObjectTypeObjectIdTagResponse422
    | DeleteApiV1TagObjectTypeObjectIdTagResponse500
    | None
):
    """Delete a tagged object

    Args:
        object_type (int):
        object_id (int):
        tag (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeleteApiV1TagObjectTypeObjectIdTagResponse200 | DeleteApiV1TagObjectTypeObjectIdTagResponse401 | DeleteApiV1TagObjectTypeObjectIdTagResponse403 | DeleteApiV1TagObjectTypeObjectIdTagResponse404 | DeleteApiV1TagObjectTypeObjectIdTagResponse422 | DeleteApiV1TagObjectTypeObjectIdTagResponse500
    """

    return (
        await asyncio_detailed(
            object_type=object_type,
            object_id=object_id,
            tag=tag,
            client=client,
        )
    ).parsed
