from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.post_api_v1_tag_object_type_object_id_body import PostApiV1TagObjectTypeObjectIdBody
from ...models.post_api_v1_tag_object_type_object_id_response_400 import PostApiV1TagObjectTypeObjectIdResponse400
from ...models.post_api_v1_tag_object_type_object_id_response_401 import PostApiV1TagObjectTypeObjectIdResponse401
from ...models.post_api_v1_tag_object_type_object_id_response_404 import PostApiV1TagObjectTypeObjectIdResponse404
from ...models.post_api_v1_tag_object_type_object_id_response_500 import PostApiV1TagObjectTypeObjectIdResponse500
from ...types import Response


def _get_kwargs(
    object_type: int,
    object_id: int,
    *,
    body: PostApiV1TagObjectTypeObjectIdBody,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/tag/{object_type}/{object_id}/".format(
            object_type=quote(str(object_type), safe=""),
            object_id=quote(str(object_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    Any
    | PostApiV1TagObjectTypeObjectIdResponse400
    | PostApiV1TagObjectTypeObjectIdResponse401
    | PostApiV1TagObjectTypeObjectIdResponse404
    | PostApiV1TagObjectTypeObjectIdResponse500
    | None
):
    if response.status_code == 201:
        response_201 = cast(Any, None)
        return response_201

    if response.status_code == 302:
        response_302 = cast(Any, None)
        return response_302

    if response.status_code == 400:
        response_400 = PostApiV1TagObjectTypeObjectIdResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PostApiV1TagObjectTypeObjectIdResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = PostApiV1TagObjectTypeObjectIdResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 500:
        response_500 = PostApiV1TagObjectTypeObjectIdResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    Any
    | PostApiV1TagObjectTypeObjectIdResponse400
    | PostApiV1TagObjectTypeObjectIdResponse401
    | PostApiV1TagObjectTypeObjectIdResponse404
    | PostApiV1TagObjectTypeObjectIdResponse500
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
    *,
    client: AuthenticatedClient,
    body: PostApiV1TagObjectTypeObjectIdBody,
) -> Response[
    Any
    | PostApiV1TagObjectTypeObjectIdResponse400
    | PostApiV1TagObjectTypeObjectIdResponse401
    | PostApiV1TagObjectTypeObjectIdResponse404
    | PostApiV1TagObjectTypeObjectIdResponse500
]:
    """Add tags to an object

     Adds tags to an object. Creates new tags if they do not already exist.

    Args:
        object_type (int):
        object_id (int):
        body (PostApiV1TagObjectTypeObjectIdBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | PostApiV1TagObjectTypeObjectIdResponse400 | PostApiV1TagObjectTypeObjectIdResponse401 | PostApiV1TagObjectTypeObjectIdResponse404 | PostApiV1TagObjectTypeObjectIdResponse500]
    """

    kwargs = _get_kwargs(
        object_type=object_type,
        object_id=object_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    object_type: int,
    object_id: int,
    *,
    client: AuthenticatedClient,
    body: PostApiV1TagObjectTypeObjectIdBody,
) -> (
    Any
    | PostApiV1TagObjectTypeObjectIdResponse400
    | PostApiV1TagObjectTypeObjectIdResponse401
    | PostApiV1TagObjectTypeObjectIdResponse404
    | PostApiV1TagObjectTypeObjectIdResponse500
    | None
):
    """Add tags to an object

     Adds tags to an object. Creates new tags if they do not already exist.

    Args:
        object_type (int):
        object_id (int):
        body (PostApiV1TagObjectTypeObjectIdBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | PostApiV1TagObjectTypeObjectIdResponse400 | PostApiV1TagObjectTypeObjectIdResponse401 | PostApiV1TagObjectTypeObjectIdResponse404 | PostApiV1TagObjectTypeObjectIdResponse500
    """

    return sync_detailed(
        object_type=object_type,
        object_id=object_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    object_type: int,
    object_id: int,
    *,
    client: AuthenticatedClient,
    body: PostApiV1TagObjectTypeObjectIdBody,
) -> Response[
    Any
    | PostApiV1TagObjectTypeObjectIdResponse400
    | PostApiV1TagObjectTypeObjectIdResponse401
    | PostApiV1TagObjectTypeObjectIdResponse404
    | PostApiV1TagObjectTypeObjectIdResponse500
]:
    """Add tags to an object

     Adds tags to an object. Creates new tags if they do not already exist.

    Args:
        object_type (int):
        object_id (int):
        body (PostApiV1TagObjectTypeObjectIdBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | PostApiV1TagObjectTypeObjectIdResponse400 | PostApiV1TagObjectTypeObjectIdResponse401 | PostApiV1TagObjectTypeObjectIdResponse404 | PostApiV1TagObjectTypeObjectIdResponse500]
    """

    kwargs = _get_kwargs(
        object_type=object_type,
        object_id=object_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    object_type: int,
    object_id: int,
    *,
    client: AuthenticatedClient,
    body: PostApiV1TagObjectTypeObjectIdBody,
) -> (
    Any
    | PostApiV1TagObjectTypeObjectIdResponse400
    | PostApiV1TagObjectTypeObjectIdResponse401
    | PostApiV1TagObjectTypeObjectIdResponse404
    | PostApiV1TagObjectTypeObjectIdResponse500
    | None
):
    """Add tags to an object

     Adds tags to an object. Creates new tags if they do not already exist.

    Args:
        object_type (int):
        object_id (int):
        body (PostApiV1TagObjectTypeObjectIdBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | PostApiV1TagObjectTypeObjectIdResponse400 | PostApiV1TagObjectTypeObjectIdResponse401 | PostApiV1TagObjectTypeObjectIdResponse404 | PostApiV1TagObjectTypeObjectIdResponse500
    """

    return (
        await asyncio_detailed(
            object_type=object_type,
            object_id=object_id,
            client=client,
            body=body,
        )
    ).parsed
