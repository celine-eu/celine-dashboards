from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.annotation_layer_rest_api_post import AnnotationLayerRestApiPost
from ...models.post_api_v1_annotation_layer_response_201 import PostApiV1AnnotationLayerResponse201
from ...models.post_api_v1_annotation_layer_response_400 import PostApiV1AnnotationLayerResponse400
from ...models.post_api_v1_annotation_layer_response_401 import PostApiV1AnnotationLayerResponse401
from ...models.post_api_v1_annotation_layer_response_404 import PostApiV1AnnotationLayerResponse404
from ...models.post_api_v1_annotation_layer_response_500 import PostApiV1AnnotationLayerResponse500
from ...types import Response


def _get_kwargs(
    *,
    body: AnnotationLayerRestApiPost,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/annotation_layer/",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    PostApiV1AnnotationLayerResponse201
    | PostApiV1AnnotationLayerResponse400
    | PostApiV1AnnotationLayerResponse401
    | PostApiV1AnnotationLayerResponse404
    | PostApiV1AnnotationLayerResponse500
    | None
):
    if response.status_code == 201:
        response_201 = PostApiV1AnnotationLayerResponse201.from_dict(response.json())

        return response_201

    if response.status_code == 400:
        response_400 = PostApiV1AnnotationLayerResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PostApiV1AnnotationLayerResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = PostApiV1AnnotationLayerResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 500:
        response_500 = PostApiV1AnnotationLayerResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PostApiV1AnnotationLayerResponse201
    | PostApiV1AnnotationLayerResponse400
    | PostApiV1AnnotationLayerResponse401
    | PostApiV1AnnotationLayerResponse404
    | PostApiV1AnnotationLayerResponse500
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
    body: AnnotationLayerRestApiPost,
) -> Response[
    PostApiV1AnnotationLayerResponse201
    | PostApiV1AnnotationLayerResponse400
    | PostApiV1AnnotationLayerResponse401
    | PostApiV1AnnotationLayerResponse404
    | PostApiV1AnnotationLayerResponse500
]:
    """Create an annotation layer

    Args:
        body (AnnotationLayerRestApiPost):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1AnnotationLayerResponse201 | PostApiV1AnnotationLayerResponse400 | PostApiV1AnnotationLayerResponse401 | PostApiV1AnnotationLayerResponse404 | PostApiV1AnnotationLayerResponse500]
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
    body: AnnotationLayerRestApiPost,
) -> (
    PostApiV1AnnotationLayerResponse201
    | PostApiV1AnnotationLayerResponse400
    | PostApiV1AnnotationLayerResponse401
    | PostApiV1AnnotationLayerResponse404
    | PostApiV1AnnotationLayerResponse500
    | None
):
    """Create an annotation layer

    Args:
        body (AnnotationLayerRestApiPost):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1AnnotationLayerResponse201 | PostApiV1AnnotationLayerResponse400 | PostApiV1AnnotationLayerResponse401 | PostApiV1AnnotationLayerResponse404 | PostApiV1AnnotationLayerResponse500
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: AnnotationLayerRestApiPost,
) -> Response[
    PostApiV1AnnotationLayerResponse201
    | PostApiV1AnnotationLayerResponse400
    | PostApiV1AnnotationLayerResponse401
    | PostApiV1AnnotationLayerResponse404
    | PostApiV1AnnotationLayerResponse500
]:
    """Create an annotation layer

    Args:
        body (AnnotationLayerRestApiPost):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1AnnotationLayerResponse201 | PostApiV1AnnotationLayerResponse400 | PostApiV1AnnotationLayerResponse401 | PostApiV1AnnotationLayerResponse404 | PostApiV1AnnotationLayerResponse500]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: AnnotationLayerRestApiPost,
) -> (
    PostApiV1AnnotationLayerResponse201
    | PostApiV1AnnotationLayerResponse400
    | PostApiV1AnnotationLayerResponse401
    | PostApiV1AnnotationLayerResponse404
    | PostApiV1AnnotationLayerResponse500
    | None
):
    """Create an annotation layer

    Args:
        body (AnnotationLayerRestApiPost):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1AnnotationLayerResponse201 | PostApiV1AnnotationLayerResponse400 | PostApiV1AnnotationLayerResponse401 | PostApiV1AnnotationLayerResponse404 | PostApiV1AnnotationLayerResponse500
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
