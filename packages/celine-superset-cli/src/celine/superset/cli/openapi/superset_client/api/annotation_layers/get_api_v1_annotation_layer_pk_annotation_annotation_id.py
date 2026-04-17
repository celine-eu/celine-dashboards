from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_annotation_layer_pk_annotation_annotation_id_response_200 import (
    GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse200,
)
from ...models.get_api_v1_annotation_layer_pk_annotation_annotation_id_response_400 import (
    GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse400,
)
from ...models.get_api_v1_annotation_layer_pk_annotation_annotation_id_response_401 import (
    GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse401,
)
from ...models.get_api_v1_annotation_layer_pk_annotation_annotation_id_response_404 import (
    GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse404,
)
from ...models.get_api_v1_annotation_layer_pk_annotation_annotation_id_response_422 import (
    GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse422,
)
from ...models.get_api_v1_annotation_layer_pk_annotation_annotation_id_response_500 import (
    GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse500,
)
from ...types import Response


def _get_kwargs(
    pk: int,
    annotation_id: int,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/annotation_layer/{pk}/annotation/{annotation_id}".format(
            pk=quote(str(pk), safe=""),
            annotation_id=quote(str(annotation_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse200
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse400
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse401
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse404
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse422
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse500
    | None
):
    if response.status_code == 200:
        response_200 = GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 422:
        response_422 = GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse200
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse400
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse401
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse404
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse422
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse500
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    pk: int,
    annotation_id: int,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse200
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse400
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse401
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse404
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse422
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse500
]:
    """Get an annotation layer

    Args:
        pk (int):
        annotation_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse200 | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse400 | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse401 | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse404 | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse422 | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
        annotation_id=annotation_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    pk: int,
    annotation_id: int,
    *,
    client: AuthenticatedClient,
) -> (
    GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse200
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse400
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse401
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse404
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse422
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse500
    | None
):
    """Get an annotation layer

    Args:
        pk (int):
        annotation_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse200 | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse400 | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse401 | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse404 | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse422 | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse500
    """

    return sync_detailed(
        pk=pk,
        annotation_id=annotation_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    pk: int,
    annotation_id: int,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse200
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse400
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse401
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse404
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse422
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse500
]:
    """Get an annotation layer

    Args:
        pk (int):
        annotation_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse200 | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse400 | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse401 | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse404 | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse422 | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
        annotation_id=annotation_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    pk: int,
    annotation_id: int,
    *,
    client: AuthenticatedClient,
) -> (
    GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse200
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse400
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse401
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse404
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse422
    | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse500
    | None
):
    """Get an annotation layer

    Args:
        pk (int):
        annotation_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse200 | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse400 | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse401 | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse404 | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse422 | GetApiV1AnnotationLayerPkAnnotationAnnotationIdResponse500
    """

    return (
        await asyncio_detailed(
            pk=pk,
            annotation_id=annotation_id,
            client=client,
        )
    ).parsed
