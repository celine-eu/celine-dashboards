from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.annotation_layer_rest_api_put import AnnotationLayerRestApiPut
from ...models.put_api_v1_annotation_layer_pk_response_200 import PutApiV1AnnotationLayerPkResponse200
from ...models.put_api_v1_annotation_layer_pk_response_400 import PutApiV1AnnotationLayerPkResponse400
from ...models.put_api_v1_annotation_layer_pk_response_401 import PutApiV1AnnotationLayerPkResponse401
from ...models.put_api_v1_annotation_layer_pk_response_404 import PutApiV1AnnotationLayerPkResponse404
from ...models.put_api_v1_annotation_layer_pk_response_500 import PutApiV1AnnotationLayerPkResponse500
from ...types import Response


def _get_kwargs(
    pk: int,
    *,
    body: AnnotationLayerRestApiPut,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "put",
        "url": "/api/v1/annotation_layer/{pk}".format(
            pk=quote(str(pk), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    PutApiV1AnnotationLayerPkResponse200
    | PutApiV1AnnotationLayerPkResponse400
    | PutApiV1AnnotationLayerPkResponse401
    | PutApiV1AnnotationLayerPkResponse404
    | PutApiV1AnnotationLayerPkResponse500
    | None
):
    if response.status_code == 200:
        response_200 = PutApiV1AnnotationLayerPkResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = PutApiV1AnnotationLayerPkResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PutApiV1AnnotationLayerPkResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = PutApiV1AnnotationLayerPkResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 500:
        response_500 = PutApiV1AnnotationLayerPkResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PutApiV1AnnotationLayerPkResponse200
    | PutApiV1AnnotationLayerPkResponse400
    | PutApiV1AnnotationLayerPkResponse401
    | PutApiV1AnnotationLayerPkResponse404
    | PutApiV1AnnotationLayerPkResponse500
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
    body: AnnotationLayerRestApiPut,
) -> Response[
    PutApiV1AnnotationLayerPkResponse200
    | PutApiV1AnnotationLayerPkResponse400
    | PutApiV1AnnotationLayerPkResponse401
    | PutApiV1AnnotationLayerPkResponse404
    | PutApiV1AnnotationLayerPkResponse500
]:
    """Update an annotation layer

    Args:
        pk (int):
        body (AnnotationLayerRestApiPut):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PutApiV1AnnotationLayerPkResponse200 | PutApiV1AnnotationLayerPkResponse400 | PutApiV1AnnotationLayerPkResponse401 | PutApiV1AnnotationLayerPkResponse404 | PutApiV1AnnotationLayerPkResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    pk: int,
    *,
    client: AuthenticatedClient,
    body: AnnotationLayerRestApiPut,
) -> (
    PutApiV1AnnotationLayerPkResponse200
    | PutApiV1AnnotationLayerPkResponse400
    | PutApiV1AnnotationLayerPkResponse401
    | PutApiV1AnnotationLayerPkResponse404
    | PutApiV1AnnotationLayerPkResponse500
    | None
):
    """Update an annotation layer

    Args:
        pk (int):
        body (AnnotationLayerRestApiPut):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PutApiV1AnnotationLayerPkResponse200 | PutApiV1AnnotationLayerPkResponse400 | PutApiV1AnnotationLayerPkResponse401 | PutApiV1AnnotationLayerPkResponse404 | PutApiV1AnnotationLayerPkResponse500
    """

    return sync_detailed(
        pk=pk,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    pk: int,
    *,
    client: AuthenticatedClient,
    body: AnnotationLayerRestApiPut,
) -> Response[
    PutApiV1AnnotationLayerPkResponse200
    | PutApiV1AnnotationLayerPkResponse400
    | PutApiV1AnnotationLayerPkResponse401
    | PutApiV1AnnotationLayerPkResponse404
    | PutApiV1AnnotationLayerPkResponse500
]:
    """Update an annotation layer

    Args:
        pk (int):
        body (AnnotationLayerRestApiPut):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PutApiV1AnnotationLayerPkResponse200 | PutApiV1AnnotationLayerPkResponse400 | PutApiV1AnnotationLayerPkResponse401 | PutApiV1AnnotationLayerPkResponse404 | PutApiV1AnnotationLayerPkResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    pk: int,
    *,
    client: AuthenticatedClient,
    body: AnnotationLayerRestApiPut,
) -> (
    PutApiV1AnnotationLayerPkResponse200
    | PutApiV1AnnotationLayerPkResponse400
    | PutApiV1AnnotationLayerPkResponse401
    | PutApiV1AnnotationLayerPkResponse404
    | PutApiV1AnnotationLayerPkResponse500
    | None
):
    """Update an annotation layer

    Args:
        pk (int):
        body (AnnotationLayerRestApiPut):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PutApiV1AnnotationLayerPkResponse200 | PutApiV1AnnotationLayerPkResponse400 | PutApiV1AnnotationLayerPkResponse401 | PutApiV1AnnotationLayerPkResponse404 | PutApiV1AnnotationLayerPkResponse500
    """

    return (
        await asyncio_detailed(
            pk=pk,
            client=client,
            body=body,
        )
    ).parsed
