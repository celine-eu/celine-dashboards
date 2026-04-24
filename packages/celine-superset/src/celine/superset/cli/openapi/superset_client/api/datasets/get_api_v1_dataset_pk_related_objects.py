from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.dataset_related_objects_response import DatasetRelatedObjectsResponse
from ...models.get_api_v1_dataset_pk_related_objects_response_401 import GetApiV1DatasetPkRelatedObjectsResponse401
from ...models.get_api_v1_dataset_pk_related_objects_response_404 import GetApiV1DatasetPkRelatedObjectsResponse404
from ...models.get_api_v1_dataset_pk_related_objects_response_500 import GetApiV1DatasetPkRelatedObjectsResponse500
from ...types import Response


def _get_kwargs(
    pk: int,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/dataset/{pk}/related_objects".format(
            pk=quote(str(pk), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    DatasetRelatedObjectsResponse
    | GetApiV1DatasetPkRelatedObjectsResponse401
    | GetApiV1DatasetPkRelatedObjectsResponse404
    | GetApiV1DatasetPkRelatedObjectsResponse500
    | None
):
    if response.status_code == 200:
        response_200 = DatasetRelatedObjectsResponse.from_dict(response.json())

        return response_200

    if response.status_code == 401:
        response_401 = GetApiV1DatasetPkRelatedObjectsResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = GetApiV1DatasetPkRelatedObjectsResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 500:
        response_500 = GetApiV1DatasetPkRelatedObjectsResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    DatasetRelatedObjectsResponse
    | GetApiV1DatasetPkRelatedObjectsResponse401
    | GetApiV1DatasetPkRelatedObjectsResponse404
    | GetApiV1DatasetPkRelatedObjectsResponse500
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
    DatasetRelatedObjectsResponse
    | GetApiV1DatasetPkRelatedObjectsResponse401
    | GetApiV1DatasetPkRelatedObjectsResponse404
    | GetApiV1DatasetPkRelatedObjectsResponse500
]:
    """Get charts and dashboards count associated to a dataset

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DatasetRelatedObjectsResponse | GetApiV1DatasetPkRelatedObjectsResponse401 | GetApiV1DatasetPkRelatedObjectsResponse404 | GetApiV1DatasetPkRelatedObjectsResponse500]
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
    DatasetRelatedObjectsResponse
    | GetApiV1DatasetPkRelatedObjectsResponse401
    | GetApiV1DatasetPkRelatedObjectsResponse404
    | GetApiV1DatasetPkRelatedObjectsResponse500
    | None
):
    """Get charts and dashboards count associated to a dataset

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DatasetRelatedObjectsResponse | GetApiV1DatasetPkRelatedObjectsResponse401 | GetApiV1DatasetPkRelatedObjectsResponse404 | GetApiV1DatasetPkRelatedObjectsResponse500
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
    DatasetRelatedObjectsResponse
    | GetApiV1DatasetPkRelatedObjectsResponse401
    | GetApiV1DatasetPkRelatedObjectsResponse404
    | GetApiV1DatasetPkRelatedObjectsResponse500
]:
    """Get charts and dashboards count associated to a dataset

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DatasetRelatedObjectsResponse | GetApiV1DatasetPkRelatedObjectsResponse401 | GetApiV1DatasetPkRelatedObjectsResponse404 | GetApiV1DatasetPkRelatedObjectsResponse500]
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
    DatasetRelatedObjectsResponse
    | GetApiV1DatasetPkRelatedObjectsResponse401
    | GetApiV1DatasetPkRelatedObjectsResponse404
    | GetApiV1DatasetPkRelatedObjectsResponse500
    | None
):
    """Get charts and dashboards count associated to a dataset

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DatasetRelatedObjectsResponse | GetApiV1DatasetPkRelatedObjectsResponse401 | GetApiV1DatasetPkRelatedObjectsResponse404 | GetApiV1DatasetPkRelatedObjectsResponse500
    """

    return (
        await asyncio_detailed(
            pk=pk,
            client=client,
        )
    ).parsed
