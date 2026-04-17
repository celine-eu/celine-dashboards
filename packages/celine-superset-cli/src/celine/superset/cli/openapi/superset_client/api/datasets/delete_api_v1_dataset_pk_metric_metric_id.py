from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.delete_api_v1_dataset_pk_metric_metric_id_response_200 import (
    DeleteApiV1DatasetPkMetricMetricIdResponse200,
)
from ...models.delete_api_v1_dataset_pk_metric_metric_id_response_401 import (
    DeleteApiV1DatasetPkMetricMetricIdResponse401,
)
from ...models.delete_api_v1_dataset_pk_metric_metric_id_response_403 import (
    DeleteApiV1DatasetPkMetricMetricIdResponse403,
)
from ...models.delete_api_v1_dataset_pk_metric_metric_id_response_404 import (
    DeleteApiV1DatasetPkMetricMetricIdResponse404,
)
from ...models.delete_api_v1_dataset_pk_metric_metric_id_response_422 import (
    DeleteApiV1DatasetPkMetricMetricIdResponse422,
)
from ...models.delete_api_v1_dataset_pk_metric_metric_id_response_500 import (
    DeleteApiV1DatasetPkMetricMetricIdResponse500,
)
from ...types import Response


def _get_kwargs(
    pk: int,
    metric_id: int,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "delete",
        "url": "/api/v1/dataset/{pk}/metric/{metric_id}".format(
            pk=quote(str(pk), safe=""),
            metric_id=quote(str(metric_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    DeleteApiV1DatasetPkMetricMetricIdResponse200
    | DeleteApiV1DatasetPkMetricMetricIdResponse401
    | DeleteApiV1DatasetPkMetricMetricIdResponse403
    | DeleteApiV1DatasetPkMetricMetricIdResponse404
    | DeleteApiV1DatasetPkMetricMetricIdResponse422
    | DeleteApiV1DatasetPkMetricMetricIdResponse500
    | None
):
    if response.status_code == 200:
        response_200 = DeleteApiV1DatasetPkMetricMetricIdResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 401:
        response_401 = DeleteApiV1DatasetPkMetricMetricIdResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 403:
        response_403 = DeleteApiV1DatasetPkMetricMetricIdResponse403.from_dict(response.json())

        return response_403

    if response.status_code == 404:
        response_404 = DeleteApiV1DatasetPkMetricMetricIdResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 422:
        response_422 = DeleteApiV1DatasetPkMetricMetricIdResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = DeleteApiV1DatasetPkMetricMetricIdResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    DeleteApiV1DatasetPkMetricMetricIdResponse200
    | DeleteApiV1DatasetPkMetricMetricIdResponse401
    | DeleteApiV1DatasetPkMetricMetricIdResponse403
    | DeleteApiV1DatasetPkMetricMetricIdResponse404
    | DeleteApiV1DatasetPkMetricMetricIdResponse422
    | DeleteApiV1DatasetPkMetricMetricIdResponse500
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    pk: int,
    metric_id: int,
    *,
    client: AuthenticatedClient,
) -> Response[
    DeleteApiV1DatasetPkMetricMetricIdResponse200
    | DeleteApiV1DatasetPkMetricMetricIdResponse401
    | DeleteApiV1DatasetPkMetricMetricIdResponse403
    | DeleteApiV1DatasetPkMetricMetricIdResponse404
    | DeleteApiV1DatasetPkMetricMetricIdResponse422
    | DeleteApiV1DatasetPkMetricMetricIdResponse500
]:
    """Delete a dataset metric

    Args:
        pk (int):
        metric_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeleteApiV1DatasetPkMetricMetricIdResponse200 | DeleteApiV1DatasetPkMetricMetricIdResponse401 | DeleteApiV1DatasetPkMetricMetricIdResponse403 | DeleteApiV1DatasetPkMetricMetricIdResponse404 | DeleteApiV1DatasetPkMetricMetricIdResponse422 | DeleteApiV1DatasetPkMetricMetricIdResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
        metric_id=metric_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    pk: int,
    metric_id: int,
    *,
    client: AuthenticatedClient,
) -> (
    DeleteApiV1DatasetPkMetricMetricIdResponse200
    | DeleteApiV1DatasetPkMetricMetricIdResponse401
    | DeleteApiV1DatasetPkMetricMetricIdResponse403
    | DeleteApiV1DatasetPkMetricMetricIdResponse404
    | DeleteApiV1DatasetPkMetricMetricIdResponse422
    | DeleteApiV1DatasetPkMetricMetricIdResponse500
    | None
):
    """Delete a dataset metric

    Args:
        pk (int):
        metric_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeleteApiV1DatasetPkMetricMetricIdResponse200 | DeleteApiV1DatasetPkMetricMetricIdResponse401 | DeleteApiV1DatasetPkMetricMetricIdResponse403 | DeleteApiV1DatasetPkMetricMetricIdResponse404 | DeleteApiV1DatasetPkMetricMetricIdResponse422 | DeleteApiV1DatasetPkMetricMetricIdResponse500
    """

    return sync_detailed(
        pk=pk,
        metric_id=metric_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    pk: int,
    metric_id: int,
    *,
    client: AuthenticatedClient,
) -> Response[
    DeleteApiV1DatasetPkMetricMetricIdResponse200
    | DeleteApiV1DatasetPkMetricMetricIdResponse401
    | DeleteApiV1DatasetPkMetricMetricIdResponse403
    | DeleteApiV1DatasetPkMetricMetricIdResponse404
    | DeleteApiV1DatasetPkMetricMetricIdResponse422
    | DeleteApiV1DatasetPkMetricMetricIdResponse500
]:
    """Delete a dataset metric

    Args:
        pk (int):
        metric_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeleteApiV1DatasetPkMetricMetricIdResponse200 | DeleteApiV1DatasetPkMetricMetricIdResponse401 | DeleteApiV1DatasetPkMetricMetricIdResponse403 | DeleteApiV1DatasetPkMetricMetricIdResponse404 | DeleteApiV1DatasetPkMetricMetricIdResponse422 | DeleteApiV1DatasetPkMetricMetricIdResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
        metric_id=metric_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    pk: int,
    metric_id: int,
    *,
    client: AuthenticatedClient,
) -> (
    DeleteApiV1DatasetPkMetricMetricIdResponse200
    | DeleteApiV1DatasetPkMetricMetricIdResponse401
    | DeleteApiV1DatasetPkMetricMetricIdResponse403
    | DeleteApiV1DatasetPkMetricMetricIdResponse404
    | DeleteApiV1DatasetPkMetricMetricIdResponse422
    | DeleteApiV1DatasetPkMetricMetricIdResponse500
    | None
):
    """Delete a dataset metric

    Args:
        pk (int):
        metric_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeleteApiV1DatasetPkMetricMetricIdResponse200 | DeleteApiV1DatasetPkMetricMetricIdResponse401 | DeleteApiV1DatasetPkMetricMetricIdResponse403 | DeleteApiV1DatasetPkMetricMetricIdResponse404 | DeleteApiV1DatasetPkMetricMetricIdResponse422 | DeleteApiV1DatasetPkMetricMetricIdResponse500
    """

    return (
        await asyncio_detailed(
            pk=pk,
            metric_id=metric_id,
            client=client,
        )
    ).parsed
