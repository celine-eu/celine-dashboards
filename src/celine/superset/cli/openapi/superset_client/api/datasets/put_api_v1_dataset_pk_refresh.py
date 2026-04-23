from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.put_api_v1_dataset_pk_refresh_response_200 import PutApiV1DatasetPkRefreshResponse200
from ...models.put_api_v1_dataset_pk_refresh_response_401 import PutApiV1DatasetPkRefreshResponse401
from ...models.put_api_v1_dataset_pk_refresh_response_403 import PutApiV1DatasetPkRefreshResponse403
from ...models.put_api_v1_dataset_pk_refresh_response_404 import PutApiV1DatasetPkRefreshResponse404
from ...models.put_api_v1_dataset_pk_refresh_response_422 import PutApiV1DatasetPkRefreshResponse422
from ...models.put_api_v1_dataset_pk_refresh_response_500 import PutApiV1DatasetPkRefreshResponse500
from ...types import Response


def _get_kwargs(
    pk: int,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "put",
        "url": "/api/v1/dataset/{pk}/refresh".format(
            pk=quote(str(pk), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    PutApiV1DatasetPkRefreshResponse200
    | PutApiV1DatasetPkRefreshResponse401
    | PutApiV1DatasetPkRefreshResponse403
    | PutApiV1DatasetPkRefreshResponse404
    | PutApiV1DatasetPkRefreshResponse422
    | PutApiV1DatasetPkRefreshResponse500
    | None
):
    if response.status_code == 200:
        response_200 = PutApiV1DatasetPkRefreshResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 401:
        response_401 = PutApiV1DatasetPkRefreshResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 403:
        response_403 = PutApiV1DatasetPkRefreshResponse403.from_dict(response.json())

        return response_403

    if response.status_code == 404:
        response_404 = PutApiV1DatasetPkRefreshResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 422:
        response_422 = PutApiV1DatasetPkRefreshResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = PutApiV1DatasetPkRefreshResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PutApiV1DatasetPkRefreshResponse200
    | PutApiV1DatasetPkRefreshResponse401
    | PutApiV1DatasetPkRefreshResponse403
    | PutApiV1DatasetPkRefreshResponse404
    | PutApiV1DatasetPkRefreshResponse422
    | PutApiV1DatasetPkRefreshResponse500
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
    PutApiV1DatasetPkRefreshResponse200
    | PutApiV1DatasetPkRefreshResponse401
    | PutApiV1DatasetPkRefreshResponse403
    | PutApiV1DatasetPkRefreshResponse404
    | PutApiV1DatasetPkRefreshResponse422
    | PutApiV1DatasetPkRefreshResponse500
]:
    """Refresh and update columns of a dataset

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PutApiV1DatasetPkRefreshResponse200 | PutApiV1DatasetPkRefreshResponse401 | PutApiV1DatasetPkRefreshResponse403 | PutApiV1DatasetPkRefreshResponse404 | PutApiV1DatasetPkRefreshResponse422 | PutApiV1DatasetPkRefreshResponse500]
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
    PutApiV1DatasetPkRefreshResponse200
    | PutApiV1DatasetPkRefreshResponse401
    | PutApiV1DatasetPkRefreshResponse403
    | PutApiV1DatasetPkRefreshResponse404
    | PutApiV1DatasetPkRefreshResponse422
    | PutApiV1DatasetPkRefreshResponse500
    | None
):
    """Refresh and update columns of a dataset

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PutApiV1DatasetPkRefreshResponse200 | PutApiV1DatasetPkRefreshResponse401 | PutApiV1DatasetPkRefreshResponse403 | PutApiV1DatasetPkRefreshResponse404 | PutApiV1DatasetPkRefreshResponse422 | PutApiV1DatasetPkRefreshResponse500
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
    PutApiV1DatasetPkRefreshResponse200
    | PutApiV1DatasetPkRefreshResponse401
    | PutApiV1DatasetPkRefreshResponse403
    | PutApiV1DatasetPkRefreshResponse404
    | PutApiV1DatasetPkRefreshResponse422
    | PutApiV1DatasetPkRefreshResponse500
]:
    """Refresh and update columns of a dataset

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PutApiV1DatasetPkRefreshResponse200 | PutApiV1DatasetPkRefreshResponse401 | PutApiV1DatasetPkRefreshResponse403 | PutApiV1DatasetPkRefreshResponse404 | PutApiV1DatasetPkRefreshResponse422 | PutApiV1DatasetPkRefreshResponse500]
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
    PutApiV1DatasetPkRefreshResponse200
    | PutApiV1DatasetPkRefreshResponse401
    | PutApiV1DatasetPkRefreshResponse403
    | PutApiV1DatasetPkRefreshResponse404
    | PutApiV1DatasetPkRefreshResponse422
    | PutApiV1DatasetPkRefreshResponse500
    | None
):
    """Refresh and update columns of a dataset

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PutApiV1DatasetPkRefreshResponse200 | PutApiV1DatasetPkRefreshResponse401 | PutApiV1DatasetPkRefreshResponse403 | PutApiV1DatasetPkRefreshResponse404 | PutApiV1DatasetPkRefreshResponse422 | PutApiV1DatasetPkRefreshResponse500
    """

    return (
        await asyncio_detailed(
            pk=pk,
            client=client,
        )
    ).parsed
