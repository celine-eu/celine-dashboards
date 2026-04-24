from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.delete_api_v1_chart_pk_response_200 import DeleteApiV1ChartPkResponse200
from ...models.delete_api_v1_chart_pk_response_401 import DeleteApiV1ChartPkResponse401
from ...models.delete_api_v1_chart_pk_response_403 import DeleteApiV1ChartPkResponse403
from ...models.delete_api_v1_chart_pk_response_404 import DeleteApiV1ChartPkResponse404
from ...models.delete_api_v1_chart_pk_response_422 import DeleteApiV1ChartPkResponse422
from ...models.delete_api_v1_chart_pk_response_500 import DeleteApiV1ChartPkResponse500
from ...types import Response


def _get_kwargs(
    pk: int,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "delete",
        "url": "/api/v1/chart/{pk}".format(
            pk=quote(str(pk), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    DeleteApiV1ChartPkResponse200
    | DeleteApiV1ChartPkResponse401
    | DeleteApiV1ChartPkResponse403
    | DeleteApiV1ChartPkResponse404
    | DeleteApiV1ChartPkResponse422
    | DeleteApiV1ChartPkResponse500
    | None
):
    if response.status_code == 200:
        response_200 = DeleteApiV1ChartPkResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 401:
        response_401 = DeleteApiV1ChartPkResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 403:
        response_403 = DeleteApiV1ChartPkResponse403.from_dict(response.json())

        return response_403

    if response.status_code == 404:
        response_404 = DeleteApiV1ChartPkResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 422:
        response_422 = DeleteApiV1ChartPkResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = DeleteApiV1ChartPkResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    DeleteApiV1ChartPkResponse200
    | DeleteApiV1ChartPkResponse401
    | DeleteApiV1ChartPkResponse403
    | DeleteApiV1ChartPkResponse404
    | DeleteApiV1ChartPkResponse422
    | DeleteApiV1ChartPkResponse500
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
    DeleteApiV1ChartPkResponse200
    | DeleteApiV1ChartPkResponse401
    | DeleteApiV1ChartPkResponse403
    | DeleteApiV1ChartPkResponse404
    | DeleteApiV1ChartPkResponse422
    | DeleteApiV1ChartPkResponse500
]:
    """Delete a chart

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeleteApiV1ChartPkResponse200 | DeleteApiV1ChartPkResponse401 | DeleteApiV1ChartPkResponse403 | DeleteApiV1ChartPkResponse404 | DeleteApiV1ChartPkResponse422 | DeleteApiV1ChartPkResponse500]
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
    DeleteApiV1ChartPkResponse200
    | DeleteApiV1ChartPkResponse401
    | DeleteApiV1ChartPkResponse403
    | DeleteApiV1ChartPkResponse404
    | DeleteApiV1ChartPkResponse422
    | DeleteApiV1ChartPkResponse500
    | None
):
    """Delete a chart

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeleteApiV1ChartPkResponse200 | DeleteApiV1ChartPkResponse401 | DeleteApiV1ChartPkResponse403 | DeleteApiV1ChartPkResponse404 | DeleteApiV1ChartPkResponse422 | DeleteApiV1ChartPkResponse500
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
    DeleteApiV1ChartPkResponse200
    | DeleteApiV1ChartPkResponse401
    | DeleteApiV1ChartPkResponse403
    | DeleteApiV1ChartPkResponse404
    | DeleteApiV1ChartPkResponse422
    | DeleteApiV1ChartPkResponse500
]:
    """Delete a chart

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeleteApiV1ChartPkResponse200 | DeleteApiV1ChartPkResponse401 | DeleteApiV1ChartPkResponse403 | DeleteApiV1ChartPkResponse404 | DeleteApiV1ChartPkResponse422 | DeleteApiV1ChartPkResponse500]
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
    DeleteApiV1ChartPkResponse200
    | DeleteApiV1ChartPkResponse401
    | DeleteApiV1ChartPkResponse403
    | DeleteApiV1ChartPkResponse404
    | DeleteApiV1ChartPkResponse422
    | DeleteApiV1ChartPkResponse500
    | None
):
    """Delete a chart

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeleteApiV1ChartPkResponse200 | DeleteApiV1ChartPkResponse401 | DeleteApiV1ChartPkResponse403 | DeleteApiV1ChartPkResponse404 | DeleteApiV1ChartPkResponse422 | DeleteApiV1ChartPkResponse500
    """

    return (
        await asyncio_detailed(
            pk=pk,
            client=client,
        )
    ).parsed
