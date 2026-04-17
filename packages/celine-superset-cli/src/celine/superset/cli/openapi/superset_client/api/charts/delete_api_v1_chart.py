from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.delete_api_v1_chart_response_200 import DeleteApiV1ChartResponse200
from ...models.delete_api_v1_chart_response_401 import DeleteApiV1ChartResponse401
from ...models.delete_api_v1_chart_response_403 import DeleteApiV1ChartResponse403
from ...models.delete_api_v1_chart_response_404 import DeleteApiV1ChartResponse404
from ...models.delete_api_v1_chart_response_422 import DeleteApiV1ChartResponse422
from ...models.delete_api_v1_chart_response_500 import DeleteApiV1ChartResponse500
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "delete",
        "url": "/api/v1/chart/",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    DeleteApiV1ChartResponse200
    | DeleteApiV1ChartResponse401
    | DeleteApiV1ChartResponse403
    | DeleteApiV1ChartResponse404
    | DeleteApiV1ChartResponse422
    | DeleteApiV1ChartResponse500
    | None
):
    if response.status_code == 200:
        response_200 = DeleteApiV1ChartResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 401:
        response_401 = DeleteApiV1ChartResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 403:
        response_403 = DeleteApiV1ChartResponse403.from_dict(response.json())

        return response_403

    if response.status_code == 404:
        response_404 = DeleteApiV1ChartResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 422:
        response_422 = DeleteApiV1ChartResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = DeleteApiV1ChartResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    DeleteApiV1ChartResponse200
    | DeleteApiV1ChartResponse401
    | DeleteApiV1ChartResponse403
    | DeleteApiV1ChartResponse404
    | DeleteApiV1ChartResponse422
    | DeleteApiV1ChartResponse500
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
) -> Response[
    DeleteApiV1ChartResponse200
    | DeleteApiV1ChartResponse401
    | DeleteApiV1ChartResponse403
    | DeleteApiV1ChartResponse404
    | DeleteApiV1ChartResponse422
    | DeleteApiV1ChartResponse500
]:
    """Bulk delete charts

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeleteApiV1ChartResponse200 | DeleteApiV1ChartResponse401 | DeleteApiV1ChartResponse403 | DeleteApiV1ChartResponse404 | DeleteApiV1ChartResponse422 | DeleteApiV1ChartResponse500]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> (
    DeleteApiV1ChartResponse200
    | DeleteApiV1ChartResponse401
    | DeleteApiV1ChartResponse403
    | DeleteApiV1ChartResponse404
    | DeleteApiV1ChartResponse422
    | DeleteApiV1ChartResponse500
    | None
):
    """Bulk delete charts

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeleteApiV1ChartResponse200 | DeleteApiV1ChartResponse401 | DeleteApiV1ChartResponse403 | DeleteApiV1ChartResponse404 | DeleteApiV1ChartResponse422 | DeleteApiV1ChartResponse500
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[
    DeleteApiV1ChartResponse200
    | DeleteApiV1ChartResponse401
    | DeleteApiV1ChartResponse403
    | DeleteApiV1ChartResponse404
    | DeleteApiV1ChartResponse422
    | DeleteApiV1ChartResponse500
]:
    """Bulk delete charts

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeleteApiV1ChartResponse200 | DeleteApiV1ChartResponse401 | DeleteApiV1ChartResponse403 | DeleteApiV1ChartResponse404 | DeleteApiV1ChartResponse422 | DeleteApiV1ChartResponse500]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> (
    DeleteApiV1ChartResponse200
    | DeleteApiV1ChartResponse401
    | DeleteApiV1ChartResponse403
    | DeleteApiV1ChartResponse404
    | DeleteApiV1ChartResponse422
    | DeleteApiV1ChartResponse500
    | None
):
    """Bulk delete charts

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeleteApiV1ChartResponse200 | DeleteApiV1ChartResponse401 | DeleteApiV1ChartResponse403 | DeleteApiV1ChartResponse404 | DeleteApiV1ChartResponse422 | DeleteApiV1ChartResponse500
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
