from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_assets_export_response_401 import GetApiV1AssetsExportResponse401
from ...models.get_api_v1_assets_export_response_404 import GetApiV1AssetsExportResponse404
from ...models.get_api_v1_assets_export_response_500 import GetApiV1AssetsExportResponse500
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/assets/export/",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GetApiV1AssetsExportResponse401 | GetApiV1AssetsExportResponse404 | GetApiV1AssetsExportResponse500 | None:
    if response.status_code == 401:
        response_401 = GetApiV1AssetsExportResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = GetApiV1AssetsExportResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 500:
        response_500 = GetApiV1AssetsExportResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[GetApiV1AssetsExportResponse401 | GetApiV1AssetsExportResponse404 | GetApiV1AssetsExportResponse500]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[GetApiV1AssetsExportResponse401 | GetApiV1AssetsExportResponse404 | GetApiV1AssetsExportResponse500]:
    """Export all assets

     Gets a ZIP file with all the Superset assets (databases, datasets, charts, dashboards, saved
    queries) as YAML files.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1AssetsExportResponse401 | GetApiV1AssetsExportResponse404 | GetApiV1AssetsExportResponse500]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> GetApiV1AssetsExportResponse401 | GetApiV1AssetsExportResponse404 | GetApiV1AssetsExportResponse500 | None:
    """Export all assets

     Gets a ZIP file with all the Superset assets (databases, datasets, charts, dashboards, saved
    queries) as YAML files.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1AssetsExportResponse401 | GetApiV1AssetsExportResponse404 | GetApiV1AssetsExportResponse500
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[GetApiV1AssetsExportResponse401 | GetApiV1AssetsExportResponse404 | GetApiV1AssetsExportResponse500]:
    """Export all assets

     Gets a ZIP file with all the Superset assets (databases, datasets, charts, dashboards, saved
    queries) as YAML files.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1AssetsExportResponse401 | GetApiV1AssetsExportResponse404 | GetApiV1AssetsExportResponse500]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> GetApiV1AssetsExportResponse401 | GetApiV1AssetsExportResponse404 | GetApiV1AssetsExportResponse500 | None:
    """Export all assets

     Gets a ZIP file with all the Superset assets (databases, datasets, charts, dashboards, saved
    queries) as YAML files.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1AssetsExportResponse401 | GetApiV1AssetsExportResponse404 | GetApiV1AssetsExportResponse500
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
