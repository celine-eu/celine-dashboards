from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_dashboard_id_or_slug_tabs_response_200 import GetApiV1DashboardIdOrSlugTabsResponse200
from ...models.get_api_v1_dashboard_id_or_slug_tabs_response_400 import GetApiV1DashboardIdOrSlugTabsResponse400
from ...models.get_api_v1_dashboard_id_or_slug_tabs_response_401 import GetApiV1DashboardIdOrSlugTabsResponse401
from ...models.get_api_v1_dashboard_id_or_slug_tabs_response_403 import GetApiV1DashboardIdOrSlugTabsResponse403
from ...models.get_api_v1_dashboard_id_or_slug_tabs_response_404 import GetApiV1DashboardIdOrSlugTabsResponse404
from ...types import Response


def _get_kwargs(
    id_or_slug: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/dashboard/{id_or_slug}/tabs".format(
            id_or_slug=quote(str(id_or_slug), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetApiV1DashboardIdOrSlugTabsResponse200
    | GetApiV1DashboardIdOrSlugTabsResponse400
    | GetApiV1DashboardIdOrSlugTabsResponse401
    | GetApiV1DashboardIdOrSlugTabsResponse403
    | GetApiV1DashboardIdOrSlugTabsResponse404
    | None
):
    if response.status_code == 200:
        response_200 = GetApiV1DashboardIdOrSlugTabsResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = GetApiV1DashboardIdOrSlugTabsResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = GetApiV1DashboardIdOrSlugTabsResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 403:
        response_403 = GetApiV1DashboardIdOrSlugTabsResponse403.from_dict(response.json())

        return response_403

    if response.status_code == 404:
        response_404 = GetApiV1DashboardIdOrSlugTabsResponse404.from_dict(response.json())

        return response_404

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    GetApiV1DashboardIdOrSlugTabsResponse200
    | GetApiV1DashboardIdOrSlugTabsResponse400
    | GetApiV1DashboardIdOrSlugTabsResponse401
    | GetApiV1DashboardIdOrSlugTabsResponse403
    | GetApiV1DashboardIdOrSlugTabsResponse404
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    id_or_slug: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetApiV1DashboardIdOrSlugTabsResponse200
    | GetApiV1DashboardIdOrSlugTabsResponse400
    | GetApiV1DashboardIdOrSlugTabsResponse401
    | GetApiV1DashboardIdOrSlugTabsResponse403
    | GetApiV1DashboardIdOrSlugTabsResponse404
]:
    """Get dashboard's tabs

     Returns a list of a dashboard's tabs and dashboard's nested tree structure for associated tabs.

    Args:
        id_or_slug (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1DashboardIdOrSlugTabsResponse200 | GetApiV1DashboardIdOrSlugTabsResponse400 | GetApiV1DashboardIdOrSlugTabsResponse401 | GetApiV1DashboardIdOrSlugTabsResponse403 | GetApiV1DashboardIdOrSlugTabsResponse404]
    """

    kwargs = _get_kwargs(
        id_or_slug=id_or_slug,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    id_or_slug: str,
    *,
    client: AuthenticatedClient,
) -> (
    GetApiV1DashboardIdOrSlugTabsResponse200
    | GetApiV1DashboardIdOrSlugTabsResponse400
    | GetApiV1DashboardIdOrSlugTabsResponse401
    | GetApiV1DashboardIdOrSlugTabsResponse403
    | GetApiV1DashboardIdOrSlugTabsResponse404
    | None
):
    """Get dashboard's tabs

     Returns a list of a dashboard's tabs and dashboard's nested tree structure for associated tabs.

    Args:
        id_or_slug (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1DashboardIdOrSlugTabsResponse200 | GetApiV1DashboardIdOrSlugTabsResponse400 | GetApiV1DashboardIdOrSlugTabsResponse401 | GetApiV1DashboardIdOrSlugTabsResponse403 | GetApiV1DashboardIdOrSlugTabsResponse404
    """

    return sync_detailed(
        id_or_slug=id_or_slug,
        client=client,
    ).parsed


async def asyncio_detailed(
    id_or_slug: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetApiV1DashboardIdOrSlugTabsResponse200
    | GetApiV1DashboardIdOrSlugTabsResponse400
    | GetApiV1DashboardIdOrSlugTabsResponse401
    | GetApiV1DashboardIdOrSlugTabsResponse403
    | GetApiV1DashboardIdOrSlugTabsResponse404
]:
    """Get dashboard's tabs

     Returns a list of a dashboard's tabs and dashboard's nested tree structure for associated tabs.

    Args:
        id_or_slug (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1DashboardIdOrSlugTabsResponse200 | GetApiV1DashboardIdOrSlugTabsResponse400 | GetApiV1DashboardIdOrSlugTabsResponse401 | GetApiV1DashboardIdOrSlugTabsResponse403 | GetApiV1DashboardIdOrSlugTabsResponse404]
    """

    kwargs = _get_kwargs(
        id_or_slug=id_or_slug,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    id_or_slug: str,
    *,
    client: AuthenticatedClient,
) -> (
    GetApiV1DashboardIdOrSlugTabsResponse200
    | GetApiV1DashboardIdOrSlugTabsResponse400
    | GetApiV1DashboardIdOrSlugTabsResponse401
    | GetApiV1DashboardIdOrSlugTabsResponse403
    | GetApiV1DashboardIdOrSlugTabsResponse404
    | None
):
    """Get dashboard's tabs

     Returns a list of a dashboard's tabs and dashboard's nested tree structure for associated tabs.

    Args:
        id_or_slug (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1DashboardIdOrSlugTabsResponse200 | GetApiV1DashboardIdOrSlugTabsResponse400 | GetApiV1DashboardIdOrSlugTabsResponse401 | GetApiV1DashboardIdOrSlugTabsResponse403 | GetApiV1DashboardIdOrSlugTabsResponse404
    """

    return (
        await asyncio_detailed(
            id_or_slug=id_or_slug,
            client=client,
        )
    ).parsed
