from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_dashboard_id_or_slug_embedded_response_200 import GetApiV1DashboardIdOrSlugEmbeddedResponse200
from ...models.get_api_v1_dashboard_id_or_slug_embedded_response_401 import GetApiV1DashboardIdOrSlugEmbeddedResponse401
from ...models.get_api_v1_dashboard_id_or_slug_embedded_response_500 import GetApiV1DashboardIdOrSlugEmbeddedResponse500
from ...types import Response


def _get_kwargs(
    id_or_slug: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/dashboard/{id_or_slug}/embedded".format(
            id_or_slug=quote(str(id_or_slug), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetApiV1DashboardIdOrSlugEmbeddedResponse200
    | GetApiV1DashboardIdOrSlugEmbeddedResponse401
    | GetApiV1DashboardIdOrSlugEmbeddedResponse500
    | None
):
    if response.status_code == 200:
        response_200 = GetApiV1DashboardIdOrSlugEmbeddedResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 401:
        response_401 = GetApiV1DashboardIdOrSlugEmbeddedResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 500:
        response_500 = GetApiV1DashboardIdOrSlugEmbeddedResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    GetApiV1DashboardIdOrSlugEmbeddedResponse200
    | GetApiV1DashboardIdOrSlugEmbeddedResponse401
    | GetApiV1DashboardIdOrSlugEmbeddedResponse500
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
    GetApiV1DashboardIdOrSlugEmbeddedResponse200
    | GetApiV1DashboardIdOrSlugEmbeddedResponse401
    | GetApiV1DashboardIdOrSlugEmbeddedResponse500
]:
    """Get the dashboard's embedded configuration

    Args:
        id_or_slug (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1DashboardIdOrSlugEmbeddedResponse200 | GetApiV1DashboardIdOrSlugEmbeddedResponse401 | GetApiV1DashboardIdOrSlugEmbeddedResponse500]
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
    GetApiV1DashboardIdOrSlugEmbeddedResponse200
    | GetApiV1DashboardIdOrSlugEmbeddedResponse401
    | GetApiV1DashboardIdOrSlugEmbeddedResponse500
    | None
):
    """Get the dashboard's embedded configuration

    Args:
        id_or_slug (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1DashboardIdOrSlugEmbeddedResponse200 | GetApiV1DashboardIdOrSlugEmbeddedResponse401 | GetApiV1DashboardIdOrSlugEmbeddedResponse500
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
    GetApiV1DashboardIdOrSlugEmbeddedResponse200
    | GetApiV1DashboardIdOrSlugEmbeddedResponse401
    | GetApiV1DashboardIdOrSlugEmbeddedResponse500
]:
    """Get the dashboard's embedded configuration

    Args:
        id_or_slug (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1DashboardIdOrSlugEmbeddedResponse200 | GetApiV1DashboardIdOrSlugEmbeddedResponse401 | GetApiV1DashboardIdOrSlugEmbeddedResponse500]
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
    GetApiV1DashboardIdOrSlugEmbeddedResponse200
    | GetApiV1DashboardIdOrSlugEmbeddedResponse401
    | GetApiV1DashboardIdOrSlugEmbeddedResponse500
    | None
):
    """Get the dashboard's embedded configuration

    Args:
        id_or_slug (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1DashboardIdOrSlugEmbeddedResponse200 | GetApiV1DashboardIdOrSlugEmbeddedResponse401 | GetApiV1DashboardIdOrSlugEmbeddedResponse500
    """

    return (
        await asyncio_detailed(
            id_or_slug=id_or_slug,
            client=client,
        )
    ).parsed
