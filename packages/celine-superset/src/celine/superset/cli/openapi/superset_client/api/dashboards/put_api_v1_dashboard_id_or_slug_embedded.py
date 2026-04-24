from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.embedded_dashboard_config import EmbeddedDashboardConfig
from ...models.put_api_v1_dashboard_id_or_slug_embedded_response_200 import PutApiV1DashboardIdOrSlugEmbeddedResponse200
from ...models.put_api_v1_dashboard_id_or_slug_embedded_response_401 import PutApiV1DashboardIdOrSlugEmbeddedResponse401
from ...models.put_api_v1_dashboard_id_or_slug_embedded_response_500 import PutApiV1DashboardIdOrSlugEmbeddedResponse500
from ...types import Response


def _get_kwargs(
    id_or_slug: str,
    *,
    body: EmbeddedDashboardConfig,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "put",
        "url": "/api/v1/dashboard/{id_or_slug}/embedded".format(
            id_or_slug=quote(str(id_or_slug), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    PutApiV1DashboardIdOrSlugEmbeddedResponse200
    | PutApiV1DashboardIdOrSlugEmbeddedResponse401
    | PutApiV1DashboardIdOrSlugEmbeddedResponse500
    | None
):
    if response.status_code == 200:
        response_200 = PutApiV1DashboardIdOrSlugEmbeddedResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 401:
        response_401 = PutApiV1DashboardIdOrSlugEmbeddedResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 500:
        response_500 = PutApiV1DashboardIdOrSlugEmbeddedResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PutApiV1DashboardIdOrSlugEmbeddedResponse200
    | PutApiV1DashboardIdOrSlugEmbeddedResponse401
    | PutApiV1DashboardIdOrSlugEmbeddedResponse500
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
    body: EmbeddedDashboardConfig,
) -> Response[
    PutApiV1DashboardIdOrSlugEmbeddedResponse200
    | PutApiV1DashboardIdOrSlugEmbeddedResponse401
    | PutApiV1DashboardIdOrSlugEmbeddedResponse500
]:
    """Sets a dashboard's embedded configuration.

    Args:
        id_or_slug (str):
        body (EmbeddedDashboardConfig):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PutApiV1DashboardIdOrSlugEmbeddedResponse200 | PutApiV1DashboardIdOrSlugEmbeddedResponse401 | PutApiV1DashboardIdOrSlugEmbeddedResponse500]
    """

    kwargs = _get_kwargs(
        id_or_slug=id_or_slug,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    id_or_slug: str,
    *,
    client: AuthenticatedClient,
    body: EmbeddedDashboardConfig,
) -> (
    PutApiV1DashboardIdOrSlugEmbeddedResponse200
    | PutApiV1DashboardIdOrSlugEmbeddedResponse401
    | PutApiV1DashboardIdOrSlugEmbeddedResponse500
    | None
):
    """Sets a dashboard's embedded configuration.

    Args:
        id_or_slug (str):
        body (EmbeddedDashboardConfig):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PutApiV1DashboardIdOrSlugEmbeddedResponse200 | PutApiV1DashboardIdOrSlugEmbeddedResponse401 | PutApiV1DashboardIdOrSlugEmbeddedResponse500
    """

    return sync_detailed(
        id_or_slug=id_or_slug,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    id_or_slug: str,
    *,
    client: AuthenticatedClient,
    body: EmbeddedDashboardConfig,
) -> Response[
    PutApiV1DashboardIdOrSlugEmbeddedResponse200
    | PutApiV1DashboardIdOrSlugEmbeddedResponse401
    | PutApiV1DashboardIdOrSlugEmbeddedResponse500
]:
    """Sets a dashboard's embedded configuration.

    Args:
        id_or_slug (str):
        body (EmbeddedDashboardConfig):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PutApiV1DashboardIdOrSlugEmbeddedResponse200 | PutApiV1DashboardIdOrSlugEmbeddedResponse401 | PutApiV1DashboardIdOrSlugEmbeddedResponse500]
    """

    kwargs = _get_kwargs(
        id_or_slug=id_or_slug,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    id_or_slug: str,
    *,
    client: AuthenticatedClient,
    body: EmbeddedDashboardConfig,
) -> (
    PutApiV1DashboardIdOrSlugEmbeddedResponse200
    | PutApiV1DashboardIdOrSlugEmbeddedResponse401
    | PutApiV1DashboardIdOrSlugEmbeddedResponse500
    | None
):
    """Sets a dashboard's embedded configuration.

    Args:
        id_or_slug (str):
        body (EmbeddedDashboardConfig):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PutApiV1DashboardIdOrSlugEmbeddedResponse200 | PutApiV1DashboardIdOrSlugEmbeddedResponse401 | PutApiV1DashboardIdOrSlugEmbeddedResponse500
    """

    return (
        await asyncio_detailed(
            id_or_slug=id_or_slug,
            client=client,
            body=body,
        )
    ).parsed
