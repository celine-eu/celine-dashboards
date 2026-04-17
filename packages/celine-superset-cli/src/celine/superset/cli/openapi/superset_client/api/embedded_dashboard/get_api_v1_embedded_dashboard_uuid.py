from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_embedded_dashboard_uuid_response_200 import GetApiV1EmbeddedDashboardUuidResponse200
from ...models.get_api_v1_embedded_dashboard_uuid_response_401 import GetApiV1EmbeddedDashboardUuidResponse401
from ...models.get_api_v1_embedded_dashboard_uuid_response_404 import GetApiV1EmbeddedDashboardUuidResponse404
from ...models.get_api_v1_embedded_dashboard_uuid_response_500 import GetApiV1EmbeddedDashboardUuidResponse500
from ...types import UNSET, Response, Unset


def _get_kwargs(
    uuid: str,
    *,
    ui_config: float | Unset = UNSET,
    show_filters: bool | Unset = UNSET,
    expand_filters: bool | Unset = UNSET,
    native_filters_key: str | Unset = UNSET,
    permalink_key: str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["uiConfig"] = ui_config

    params["show_filters"] = show_filters

    params["expand_filters"] = expand_filters

    params["native_filters_key"] = native_filters_key

    params["permalink_key"] = permalink_key

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/embedded_dashboard/{uuid}".format(
            uuid=quote(str(uuid), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetApiV1EmbeddedDashboardUuidResponse200
    | GetApiV1EmbeddedDashboardUuidResponse401
    | GetApiV1EmbeddedDashboardUuidResponse404
    | GetApiV1EmbeddedDashboardUuidResponse500
    | None
):
    if response.status_code == 200:
        response_200 = GetApiV1EmbeddedDashboardUuidResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 401:
        response_401 = GetApiV1EmbeddedDashboardUuidResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = GetApiV1EmbeddedDashboardUuidResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 500:
        response_500 = GetApiV1EmbeddedDashboardUuidResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    GetApiV1EmbeddedDashboardUuidResponse200
    | GetApiV1EmbeddedDashboardUuidResponse401
    | GetApiV1EmbeddedDashboardUuidResponse404
    | GetApiV1EmbeddedDashboardUuidResponse500
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    uuid: str,
    *,
    client: AuthenticatedClient,
    ui_config: float | Unset = UNSET,
    show_filters: bool | Unset = UNSET,
    expand_filters: bool | Unset = UNSET,
    native_filters_key: str | Unset = UNSET,
    permalink_key: str | Unset = UNSET,
) -> Response[
    GetApiV1EmbeddedDashboardUuidResponse200
    | GetApiV1EmbeddedDashboardUuidResponse401
    | GetApiV1EmbeddedDashboardUuidResponse404
    | GetApiV1EmbeddedDashboardUuidResponse500
]:
    """Get a report schedule log

    Args:
        uuid (str):
        ui_config (float | Unset):
        show_filters (bool | Unset):
        expand_filters (bool | Unset):
        native_filters_key (str | Unset):
        permalink_key (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1EmbeddedDashboardUuidResponse200 | GetApiV1EmbeddedDashboardUuidResponse401 | GetApiV1EmbeddedDashboardUuidResponse404 | GetApiV1EmbeddedDashboardUuidResponse500]
    """

    kwargs = _get_kwargs(
        uuid=uuid,
        ui_config=ui_config,
        show_filters=show_filters,
        expand_filters=expand_filters,
        native_filters_key=native_filters_key,
        permalink_key=permalink_key,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    uuid: str,
    *,
    client: AuthenticatedClient,
    ui_config: float | Unset = UNSET,
    show_filters: bool | Unset = UNSET,
    expand_filters: bool | Unset = UNSET,
    native_filters_key: str | Unset = UNSET,
    permalink_key: str | Unset = UNSET,
) -> (
    GetApiV1EmbeddedDashboardUuidResponse200
    | GetApiV1EmbeddedDashboardUuidResponse401
    | GetApiV1EmbeddedDashboardUuidResponse404
    | GetApiV1EmbeddedDashboardUuidResponse500
    | None
):
    """Get a report schedule log

    Args:
        uuid (str):
        ui_config (float | Unset):
        show_filters (bool | Unset):
        expand_filters (bool | Unset):
        native_filters_key (str | Unset):
        permalink_key (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1EmbeddedDashboardUuidResponse200 | GetApiV1EmbeddedDashboardUuidResponse401 | GetApiV1EmbeddedDashboardUuidResponse404 | GetApiV1EmbeddedDashboardUuidResponse500
    """

    return sync_detailed(
        uuid=uuid,
        client=client,
        ui_config=ui_config,
        show_filters=show_filters,
        expand_filters=expand_filters,
        native_filters_key=native_filters_key,
        permalink_key=permalink_key,
    ).parsed


async def asyncio_detailed(
    uuid: str,
    *,
    client: AuthenticatedClient,
    ui_config: float | Unset = UNSET,
    show_filters: bool | Unset = UNSET,
    expand_filters: bool | Unset = UNSET,
    native_filters_key: str | Unset = UNSET,
    permalink_key: str | Unset = UNSET,
) -> Response[
    GetApiV1EmbeddedDashboardUuidResponse200
    | GetApiV1EmbeddedDashboardUuidResponse401
    | GetApiV1EmbeddedDashboardUuidResponse404
    | GetApiV1EmbeddedDashboardUuidResponse500
]:
    """Get a report schedule log

    Args:
        uuid (str):
        ui_config (float | Unset):
        show_filters (bool | Unset):
        expand_filters (bool | Unset):
        native_filters_key (str | Unset):
        permalink_key (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1EmbeddedDashboardUuidResponse200 | GetApiV1EmbeddedDashboardUuidResponse401 | GetApiV1EmbeddedDashboardUuidResponse404 | GetApiV1EmbeddedDashboardUuidResponse500]
    """

    kwargs = _get_kwargs(
        uuid=uuid,
        ui_config=ui_config,
        show_filters=show_filters,
        expand_filters=expand_filters,
        native_filters_key=native_filters_key,
        permalink_key=permalink_key,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    uuid: str,
    *,
    client: AuthenticatedClient,
    ui_config: float | Unset = UNSET,
    show_filters: bool | Unset = UNSET,
    expand_filters: bool | Unset = UNSET,
    native_filters_key: str | Unset = UNSET,
    permalink_key: str | Unset = UNSET,
) -> (
    GetApiV1EmbeddedDashboardUuidResponse200
    | GetApiV1EmbeddedDashboardUuidResponse401
    | GetApiV1EmbeddedDashboardUuidResponse404
    | GetApiV1EmbeddedDashboardUuidResponse500
    | None
):
    """Get a report schedule log

    Args:
        uuid (str):
        ui_config (float | Unset):
        show_filters (bool | Unset):
        expand_filters (bool | Unset):
        native_filters_key (str | Unset):
        permalink_key (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1EmbeddedDashboardUuidResponse200 | GetApiV1EmbeddedDashboardUuidResponse401 | GetApiV1EmbeddedDashboardUuidResponse404 | GetApiV1EmbeddedDashboardUuidResponse500
    """

    return (
        await asyncio_detailed(
            uuid=uuid,
            client=client,
            ui_config=ui_config,
            show_filters=show_filters,
            expand_filters=expand_filters,
            native_filters_key=native_filters_key,
            permalink_key=permalink_key,
        )
    ).parsed
