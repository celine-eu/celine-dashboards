from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_chart_id_or_uuid_response_200 import GetApiV1ChartIdOrUuidResponse200
from ...models.get_api_v1_chart_id_or_uuid_response_400 import GetApiV1ChartIdOrUuidResponse400
from ...models.get_api_v1_chart_id_or_uuid_response_401 import GetApiV1ChartIdOrUuidResponse401
from ...models.get_api_v1_chart_id_or_uuid_response_404 import GetApiV1ChartIdOrUuidResponse404
from ...types import Response


def _get_kwargs(
    id_or_uuid: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/chart/{id_or_uuid}".format(
            id_or_uuid=quote(str(id_or_uuid), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    Any
    | GetApiV1ChartIdOrUuidResponse200
    | GetApiV1ChartIdOrUuidResponse400
    | GetApiV1ChartIdOrUuidResponse401
    | GetApiV1ChartIdOrUuidResponse404
    | None
):
    if response.status_code == 200:
        response_200 = GetApiV1ChartIdOrUuidResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 302:
        response_302 = cast(Any, None)
        return response_302

    if response.status_code == 400:
        response_400 = GetApiV1ChartIdOrUuidResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = GetApiV1ChartIdOrUuidResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = GetApiV1ChartIdOrUuidResponse404.from_dict(response.json())

        return response_404

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    Any
    | GetApiV1ChartIdOrUuidResponse200
    | GetApiV1ChartIdOrUuidResponse400
    | GetApiV1ChartIdOrUuidResponse401
    | GetApiV1ChartIdOrUuidResponse404
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    id_or_uuid: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    Any
    | GetApiV1ChartIdOrUuidResponse200
    | GetApiV1ChartIdOrUuidResponse400
    | GetApiV1ChartIdOrUuidResponse401
    | GetApiV1ChartIdOrUuidResponse404
]:
    """Get a chart detail information

     Get a chart

    Args:
        id_or_uuid (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | GetApiV1ChartIdOrUuidResponse200 | GetApiV1ChartIdOrUuidResponse400 | GetApiV1ChartIdOrUuidResponse401 | GetApiV1ChartIdOrUuidResponse404]
    """

    kwargs = _get_kwargs(
        id_or_uuid=id_or_uuid,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    id_or_uuid: str,
    *,
    client: AuthenticatedClient,
) -> (
    Any
    | GetApiV1ChartIdOrUuidResponse200
    | GetApiV1ChartIdOrUuidResponse400
    | GetApiV1ChartIdOrUuidResponse401
    | GetApiV1ChartIdOrUuidResponse404
    | None
):
    """Get a chart detail information

     Get a chart

    Args:
        id_or_uuid (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | GetApiV1ChartIdOrUuidResponse200 | GetApiV1ChartIdOrUuidResponse400 | GetApiV1ChartIdOrUuidResponse401 | GetApiV1ChartIdOrUuidResponse404
    """

    return sync_detailed(
        id_or_uuid=id_or_uuid,
        client=client,
    ).parsed


async def asyncio_detailed(
    id_or_uuid: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    Any
    | GetApiV1ChartIdOrUuidResponse200
    | GetApiV1ChartIdOrUuidResponse400
    | GetApiV1ChartIdOrUuidResponse401
    | GetApiV1ChartIdOrUuidResponse404
]:
    """Get a chart detail information

     Get a chart

    Args:
        id_or_uuid (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | GetApiV1ChartIdOrUuidResponse200 | GetApiV1ChartIdOrUuidResponse400 | GetApiV1ChartIdOrUuidResponse401 | GetApiV1ChartIdOrUuidResponse404]
    """

    kwargs = _get_kwargs(
        id_or_uuid=id_or_uuid,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    id_or_uuid: str,
    *,
    client: AuthenticatedClient,
) -> (
    Any
    | GetApiV1ChartIdOrUuidResponse200
    | GetApiV1ChartIdOrUuidResponse400
    | GetApiV1ChartIdOrUuidResponse401
    | GetApiV1ChartIdOrUuidResponse404
    | None
):
    """Get a chart detail information

     Get a chart

    Args:
        id_or_uuid (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | GetApiV1ChartIdOrUuidResponse200 | GetApiV1ChartIdOrUuidResponse400 | GetApiV1ChartIdOrUuidResponse401 | GetApiV1ChartIdOrUuidResponse404
    """

    return (
        await asyncio_detailed(
            id_or_uuid=id_or_uuid,
            client=client,
        )
    ).parsed
