from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_sqllab_export_client_id_response_400 import GetApiV1SqllabExportClientIdResponse400
from ...models.get_api_v1_sqllab_export_client_id_response_401 import GetApiV1SqllabExportClientIdResponse401
from ...models.get_api_v1_sqllab_export_client_id_response_403 import GetApiV1SqllabExportClientIdResponse403
from ...models.get_api_v1_sqllab_export_client_id_response_404 import GetApiV1SqllabExportClientIdResponse404
from ...models.get_api_v1_sqllab_export_client_id_response_500 import GetApiV1SqllabExportClientIdResponse500
from ...types import Response


def _get_kwargs(
    client_id: int,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/sqllab/export/{client_id}/".format(
            client_id=quote(str(client_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetApiV1SqllabExportClientIdResponse400
    | GetApiV1SqllabExportClientIdResponse401
    | GetApiV1SqllabExportClientIdResponse403
    | GetApiV1SqllabExportClientIdResponse404
    | GetApiV1SqllabExportClientIdResponse500
    | str
    | None
):
    if response.status_code == 200:
        response_200 = response.text
        return response_200

    if response.status_code == 400:
        response_400 = GetApiV1SqllabExportClientIdResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = GetApiV1SqllabExportClientIdResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 403:
        response_403 = GetApiV1SqllabExportClientIdResponse403.from_dict(response.json())

        return response_403

    if response.status_code == 404:
        response_404 = GetApiV1SqllabExportClientIdResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 500:
        response_500 = GetApiV1SqllabExportClientIdResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    GetApiV1SqllabExportClientIdResponse400
    | GetApiV1SqllabExportClientIdResponse401
    | GetApiV1SqllabExportClientIdResponse403
    | GetApiV1SqllabExportClientIdResponse404
    | GetApiV1SqllabExportClientIdResponse500
    | str
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    client_id: int,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetApiV1SqllabExportClientIdResponse400
    | GetApiV1SqllabExportClientIdResponse401
    | GetApiV1SqllabExportClientIdResponse403
    | GetApiV1SqllabExportClientIdResponse404
    | GetApiV1SqllabExportClientIdResponse500
    | str
]:
    """Export the SQL query results to a CSV

    Args:
        client_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1SqllabExportClientIdResponse400 | GetApiV1SqllabExportClientIdResponse401 | GetApiV1SqllabExportClientIdResponse403 | GetApiV1SqllabExportClientIdResponse404 | GetApiV1SqllabExportClientIdResponse500 | str]
    """

    kwargs = _get_kwargs(
        client_id=client_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    client_id: int,
    *,
    client: AuthenticatedClient,
) -> (
    GetApiV1SqllabExportClientIdResponse400
    | GetApiV1SqllabExportClientIdResponse401
    | GetApiV1SqllabExportClientIdResponse403
    | GetApiV1SqllabExportClientIdResponse404
    | GetApiV1SqllabExportClientIdResponse500
    | str
    | None
):
    """Export the SQL query results to a CSV

    Args:
        client_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1SqllabExportClientIdResponse400 | GetApiV1SqllabExportClientIdResponse401 | GetApiV1SqllabExportClientIdResponse403 | GetApiV1SqllabExportClientIdResponse404 | GetApiV1SqllabExportClientIdResponse500 | str
    """

    return sync_detailed(
        client_id=client_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    client_id: int,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetApiV1SqllabExportClientIdResponse400
    | GetApiV1SqllabExportClientIdResponse401
    | GetApiV1SqllabExportClientIdResponse403
    | GetApiV1SqllabExportClientIdResponse404
    | GetApiV1SqllabExportClientIdResponse500
    | str
]:
    """Export the SQL query results to a CSV

    Args:
        client_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1SqllabExportClientIdResponse400 | GetApiV1SqllabExportClientIdResponse401 | GetApiV1SqllabExportClientIdResponse403 | GetApiV1SqllabExportClientIdResponse404 | GetApiV1SqllabExportClientIdResponse500 | str]
    """

    kwargs = _get_kwargs(
        client_id=client_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    client_id: int,
    *,
    client: AuthenticatedClient,
) -> (
    GetApiV1SqllabExportClientIdResponse400
    | GetApiV1SqllabExportClientIdResponse401
    | GetApiV1SqllabExportClientIdResponse403
    | GetApiV1SqllabExportClientIdResponse404
    | GetApiV1SqllabExportClientIdResponse500
    | str
    | None
):
    """Export the SQL query results to a CSV

    Args:
        client_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1SqllabExportClientIdResponse400 | GetApiV1SqllabExportClientIdResponse401 | GetApiV1SqllabExportClientIdResponse403 | GetApiV1SqllabExportClientIdResponse404 | GetApiV1SqllabExportClientIdResponse500 | str
    """

    return (
        await asyncio_detailed(
            client_id=client_id,
            client=client,
        )
    ).parsed
