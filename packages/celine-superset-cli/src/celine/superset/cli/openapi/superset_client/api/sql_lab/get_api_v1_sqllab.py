from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_sqllab_response_400 import GetApiV1SqllabResponse400
from ...models.get_api_v1_sqllab_response_401 import GetApiV1SqllabResponse401
from ...models.get_api_v1_sqllab_response_403 import GetApiV1SqllabResponse403
from ...models.get_api_v1_sqllab_response_500 import GetApiV1SqllabResponse500
from ...models.sql_lab_bootstrap_schema import SQLLabBootstrapSchema
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/sqllab/",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetApiV1SqllabResponse400
    | GetApiV1SqllabResponse401
    | GetApiV1SqllabResponse403
    | GetApiV1SqllabResponse500
    | SQLLabBootstrapSchema
    | None
):
    if response.status_code == 200:
        response_200 = SQLLabBootstrapSchema.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = GetApiV1SqllabResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = GetApiV1SqllabResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 403:
        response_403 = GetApiV1SqllabResponse403.from_dict(response.json())

        return response_403

    if response.status_code == 500:
        response_500 = GetApiV1SqllabResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    GetApiV1SqllabResponse400
    | GetApiV1SqllabResponse401
    | GetApiV1SqllabResponse403
    | GetApiV1SqllabResponse500
    | SQLLabBootstrapSchema
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
    GetApiV1SqllabResponse400
    | GetApiV1SqllabResponse401
    | GetApiV1SqllabResponse403
    | GetApiV1SqllabResponse500
    | SQLLabBootstrapSchema
]:
    """Get the bootstrap data for SqlLab page

     Assembles SQLLab bootstrap data (active_tab, databases, queries, tab_state_ids) in a single
    endpoint. The data can be assembled from the current user's id.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1SqllabResponse400 | GetApiV1SqllabResponse401 | GetApiV1SqllabResponse403 | GetApiV1SqllabResponse500 | SQLLabBootstrapSchema]
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
    GetApiV1SqllabResponse400
    | GetApiV1SqllabResponse401
    | GetApiV1SqllabResponse403
    | GetApiV1SqllabResponse500
    | SQLLabBootstrapSchema
    | None
):
    """Get the bootstrap data for SqlLab page

     Assembles SQLLab bootstrap data (active_tab, databases, queries, tab_state_ids) in a single
    endpoint. The data can be assembled from the current user's id.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1SqllabResponse400 | GetApiV1SqllabResponse401 | GetApiV1SqllabResponse403 | GetApiV1SqllabResponse500 | SQLLabBootstrapSchema
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[
    GetApiV1SqllabResponse400
    | GetApiV1SqllabResponse401
    | GetApiV1SqllabResponse403
    | GetApiV1SqllabResponse500
    | SQLLabBootstrapSchema
]:
    """Get the bootstrap data for SqlLab page

     Assembles SQLLab bootstrap data (active_tab, databases, queries, tab_state_ids) in a single
    endpoint. The data can be assembled from the current user's id.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1SqllabResponse400 | GetApiV1SqllabResponse401 | GetApiV1SqllabResponse403 | GetApiV1SqllabResponse500 | SQLLabBootstrapSchema]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> (
    GetApiV1SqllabResponse400
    | GetApiV1SqllabResponse401
    | GetApiV1SqllabResponse403
    | GetApiV1SqllabResponse500
    | SQLLabBootstrapSchema
    | None
):
    """Get the bootstrap data for SqlLab page

     Assembles SQLLab bootstrap data (active_tab, databases, queries, tab_state_ids) in a single
    endpoint. The data can be assembled from the current user's id.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1SqllabResponse400 | GetApiV1SqllabResponse401 | GetApiV1SqllabResponse403 | GetApiV1SqllabResponse500 | SQLLabBootstrapSchema
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
