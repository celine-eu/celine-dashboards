from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_datasource_datasource_type_datasource_id_column_column_name_values_response_200 import (
    GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse200,
)
from ...models.get_api_v1_datasource_datasource_type_datasource_id_column_column_name_values_response_400 import (
    GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse400,
)
from ...models.get_api_v1_datasource_datasource_type_datasource_id_column_column_name_values_response_401 import (
    GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse401,
)
from ...models.get_api_v1_datasource_datasource_type_datasource_id_column_column_name_values_response_403 import (
    GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse403,
)
from ...models.get_api_v1_datasource_datasource_type_datasource_id_column_column_name_values_response_404 import (
    GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse404,
)
from ...models.get_api_v1_datasource_datasource_type_datasource_id_column_column_name_values_response_500 import (
    GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse500,
)
from ...types import Response


def _get_kwargs(
    datasource_type: str,
    datasource_id: int,
    column_name: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/datasource/{datasource_type}/{datasource_id}/column/{column_name}/values/".format(
            datasource_type=quote(str(datasource_type), safe=""),
            datasource_id=quote(str(datasource_id), safe=""),
            column_name=quote(str(column_name), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse200
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse400
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse401
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse403
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse404
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse500
    | None
):
    if response.status_code == 200:
        response_200 = GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse200.from_dict(
            response.json()
        )

        return response_200

    if response.status_code == 400:
        response_400 = GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse400.from_dict(
            response.json()
        )

        return response_400

    if response.status_code == 401:
        response_401 = GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse401.from_dict(
            response.json()
        )

        return response_401

    if response.status_code == 403:
        response_403 = GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse403.from_dict(
            response.json()
        )

        return response_403

    if response.status_code == 404:
        response_404 = GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse404.from_dict(
            response.json()
        )

        return response_404

    if response.status_code == 500:
        response_500 = GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse500.from_dict(
            response.json()
        )

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse200
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse400
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse401
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse403
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse404
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse500
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    datasource_type: str,
    datasource_id: int,
    column_name: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse200
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse400
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse401
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse403
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse404
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse500
]:
    """Get possible values for a datasource column

    Args:
        datasource_type (str):
        datasource_id (int):
        column_name (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse200 | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse400 | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse401 | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse403 | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse404 | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse500]
    """

    kwargs = _get_kwargs(
        datasource_type=datasource_type,
        datasource_id=datasource_id,
        column_name=column_name,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    datasource_type: str,
    datasource_id: int,
    column_name: str,
    *,
    client: AuthenticatedClient,
) -> (
    GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse200
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse400
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse401
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse403
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse404
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse500
    | None
):
    """Get possible values for a datasource column

    Args:
        datasource_type (str):
        datasource_id (int):
        column_name (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse200 | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse400 | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse401 | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse403 | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse404 | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse500
    """

    return sync_detailed(
        datasource_type=datasource_type,
        datasource_id=datasource_id,
        column_name=column_name,
        client=client,
    ).parsed


async def asyncio_detailed(
    datasource_type: str,
    datasource_id: int,
    column_name: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse200
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse400
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse401
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse403
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse404
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse500
]:
    """Get possible values for a datasource column

    Args:
        datasource_type (str):
        datasource_id (int):
        column_name (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse200 | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse400 | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse401 | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse403 | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse404 | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse500]
    """

    kwargs = _get_kwargs(
        datasource_type=datasource_type,
        datasource_id=datasource_id,
        column_name=column_name,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    datasource_type: str,
    datasource_id: int,
    column_name: str,
    *,
    client: AuthenticatedClient,
) -> (
    GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse200
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse400
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse401
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse403
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse404
    | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse500
    | None
):
    """Get possible values for a datasource column

    Args:
        datasource_type (str):
        datasource_id (int):
        column_name (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse200 | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse400 | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse401 | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse403 | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse404 | GetApiV1DatasourceDatasourceTypeDatasourceIdColumnColumnNameValuesResponse500
    """

    return (
        await asyncio_detailed(
            datasource_type=datasource_type,
            datasource_id=datasource_id,
            column_name=column_name,
            client=client,
        )
    ).parsed
