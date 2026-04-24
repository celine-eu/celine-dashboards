from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_database_pk_table_table_name_schema_name_response_400 import (
    GetApiV1DatabasePkTableTableNameSchemaNameResponse400,
)
from ...models.get_api_v1_database_pk_table_table_name_schema_name_response_401 import (
    GetApiV1DatabasePkTableTableNameSchemaNameResponse401,
)
from ...models.get_api_v1_database_pk_table_table_name_schema_name_response_404 import (
    GetApiV1DatabasePkTableTableNameSchemaNameResponse404,
)
from ...models.get_api_v1_database_pk_table_table_name_schema_name_response_422 import (
    GetApiV1DatabasePkTableTableNameSchemaNameResponse422,
)
from ...models.get_api_v1_database_pk_table_table_name_schema_name_response_500 import (
    GetApiV1DatabasePkTableTableNameSchemaNameResponse500,
)
from ...models.table_metadata_response_schema import TableMetadataResponseSchema
from ...types import Response


def _get_kwargs(
    pk: int,
    table_name: str,
    schema_name: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/database/{pk}/table/{table_name}/{schema_name}/".format(
            pk=quote(str(pk), safe=""),
            table_name=quote(str(table_name), safe=""),
            schema_name=quote(str(schema_name), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetApiV1DatabasePkTableTableNameSchemaNameResponse400
    | GetApiV1DatabasePkTableTableNameSchemaNameResponse401
    | GetApiV1DatabasePkTableTableNameSchemaNameResponse404
    | GetApiV1DatabasePkTableTableNameSchemaNameResponse422
    | GetApiV1DatabasePkTableTableNameSchemaNameResponse500
    | TableMetadataResponseSchema
    | None
):
    if response.status_code == 200:
        response_200 = TableMetadataResponseSchema.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = GetApiV1DatabasePkTableTableNameSchemaNameResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = GetApiV1DatabasePkTableTableNameSchemaNameResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = GetApiV1DatabasePkTableTableNameSchemaNameResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 422:
        response_422 = GetApiV1DatabasePkTableTableNameSchemaNameResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = GetApiV1DatabasePkTableTableNameSchemaNameResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    GetApiV1DatabasePkTableTableNameSchemaNameResponse400
    | GetApiV1DatabasePkTableTableNameSchemaNameResponse401
    | GetApiV1DatabasePkTableTableNameSchemaNameResponse404
    | GetApiV1DatabasePkTableTableNameSchemaNameResponse422
    | GetApiV1DatabasePkTableTableNameSchemaNameResponse500
    | TableMetadataResponseSchema
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    pk: int,
    table_name: str,
    schema_name: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetApiV1DatabasePkTableTableNameSchemaNameResponse400
    | GetApiV1DatabasePkTableTableNameSchemaNameResponse401
    | GetApiV1DatabasePkTableTableNameSchemaNameResponse404
    | GetApiV1DatabasePkTableTableNameSchemaNameResponse422
    | GetApiV1DatabasePkTableTableNameSchemaNameResponse500
    | TableMetadataResponseSchema
]:
    """Get database table metadata

    Args:
        pk (int):
        table_name (str):
        schema_name (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1DatabasePkTableTableNameSchemaNameResponse400 | GetApiV1DatabasePkTableTableNameSchemaNameResponse401 | GetApiV1DatabasePkTableTableNameSchemaNameResponse404 | GetApiV1DatabasePkTableTableNameSchemaNameResponse422 | GetApiV1DatabasePkTableTableNameSchemaNameResponse500 | TableMetadataResponseSchema]
    """

    kwargs = _get_kwargs(
        pk=pk,
        table_name=table_name,
        schema_name=schema_name,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    pk: int,
    table_name: str,
    schema_name: str,
    *,
    client: AuthenticatedClient,
) -> (
    GetApiV1DatabasePkTableTableNameSchemaNameResponse400
    | GetApiV1DatabasePkTableTableNameSchemaNameResponse401
    | GetApiV1DatabasePkTableTableNameSchemaNameResponse404
    | GetApiV1DatabasePkTableTableNameSchemaNameResponse422
    | GetApiV1DatabasePkTableTableNameSchemaNameResponse500
    | TableMetadataResponseSchema
    | None
):
    """Get database table metadata

    Args:
        pk (int):
        table_name (str):
        schema_name (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1DatabasePkTableTableNameSchemaNameResponse400 | GetApiV1DatabasePkTableTableNameSchemaNameResponse401 | GetApiV1DatabasePkTableTableNameSchemaNameResponse404 | GetApiV1DatabasePkTableTableNameSchemaNameResponse422 | GetApiV1DatabasePkTableTableNameSchemaNameResponse500 | TableMetadataResponseSchema
    """

    return sync_detailed(
        pk=pk,
        table_name=table_name,
        schema_name=schema_name,
        client=client,
    ).parsed


async def asyncio_detailed(
    pk: int,
    table_name: str,
    schema_name: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetApiV1DatabasePkTableTableNameSchemaNameResponse400
    | GetApiV1DatabasePkTableTableNameSchemaNameResponse401
    | GetApiV1DatabasePkTableTableNameSchemaNameResponse404
    | GetApiV1DatabasePkTableTableNameSchemaNameResponse422
    | GetApiV1DatabasePkTableTableNameSchemaNameResponse500
    | TableMetadataResponseSchema
]:
    """Get database table metadata

    Args:
        pk (int):
        table_name (str):
        schema_name (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1DatabasePkTableTableNameSchemaNameResponse400 | GetApiV1DatabasePkTableTableNameSchemaNameResponse401 | GetApiV1DatabasePkTableTableNameSchemaNameResponse404 | GetApiV1DatabasePkTableTableNameSchemaNameResponse422 | GetApiV1DatabasePkTableTableNameSchemaNameResponse500 | TableMetadataResponseSchema]
    """

    kwargs = _get_kwargs(
        pk=pk,
        table_name=table_name,
        schema_name=schema_name,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    pk: int,
    table_name: str,
    schema_name: str,
    *,
    client: AuthenticatedClient,
) -> (
    GetApiV1DatabasePkTableTableNameSchemaNameResponse400
    | GetApiV1DatabasePkTableTableNameSchemaNameResponse401
    | GetApiV1DatabasePkTableTableNameSchemaNameResponse404
    | GetApiV1DatabasePkTableTableNameSchemaNameResponse422
    | GetApiV1DatabasePkTableTableNameSchemaNameResponse500
    | TableMetadataResponseSchema
    | None
):
    """Get database table metadata

    Args:
        pk (int):
        table_name (str):
        schema_name (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1DatabasePkTableTableNameSchemaNameResponse400 | GetApiV1DatabasePkTableTableNameSchemaNameResponse401 | GetApiV1DatabasePkTableTableNameSchemaNameResponse404 | GetApiV1DatabasePkTableTableNameSchemaNameResponse422 | GetApiV1DatabasePkTableTableNameSchemaNameResponse500 | TableMetadataResponseSchema
    """

    return (
        await asyncio_detailed(
            pk=pk,
            table_name=table_name,
            schema_name=schema_name,
            client=client,
        )
    ).parsed
