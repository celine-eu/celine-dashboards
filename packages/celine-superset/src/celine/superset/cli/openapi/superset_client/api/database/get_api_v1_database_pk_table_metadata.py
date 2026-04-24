from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_database_pk_table_metadata_response_401 import GetApiV1DatabasePkTableMetadataResponse401
from ...models.get_api_v1_database_pk_table_metadata_response_404 import GetApiV1DatabasePkTableMetadataResponse404
from ...models.get_api_v1_database_pk_table_metadata_response_500 import GetApiV1DatabasePkTableMetadataResponse500
from ...models.table_extra_metadata_response_schema import TableExtraMetadataResponseSchema
from ...types import UNSET, Response, Unset


def _get_kwargs(
    pk: int,
    *,
    name: str,
    schema: str | Unset = UNSET,
    catalog: str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["name"] = name

    params["schema"] = schema

    params["catalog"] = catalog

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/database/{pk}/table_metadata/".format(
            pk=quote(str(pk), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetApiV1DatabasePkTableMetadataResponse401
    | GetApiV1DatabasePkTableMetadataResponse404
    | GetApiV1DatabasePkTableMetadataResponse500
    | TableExtraMetadataResponseSchema
    | None
):
    if response.status_code == 200:
        response_200 = TableExtraMetadataResponseSchema.from_dict(response.json())

        return response_200

    if response.status_code == 401:
        response_401 = GetApiV1DatabasePkTableMetadataResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = GetApiV1DatabasePkTableMetadataResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 500:
        response_500 = GetApiV1DatabasePkTableMetadataResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    GetApiV1DatabasePkTableMetadataResponse401
    | GetApiV1DatabasePkTableMetadataResponse404
    | GetApiV1DatabasePkTableMetadataResponse500
    | TableExtraMetadataResponseSchema
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    pk: int,
    *,
    client: AuthenticatedClient,
    name: str,
    schema: str | Unset = UNSET,
    catalog: str | Unset = UNSET,
) -> Response[
    GetApiV1DatabasePkTableMetadataResponse401
    | GetApiV1DatabasePkTableMetadataResponse404
    | GetApiV1DatabasePkTableMetadataResponse500
    | TableExtraMetadataResponseSchema
]:
    """Get table metadata

     Metadata associated with the table (columns, indexes, etc.)

    Args:
        pk (int):
        name (str):
        schema (str | Unset):
        catalog (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1DatabasePkTableMetadataResponse401 | GetApiV1DatabasePkTableMetadataResponse404 | GetApiV1DatabasePkTableMetadataResponse500 | TableExtraMetadataResponseSchema]
    """

    kwargs = _get_kwargs(
        pk=pk,
        name=name,
        schema=schema,
        catalog=catalog,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    pk: int,
    *,
    client: AuthenticatedClient,
    name: str,
    schema: str | Unset = UNSET,
    catalog: str | Unset = UNSET,
) -> (
    GetApiV1DatabasePkTableMetadataResponse401
    | GetApiV1DatabasePkTableMetadataResponse404
    | GetApiV1DatabasePkTableMetadataResponse500
    | TableExtraMetadataResponseSchema
    | None
):
    """Get table metadata

     Metadata associated with the table (columns, indexes, etc.)

    Args:
        pk (int):
        name (str):
        schema (str | Unset):
        catalog (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1DatabasePkTableMetadataResponse401 | GetApiV1DatabasePkTableMetadataResponse404 | GetApiV1DatabasePkTableMetadataResponse500 | TableExtraMetadataResponseSchema
    """

    return sync_detailed(
        pk=pk,
        client=client,
        name=name,
        schema=schema,
        catalog=catalog,
    ).parsed


async def asyncio_detailed(
    pk: int,
    *,
    client: AuthenticatedClient,
    name: str,
    schema: str | Unset = UNSET,
    catalog: str | Unset = UNSET,
) -> Response[
    GetApiV1DatabasePkTableMetadataResponse401
    | GetApiV1DatabasePkTableMetadataResponse404
    | GetApiV1DatabasePkTableMetadataResponse500
    | TableExtraMetadataResponseSchema
]:
    """Get table metadata

     Metadata associated with the table (columns, indexes, etc.)

    Args:
        pk (int):
        name (str):
        schema (str | Unset):
        catalog (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1DatabasePkTableMetadataResponse401 | GetApiV1DatabasePkTableMetadataResponse404 | GetApiV1DatabasePkTableMetadataResponse500 | TableExtraMetadataResponseSchema]
    """

    kwargs = _get_kwargs(
        pk=pk,
        name=name,
        schema=schema,
        catalog=catalog,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    pk: int,
    *,
    client: AuthenticatedClient,
    name: str,
    schema: str | Unset = UNSET,
    catalog: str | Unset = UNSET,
) -> (
    GetApiV1DatabasePkTableMetadataResponse401
    | GetApiV1DatabasePkTableMetadataResponse404
    | GetApiV1DatabasePkTableMetadataResponse500
    | TableExtraMetadataResponseSchema
    | None
):
    """Get table metadata

     Metadata associated with the table (columns, indexes, etc.)

    Args:
        pk (int):
        name (str):
        schema (str | Unset):
        catalog (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1DatabasePkTableMetadataResponse401 | GetApiV1DatabasePkTableMetadataResponse404 | GetApiV1DatabasePkTableMetadataResponse500 | TableExtraMetadataResponseSchema
    """

    return (
        await asyncio_detailed(
            pk=pk,
            client=client,
            name=name,
            schema=schema,
            catalog=catalog,
        )
    ).parsed
