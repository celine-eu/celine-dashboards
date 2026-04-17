from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.database_connection_schema import DatabaseConnectionSchema
from ...models.get_api_v1_database_pk_connection_response_400 import GetApiV1DatabasePkConnectionResponse400
from ...models.get_api_v1_database_pk_connection_response_401 import GetApiV1DatabasePkConnectionResponse401
from ...models.get_api_v1_database_pk_connection_response_422 import GetApiV1DatabasePkConnectionResponse422
from ...models.get_api_v1_database_pk_connection_response_500 import GetApiV1DatabasePkConnectionResponse500
from ...types import Response


def _get_kwargs(
    pk: int,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/database/{pk}/connection".format(
            pk=quote(str(pk), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    DatabaseConnectionSchema
    | GetApiV1DatabasePkConnectionResponse400
    | GetApiV1DatabasePkConnectionResponse401
    | GetApiV1DatabasePkConnectionResponse422
    | GetApiV1DatabasePkConnectionResponse500
    | None
):
    if response.status_code == 200:
        response_200 = DatabaseConnectionSchema.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = GetApiV1DatabasePkConnectionResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = GetApiV1DatabasePkConnectionResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 422:
        response_422 = GetApiV1DatabasePkConnectionResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = GetApiV1DatabasePkConnectionResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    DatabaseConnectionSchema
    | GetApiV1DatabasePkConnectionResponse400
    | GetApiV1DatabasePkConnectionResponse401
    | GetApiV1DatabasePkConnectionResponse422
    | GetApiV1DatabasePkConnectionResponse500
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
) -> Response[
    DatabaseConnectionSchema
    | GetApiV1DatabasePkConnectionResponse400
    | GetApiV1DatabasePkConnectionResponse401
    | GetApiV1DatabasePkConnectionResponse422
    | GetApiV1DatabasePkConnectionResponse500
]:
    """Get a database connection info

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DatabaseConnectionSchema | GetApiV1DatabasePkConnectionResponse400 | GetApiV1DatabasePkConnectionResponse401 | GetApiV1DatabasePkConnectionResponse422 | GetApiV1DatabasePkConnectionResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    pk: int,
    *,
    client: AuthenticatedClient,
) -> (
    DatabaseConnectionSchema
    | GetApiV1DatabasePkConnectionResponse400
    | GetApiV1DatabasePkConnectionResponse401
    | GetApiV1DatabasePkConnectionResponse422
    | GetApiV1DatabasePkConnectionResponse500
    | None
):
    """Get a database connection info

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DatabaseConnectionSchema | GetApiV1DatabasePkConnectionResponse400 | GetApiV1DatabasePkConnectionResponse401 | GetApiV1DatabasePkConnectionResponse422 | GetApiV1DatabasePkConnectionResponse500
    """

    return sync_detailed(
        pk=pk,
        client=client,
    ).parsed


async def asyncio_detailed(
    pk: int,
    *,
    client: AuthenticatedClient,
) -> Response[
    DatabaseConnectionSchema
    | GetApiV1DatabasePkConnectionResponse400
    | GetApiV1DatabasePkConnectionResponse401
    | GetApiV1DatabasePkConnectionResponse422
    | GetApiV1DatabasePkConnectionResponse500
]:
    """Get a database connection info

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DatabaseConnectionSchema | GetApiV1DatabasePkConnectionResponse400 | GetApiV1DatabasePkConnectionResponse401 | GetApiV1DatabasePkConnectionResponse422 | GetApiV1DatabasePkConnectionResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    pk: int,
    *,
    client: AuthenticatedClient,
) -> (
    DatabaseConnectionSchema
    | GetApiV1DatabasePkConnectionResponse400
    | GetApiV1DatabasePkConnectionResponse401
    | GetApiV1DatabasePkConnectionResponse422
    | GetApiV1DatabasePkConnectionResponse500
    | None
):
    """Get a database connection info

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DatabaseConnectionSchema | GetApiV1DatabasePkConnectionResponse400 | GetApiV1DatabasePkConnectionResponse401 | GetApiV1DatabasePkConnectionResponse422 | GetApiV1DatabasePkConnectionResponse500
    """

    return (
        await asyncio_detailed(
            pk=pk,
            client=client,
        )
    ).parsed
