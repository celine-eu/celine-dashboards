from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.distinc_response_schema import DistincResponseSchema
from ...models.get_api_v1_saved_query_distinct_column_name_response_400 import (
    GetApiV1SavedQueryDistinctColumnNameResponse400,
)
from ...models.get_api_v1_saved_query_distinct_column_name_response_401 import (
    GetApiV1SavedQueryDistinctColumnNameResponse401,
)
from ...models.get_api_v1_saved_query_distinct_column_name_response_404 import (
    GetApiV1SavedQueryDistinctColumnNameResponse404,
)
from ...models.get_api_v1_saved_query_distinct_column_name_response_500 import (
    GetApiV1SavedQueryDistinctColumnNameResponse500,
)
from ...types import Response


def _get_kwargs(
    column_name: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/saved_query/distinct/{column_name}".format(
            column_name=quote(str(column_name), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    DistincResponseSchema
    | GetApiV1SavedQueryDistinctColumnNameResponse400
    | GetApiV1SavedQueryDistinctColumnNameResponse401
    | GetApiV1SavedQueryDistinctColumnNameResponse404
    | GetApiV1SavedQueryDistinctColumnNameResponse500
    | None
):
    if response.status_code == 200:
        response_200 = DistincResponseSchema.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = GetApiV1SavedQueryDistinctColumnNameResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = GetApiV1SavedQueryDistinctColumnNameResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = GetApiV1SavedQueryDistinctColumnNameResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 500:
        response_500 = GetApiV1SavedQueryDistinctColumnNameResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    DistincResponseSchema
    | GetApiV1SavedQueryDistinctColumnNameResponse400
    | GetApiV1SavedQueryDistinctColumnNameResponse401
    | GetApiV1SavedQueryDistinctColumnNameResponse404
    | GetApiV1SavedQueryDistinctColumnNameResponse500
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    column_name: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    DistincResponseSchema
    | GetApiV1SavedQueryDistinctColumnNameResponse400
    | GetApiV1SavedQueryDistinctColumnNameResponse401
    | GetApiV1SavedQueryDistinctColumnNameResponse404
    | GetApiV1SavedQueryDistinctColumnNameResponse500
]:
    """Get distinct values from field data

    Args:
        column_name (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DistincResponseSchema | GetApiV1SavedQueryDistinctColumnNameResponse400 | GetApiV1SavedQueryDistinctColumnNameResponse401 | GetApiV1SavedQueryDistinctColumnNameResponse404 | GetApiV1SavedQueryDistinctColumnNameResponse500]
    """

    kwargs = _get_kwargs(
        column_name=column_name,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    column_name: str,
    *,
    client: AuthenticatedClient,
) -> (
    DistincResponseSchema
    | GetApiV1SavedQueryDistinctColumnNameResponse400
    | GetApiV1SavedQueryDistinctColumnNameResponse401
    | GetApiV1SavedQueryDistinctColumnNameResponse404
    | GetApiV1SavedQueryDistinctColumnNameResponse500
    | None
):
    """Get distinct values from field data

    Args:
        column_name (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DistincResponseSchema | GetApiV1SavedQueryDistinctColumnNameResponse400 | GetApiV1SavedQueryDistinctColumnNameResponse401 | GetApiV1SavedQueryDistinctColumnNameResponse404 | GetApiV1SavedQueryDistinctColumnNameResponse500
    """

    return sync_detailed(
        column_name=column_name,
        client=client,
    ).parsed


async def asyncio_detailed(
    column_name: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    DistincResponseSchema
    | GetApiV1SavedQueryDistinctColumnNameResponse400
    | GetApiV1SavedQueryDistinctColumnNameResponse401
    | GetApiV1SavedQueryDistinctColumnNameResponse404
    | GetApiV1SavedQueryDistinctColumnNameResponse500
]:
    """Get distinct values from field data

    Args:
        column_name (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DistincResponseSchema | GetApiV1SavedQueryDistinctColumnNameResponse400 | GetApiV1SavedQueryDistinctColumnNameResponse401 | GetApiV1SavedQueryDistinctColumnNameResponse404 | GetApiV1SavedQueryDistinctColumnNameResponse500]
    """

    kwargs = _get_kwargs(
        column_name=column_name,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    column_name: str,
    *,
    client: AuthenticatedClient,
) -> (
    DistincResponseSchema
    | GetApiV1SavedQueryDistinctColumnNameResponse400
    | GetApiV1SavedQueryDistinctColumnNameResponse401
    | GetApiV1SavedQueryDistinctColumnNameResponse404
    | GetApiV1SavedQueryDistinctColumnNameResponse500
    | None
):
    """Get distinct values from field data

    Args:
        column_name (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DistincResponseSchema | GetApiV1SavedQueryDistinctColumnNameResponse400 | GetApiV1SavedQueryDistinctColumnNameResponse401 | GetApiV1SavedQueryDistinctColumnNameResponse404 | GetApiV1SavedQueryDistinctColumnNameResponse500
    """

    return (
        await asyncio_detailed(
            column_name=column_name,
            client=client,
        )
    ).parsed
