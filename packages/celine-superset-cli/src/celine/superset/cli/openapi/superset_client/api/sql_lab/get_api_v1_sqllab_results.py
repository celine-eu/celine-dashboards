from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_sqllab_results_response_400 import GetApiV1SqllabResultsResponse400
from ...models.get_api_v1_sqllab_results_response_401 import GetApiV1SqllabResultsResponse401
from ...models.get_api_v1_sqllab_results_response_403 import GetApiV1SqllabResultsResponse403
from ...models.get_api_v1_sqllab_results_response_404 import GetApiV1SqllabResultsResponse404
from ...models.get_api_v1_sqllab_results_response_410 import GetApiV1SqllabResultsResponse410
from ...models.get_api_v1_sqllab_results_response_500 import GetApiV1SqllabResultsResponse500
from ...models.query_execution_response_schema import QueryExecutionResponseSchema
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/sqllab/results/",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetApiV1SqllabResultsResponse400
    | GetApiV1SqllabResultsResponse401
    | GetApiV1SqllabResultsResponse403
    | GetApiV1SqllabResultsResponse404
    | GetApiV1SqllabResultsResponse410
    | GetApiV1SqllabResultsResponse500
    | QueryExecutionResponseSchema
    | None
):
    if response.status_code == 200:
        response_200 = QueryExecutionResponseSchema.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = GetApiV1SqllabResultsResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = GetApiV1SqllabResultsResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 403:
        response_403 = GetApiV1SqllabResultsResponse403.from_dict(response.json())

        return response_403

    if response.status_code == 404:
        response_404 = GetApiV1SqllabResultsResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 410:
        response_410 = GetApiV1SqllabResultsResponse410.from_dict(response.json())

        return response_410

    if response.status_code == 500:
        response_500 = GetApiV1SqllabResultsResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    GetApiV1SqllabResultsResponse400
    | GetApiV1SqllabResultsResponse401
    | GetApiV1SqllabResultsResponse403
    | GetApiV1SqllabResultsResponse404
    | GetApiV1SqllabResultsResponse410
    | GetApiV1SqllabResultsResponse500
    | QueryExecutionResponseSchema
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
    GetApiV1SqllabResultsResponse400
    | GetApiV1SqllabResultsResponse401
    | GetApiV1SqllabResultsResponse403
    | GetApiV1SqllabResultsResponse404
    | GetApiV1SqllabResultsResponse410
    | GetApiV1SqllabResultsResponse500
    | QueryExecutionResponseSchema
]:
    """Get the result of a SQL query execution

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1SqllabResultsResponse400 | GetApiV1SqllabResultsResponse401 | GetApiV1SqllabResultsResponse403 | GetApiV1SqllabResultsResponse404 | GetApiV1SqllabResultsResponse410 | GetApiV1SqllabResultsResponse500 | QueryExecutionResponseSchema]
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
    GetApiV1SqllabResultsResponse400
    | GetApiV1SqllabResultsResponse401
    | GetApiV1SqllabResultsResponse403
    | GetApiV1SqllabResultsResponse404
    | GetApiV1SqllabResultsResponse410
    | GetApiV1SqllabResultsResponse500
    | QueryExecutionResponseSchema
    | None
):
    """Get the result of a SQL query execution

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1SqllabResultsResponse400 | GetApiV1SqllabResultsResponse401 | GetApiV1SqllabResultsResponse403 | GetApiV1SqllabResultsResponse404 | GetApiV1SqllabResultsResponse410 | GetApiV1SqllabResultsResponse500 | QueryExecutionResponseSchema
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[
    GetApiV1SqllabResultsResponse400
    | GetApiV1SqllabResultsResponse401
    | GetApiV1SqllabResultsResponse403
    | GetApiV1SqllabResultsResponse404
    | GetApiV1SqllabResultsResponse410
    | GetApiV1SqllabResultsResponse500
    | QueryExecutionResponseSchema
]:
    """Get the result of a SQL query execution

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1SqllabResultsResponse400 | GetApiV1SqllabResultsResponse401 | GetApiV1SqllabResultsResponse403 | GetApiV1SqllabResultsResponse404 | GetApiV1SqllabResultsResponse410 | GetApiV1SqllabResultsResponse500 | QueryExecutionResponseSchema]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> (
    GetApiV1SqllabResultsResponse400
    | GetApiV1SqllabResultsResponse401
    | GetApiV1SqllabResultsResponse403
    | GetApiV1SqllabResultsResponse404
    | GetApiV1SqllabResultsResponse410
    | GetApiV1SqllabResultsResponse500
    | QueryExecutionResponseSchema
    | None
):
    """Get the result of a SQL query execution

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1SqllabResultsResponse400 | GetApiV1SqllabResultsResponse401 | GetApiV1SqllabResultsResponse403 | GetApiV1SqllabResultsResponse404 | GetApiV1SqllabResultsResponse410 | GetApiV1SqllabResultsResponse500 | QueryExecutionResponseSchema
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
