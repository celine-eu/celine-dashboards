from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.execute_payload_schema import ExecutePayloadSchema
from ...models.post_api_v1_sqllab_execute_response_400 import PostApiV1SqllabExecuteResponse400
from ...models.post_api_v1_sqllab_execute_response_401 import PostApiV1SqllabExecuteResponse401
from ...models.post_api_v1_sqllab_execute_response_403 import PostApiV1SqllabExecuteResponse403
from ...models.post_api_v1_sqllab_execute_response_404 import PostApiV1SqllabExecuteResponse404
from ...models.post_api_v1_sqllab_execute_response_500 import PostApiV1SqllabExecuteResponse500
from ...models.query_execution_response_schema import QueryExecutionResponseSchema
from ...types import Response


def _get_kwargs(
    *,
    body: ExecutePayloadSchema,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/sqllab/execute/",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    PostApiV1SqllabExecuteResponse400
    | PostApiV1SqllabExecuteResponse401
    | PostApiV1SqllabExecuteResponse403
    | PostApiV1SqllabExecuteResponse404
    | PostApiV1SqllabExecuteResponse500
    | QueryExecutionResponseSchema
    | None
):
    if response.status_code == 200:
        response_200 = QueryExecutionResponseSchema.from_dict(response.json())

        return response_200

    if response.status_code == 202:
        response_202 = QueryExecutionResponseSchema.from_dict(response.json())

        return response_202

    if response.status_code == 400:
        response_400 = PostApiV1SqllabExecuteResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PostApiV1SqllabExecuteResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 403:
        response_403 = PostApiV1SqllabExecuteResponse403.from_dict(response.json())

        return response_403

    if response.status_code == 404:
        response_404 = PostApiV1SqllabExecuteResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 500:
        response_500 = PostApiV1SqllabExecuteResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PostApiV1SqllabExecuteResponse400
    | PostApiV1SqllabExecuteResponse401
    | PostApiV1SqllabExecuteResponse403
    | PostApiV1SqllabExecuteResponse404
    | PostApiV1SqllabExecuteResponse500
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
    body: ExecutePayloadSchema,
) -> Response[
    PostApiV1SqllabExecuteResponse400
    | PostApiV1SqllabExecuteResponse401
    | PostApiV1SqllabExecuteResponse403
    | PostApiV1SqllabExecuteResponse404
    | PostApiV1SqllabExecuteResponse500
    | QueryExecutionResponseSchema
]:
    """Execute a SQL query

    Args:
        body (ExecutePayloadSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1SqllabExecuteResponse400 | PostApiV1SqllabExecuteResponse401 | PostApiV1SqllabExecuteResponse403 | PostApiV1SqllabExecuteResponse404 | PostApiV1SqllabExecuteResponse500 | QueryExecutionResponseSchema]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: ExecutePayloadSchema,
) -> (
    PostApiV1SqllabExecuteResponse400
    | PostApiV1SqllabExecuteResponse401
    | PostApiV1SqllabExecuteResponse403
    | PostApiV1SqllabExecuteResponse404
    | PostApiV1SqllabExecuteResponse500
    | QueryExecutionResponseSchema
    | None
):
    """Execute a SQL query

    Args:
        body (ExecutePayloadSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1SqllabExecuteResponse400 | PostApiV1SqllabExecuteResponse401 | PostApiV1SqllabExecuteResponse403 | PostApiV1SqllabExecuteResponse404 | PostApiV1SqllabExecuteResponse500 | QueryExecutionResponseSchema
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: ExecutePayloadSchema,
) -> Response[
    PostApiV1SqllabExecuteResponse400
    | PostApiV1SqllabExecuteResponse401
    | PostApiV1SqllabExecuteResponse403
    | PostApiV1SqllabExecuteResponse404
    | PostApiV1SqllabExecuteResponse500
    | QueryExecutionResponseSchema
]:
    """Execute a SQL query

    Args:
        body (ExecutePayloadSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1SqllabExecuteResponse400 | PostApiV1SqllabExecuteResponse401 | PostApiV1SqllabExecuteResponse403 | PostApiV1SqllabExecuteResponse404 | PostApiV1SqllabExecuteResponse500 | QueryExecutionResponseSchema]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: ExecutePayloadSchema,
) -> (
    PostApiV1SqllabExecuteResponse400
    | PostApiV1SqllabExecuteResponse401
    | PostApiV1SqllabExecuteResponse403
    | PostApiV1SqllabExecuteResponse404
    | PostApiV1SqllabExecuteResponse500
    | QueryExecutionResponseSchema
    | None
):
    """Execute a SQL query

    Args:
        body (ExecutePayloadSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1SqllabExecuteResponse400 | PostApiV1SqllabExecuteResponse401 | PostApiV1SqllabExecuteResponse403 | PostApiV1SqllabExecuteResponse404 | PostApiV1SqllabExecuteResponse500 | QueryExecutionResponseSchema
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
