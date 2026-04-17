from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.post_api_v1_database_pk_validate_sql_response_200 import PostApiV1DatabasePkValidateSqlResponse200
from ...models.post_api_v1_database_pk_validate_sql_response_400 import PostApiV1DatabasePkValidateSqlResponse400
from ...models.post_api_v1_database_pk_validate_sql_response_401 import PostApiV1DatabasePkValidateSqlResponse401
from ...models.post_api_v1_database_pk_validate_sql_response_404 import PostApiV1DatabasePkValidateSqlResponse404
from ...models.post_api_v1_database_pk_validate_sql_response_500 import PostApiV1DatabasePkValidateSqlResponse500
from ...models.validate_sql_request import ValidateSQLRequest
from ...types import Response


def _get_kwargs(
    pk: int,
    *,
    body: ValidateSQLRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/database/{pk}/validate_sql/".format(
            pk=quote(str(pk), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    PostApiV1DatabasePkValidateSqlResponse200
    | PostApiV1DatabasePkValidateSqlResponse400
    | PostApiV1DatabasePkValidateSqlResponse401
    | PostApiV1DatabasePkValidateSqlResponse404
    | PostApiV1DatabasePkValidateSqlResponse500
    | None
):
    if response.status_code == 200:
        response_200 = PostApiV1DatabasePkValidateSqlResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = PostApiV1DatabasePkValidateSqlResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PostApiV1DatabasePkValidateSqlResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = PostApiV1DatabasePkValidateSqlResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 500:
        response_500 = PostApiV1DatabasePkValidateSqlResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PostApiV1DatabasePkValidateSqlResponse200
    | PostApiV1DatabasePkValidateSqlResponse400
    | PostApiV1DatabasePkValidateSqlResponse401
    | PostApiV1DatabasePkValidateSqlResponse404
    | PostApiV1DatabasePkValidateSqlResponse500
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
    body: ValidateSQLRequest,
) -> Response[
    PostApiV1DatabasePkValidateSqlResponse200
    | PostApiV1DatabasePkValidateSqlResponse400
    | PostApiV1DatabasePkValidateSqlResponse401
    | PostApiV1DatabasePkValidateSqlResponse404
    | PostApiV1DatabasePkValidateSqlResponse500
]:
    """Validate arbitrary SQL

     Validates that arbitrary SQL is acceptable for the given database.

    Args:
        pk (int):
        body (ValidateSQLRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1DatabasePkValidateSqlResponse200 | PostApiV1DatabasePkValidateSqlResponse400 | PostApiV1DatabasePkValidateSqlResponse401 | PostApiV1DatabasePkValidateSqlResponse404 | PostApiV1DatabasePkValidateSqlResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    pk: int,
    *,
    client: AuthenticatedClient,
    body: ValidateSQLRequest,
) -> (
    PostApiV1DatabasePkValidateSqlResponse200
    | PostApiV1DatabasePkValidateSqlResponse400
    | PostApiV1DatabasePkValidateSqlResponse401
    | PostApiV1DatabasePkValidateSqlResponse404
    | PostApiV1DatabasePkValidateSqlResponse500
    | None
):
    """Validate arbitrary SQL

     Validates that arbitrary SQL is acceptable for the given database.

    Args:
        pk (int):
        body (ValidateSQLRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1DatabasePkValidateSqlResponse200 | PostApiV1DatabasePkValidateSqlResponse400 | PostApiV1DatabasePkValidateSqlResponse401 | PostApiV1DatabasePkValidateSqlResponse404 | PostApiV1DatabasePkValidateSqlResponse500
    """

    return sync_detailed(
        pk=pk,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    pk: int,
    *,
    client: AuthenticatedClient,
    body: ValidateSQLRequest,
) -> Response[
    PostApiV1DatabasePkValidateSqlResponse200
    | PostApiV1DatabasePkValidateSqlResponse400
    | PostApiV1DatabasePkValidateSqlResponse401
    | PostApiV1DatabasePkValidateSqlResponse404
    | PostApiV1DatabasePkValidateSqlResponse500
]:
    """Validate arbitrary SQL

     Validates that arbitrary SQL is acceptable for the given database.

    Args:
        pk (int):
        body (ValidateSQLRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1DatabasePkValidateSqlResponse200 | PostApiV1DatabasePkValidateSqlResponse400 | PostApiV1DatabasePkValidateSqlResponse401 | PostApiV1DatabasePkValidateSqlResponse404 | PostApiV1DatabasePkValidateSqlResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    pk: int,
    *,
    client: AuthenticatedClient,
    body: ValidateSQLRequest,
) -> (
    PostApiV1DatabasePkValidateSqlResponse200
    | PostApiV1DatabasePkValidateSqlResponse400
    | PostApiV1DatabasePkValidateSqlResponse401
    | PostApiV1DatabasePkValidateSqlResponse404
    | PostApiV1DatabasePkValidateSqlResponse500
    | None
):
    """Validate arbitrary SQL

     Validates that arbitrary SQL is acceptable for the given database.

    Args:
        pk (int):
        body (ValidateSQLRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1DatabasePkValidateSqlResponse200 | PostApiV1DatabasePkValidateSqlResponse400 | PostApiV1DatabasePkValidateSqlResponse401 | PostApiV1DatabasePkValidateSqlResponse404 | PostApiV1DatabasePkValidateSqlResponse500
    """

    return (
        await asyncio_detailed(
            pk=pk,
            client=client,
            body=body,
        )
    ).parsed
