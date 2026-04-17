from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.database_rest_api_put import DatabaseRestApiPut
from ...models.put_api_v1_database_pk_response_200 import PutApiV1DatabasePkResponse200
from ...models.put_api_v1_database_pk_response_400 import PutApiV1DatabasePkResponse400
from ...models.put_api_v1_database_pk_response_401 import PutApiV1DatabasePkResponse401
from ...models.put_api_v1_database_pk_response_403 import PutApiV1DatabasePkResponse403
from ...models.put_api_v1_database_pk_response_404 import PutApiV1DatabasePkResponse404
from ...models.put_api_v1_database_pk_response_422 import PutApiV1DatabasePkResponse422
from ...models.put_api_v1_database_pk_response_500 import PutApiV1DatabasePkResponse500
from ...types import Response


def _get_kwargs(
    pk: int,
    *,
    body: DatabaseRestApiPut,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "put",
        "url": "/api/v1/database/{pk}".format(
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
    PutApiV1DatabasePkResponse200
    | PutApiV1DatabasePkResponse400
    | PutApiV1DatabasePkResponse401
    | PutApiV1DatabasePkResponse403
    | PutApiV1DatabasePkResponse404
    | PutApiV1DatabasePkResponse422
    | PutApiV1DatabasePkResponse500
    | None
):
    if response.status_code == 200:
        response_200 = PutApiV1DatabasePkResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = PutApiV1DatabasePkResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PutApiV1DatabasePkResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 403:
        response_403 = PutApiV1DatabasePkResponse403.from_dict(response.json())

        return response_403

    if response.status_code == 404:
        response_404 = PutApiV1DatabasePkResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 422:
        response_422 = PutApiV1DatabasePkResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = PutApiV1DatabasePkResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PutApiV1DatabasePkResponse200
    | PutApiV1DatabasePkResponse400
    | PutApiV1DatabasePkResponse401
    | PutApiV1DatabasePkResponse403
    | PutApiV1DatabasePkResponse404
    | PutApiV1DatabasePkResponse422
    | PutApiV1DatabasePkResponse500
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
    body: DatabaseRestApiPut,
) -> Response[
    PutApiV1DatabasePkResponse200
    | PutApiV1DatabasePkResponse400
    | PutApiV1DatabasePkResponse401
    | PutApiV1DatabasePkResponse403
    | PutApiV1DatabasePkResponse404
    | PutApiV1DatabasePkResponse422
    | PutApiV1DatabasePkResponse500
]:
    """Change a database

    Args:
        pk (int):
        body (DatabaseRestApiPut):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PutApiV1DatabasePkResponse200 | PutApiV1DatabasePkResponse400 | PutApiV1DatabasePkResponse401 | PutApiV1DatabasePkResponse403 | PutApiV1DatabasePkResponse404 | PutApiV1DatabasePkResponse422 | PutApiV1DatabasePkResponse500]
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
    body: DatabaseRestApiPut,
) -> (
    PutApiV1DatabasePkResponse200
    | PutApiV1DatabasePkResponse400
    | PutApiV1DatabasePkResponse401
    | PutApiV1DatabasePkResponse403
    | PutApiV1DatabasePkResponse404
    | PutApiV1DatabasePkResponse422
    | PutApiV1DatabasePkResponse500
    | None
):
    """Change a database

    Args:
        pk (int):
        body (DatabaseRestApiPut):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PutApiV1DatabasePkResponse200 | PutApiV1DatabasePkResponse400 | PutApiV1DatabasePkResponse401 | PutApiV1DatabasePkResponse403 | PutApiV1DatabasePkResponse404 | PutApiV1DatabasePkResponse422 | PutApiV1DatabasePkResponse500
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
    body: DatabaseRestApiPut,
) -> Response[
    PutApiV1DatabasePkResponse200
    | PutApiV1DatabasePkResponse400
    | PutApiV1DatabasePkResponse401
    | PutApiV1DatabasePkResponse403
    | PutApiV1DatabasePkResponse404
    | PutApiV1DatabasePkResponse422
    | PutApiV1DatabasePkResponse500
]:
    """Change a database

    Args:
        pk (int):
        body (DatabaseRestApiPut):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PutApiV1DatabasePkResponse200 | PutApiV1DatabasePkResponse400 | PutApiV1DatabasePkResponse401 | PutApiV1DatabasePkResponse403 | PutApiV1DatabasePkResponse404 | PutApiV1DatabasePkResponse422 | PutApiV1DatabasePkResponse500]
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
    body: DatabaseRestApiPut,
) -> (
    PutApiV1DatabasePkResponse200
    | PutApiV1DatabasePkResponse400
    | PutApiV1DatabasePkResponse401
    | PutApiV1DatabasePkResponse403
    | PutApiV1DatabasePkResponse404
    | PutApiV1DatabasePkResponse422
    | PutApiV1DatabasePkResponse500
    | None
):
    """Change a database

    Args:
        pk (int):
        body (DatabaseRestApiPut):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PutApiV1DatabasePkResponse200 | PutApiV1DatabasePkResponse400 | PutApiV1DatabasePkResponse401 | PutApiV1DatabasePkResponse403 | PutApiV1DatabasePkResponse404 | PutApiV1DatabasePkResponse422 | PutApiV1DatabasePkResponse500
    """

    return (
        await asyncio_detailed(
            pk=pk,
            client=client,
            body=body,
        )
    ).parsed
