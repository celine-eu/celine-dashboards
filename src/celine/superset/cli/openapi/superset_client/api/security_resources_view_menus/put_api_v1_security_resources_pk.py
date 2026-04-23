from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.put_api_v1_security_resources_pk_response_200 import PutApiV1SecurityResourcesPkResponse200
from ...models.put_api_v1_security_resources_pk_response_400 import PutApiV1SecurityResourcesPkResponse400
from ...models.put_api_v1_security_resources_pk_response_401 import PutApiV1SecurityResourcesPkResponse401
from ...models.put_api_v1_security_resources_pk_response_404 import PutApiV1SecurityResourcesPkResponse404
from ...models.put_api_v1_security_resources_pk_response_422 import PutApiV1SecurityResourcesPkResponse422
from ...models.put_api_v1_security_resources_pk_response_500 import PutApiV1SecurityResourcesPkResponse500
from ...models.view_menu_api_put import ViewMenuApiPut
from ...types import Response


def _get_kwargs(
    pk: int,
    *,
    body: ViewMenuApiPut,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "put",
        "url": "/api/v1/security/resources/{pk}".format(
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
    PutApiV1SecurityResourcesPkResponse200
    | PutApiV1SecurityResourcesPkResponse400
    | PutApiV1SecurityResourcesPkResponse401
    | PutApiV1SecurityResourcesPkResponse404
    | PutApiV1SecurityResourcesPkResponse422
    | PutApiV1SecurityResourcesPkResponse500
    | None
):
    if response.status_code == 200:
        response_200 = PutApiV1SecurityResourcesPkResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = PutApiV1SecurityResourcesPkResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PutApiV1SecurityResourcesPkResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = PutApiV1SecurityResourcesPkResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 422:
        response_422 = PutApiV1SecurityResourcesPkResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = PutApiV1SecurityResourcesPkResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PutApiV1SecurityResourcesPkResponse200
    | PutApiV1SecurityResourcesPkResponse400
    | PutApiV1SecurityResourcesPkResponse401
    | PutApiV1SecurityResourcesPkResponse404
    | PutApiV1SecurityResourcesPkResponse422
    | PutApiV1SecurityResourcesPkResponse500
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
    body: ViewMenuApiPut,
) -> Response[
    PutApiV1SecurityResourcesPkResponse200
    | PutApiV1SecurityResourcesPkResponse400
    | PutApiV1SecurityResourcesPkResponse401
    | PutApiV1SecurityResourcesPkResponse404
    | PutApiV1SecurityResourcesPkResponse422
    | PutApiV1SecurityResourcesPkResponse500
]:
    """
    Args:
        pk (int):
        body (ViewMenuApiPut):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PutApiV1SecurityResourcesPkResponse200 | PutApiV1SecurityResourcesPkResponse400 | PutApiV1SecurityResourcesPkResponse401 | PutApiV1SecurityResourcesPkResponse404 | PutApiV1SecurityResourcesPkResponse422 | PutApiV1SecurityResourcesPkResponse500]
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
    body: ViewMenuApiPut,
) -> (
    PutApiV1SecurityResourcesPkResponse200
    | PutApiV1SecurityResourcesPkResponse400
    | PutApiV1SecurityResourcesPkResponse401
    | PutApiV1SecurityResourcesPkResponse404
    | PutApiV1SecurityResourcesPkResponse422
    | PutApiV1SecurityResourcesPkResponse500
    | None
):
    """
    Args:
        pk (int):
        body (ViewMenuApiPut):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PutApiV1SecurityResourcesPkResponse200 | PutApiV1SecurityResourcesPkResponse400 | PutApiV1SecurityResourcesPkResponse401 | PutApiV1SecurityResourcesPkResponse404 | PutApiV1SecurityResourcesPkResponse422 | PutApiV1SecurityResourcesPkResponse500
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
    body: ViewMenuApiPut,
) -> Response[
    PutApiV1SecurityResourcesPkResponse200
    | PutApiV1SecurityResourcesPkResponse400
    | PutApiV1SecurityResourcesPkResponse401
    | PutApiV1SecurityResourcesPkResponse404
    | PutApiV1SecurityResourcesPkResponse422
    | PutApiV1SecurityResourcesPkResponse500
]:
    """
    Args:
        pk (int):
        body (ViewMenuApiPut):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PutApiV1SecurityResourcesPkResponse200 | PutApiV1SecurityResourcesPkResponse400 | PutApiV1SecurityResourcesPkResponse401 | PutApiV1SecurityResourcesPkResponse404 | PutApiV1SecurityResourcesPkResponse422 | PutApiV1SecurityResourcesPkResponse500]
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
    body: ViewMenuApiPut,
) -> (
    PutApiV1SecurityResourcesPkResponse200
    | PutApiV1SecurityResourcesPkResponse400
    | PutApiV1SecurityResourcesPkResponse401
    | PutApiV1SecurityResourcesPkResponse404
    | PutApiV1SecurityResourcesPkResponse422
    | PutApiV1SecurityResourcesPkResponse500
    | None
):
    """
    Args:
        pk (int):
        body (ViewMenuApiPut):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PutApiV1SecurityResourcesPkResponse200 | PutApiV1SecurityResourcesPkResponse400 | PutApiV1SecurityResourcesPkResponse401 | PutApiV1SecurityResourcesPkResponse404 | PutApiV1SecurityResourcesPkResponse422 | PutApiV1SecurityResourcesPkResponse500
    """

    return (
        await asyncio_detailed(
            pk=pk,
            client=client,
            body=body,
        )
    ).parsed
