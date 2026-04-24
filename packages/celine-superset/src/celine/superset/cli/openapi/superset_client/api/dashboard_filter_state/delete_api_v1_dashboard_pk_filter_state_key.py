from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.delete_api_v1_dashboard_pk_filter_state_key_response_200 import (
    DeleteApiV1DashboardPkFilterStateKeyResponse200,
)
from ...models.delete_api_v1_dashboard_pk_filter_state_key_response_400 import (
    DeleteApiV1DashboardPkFilterStateKeyResponse400,
)
from ...models.delete_api_v1_dashboard_pk_filter_state_key_response_401 import (
    DeleteApiV1DashboardPkFilterStateKeyResponse401,
)
from ...models.delete_api_v1_dashboard_pk_filter_state_key_response_404 import (
    DeleteApiV1DashboardPkFilterStateKeyResponse404,
)
from ...models.delete_api_v1_dashboard_pk_filter_state_key_response_422 import (
    DeleteApiV1DashboardPkFilterStateKeyResponse422,
)
from ...models.delete_api_v1_dashboard_pk_filter_state_key_response_500 import (
    DeleteApiV1DashboardPkFilterStateKeyResponse500,
)
from ...types import Response


def _get_kwargs(
    pk: int,
    key: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "delete",
        "url": "/api/v1/dashboard/{pk}/filter_state/{key}".format(
            pk=quote(str(pk), safe=""),
            key=quote(str(key), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    DeleteApiV1DashboardPkFilterStateKeyResponse200
    | DeleteApiV1DashboardPkFilterStateKeyResponse400
    | DeleteApiV1DashboardPkFilterStateKeyResponse401
    | DeleteApiV1DashboardPkFilterStateKeyResponse404
    | DeleteApiV1DashboardPkFilterStateKeyResponse422
    | DeleteApiV1DashboardPkFilterStateKeyResponse500
    | None
):
    if response.status_code == 200:
        response_200 = DeleteApiV1DashboardPkFilterStateKeyResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = DeleteApiV1DashboardPkFilterStateKeyResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = DeleteApiV1DashboardPkFilterStateKeyResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = DeleteApiV1DashboardPkFilterStateKeyResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 422:
        response_422 = DeleteApiV1DashboardPkFilterStateKeyResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = DeleteApiV1DashboardPkFilterStateKeyResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    DeleteApiV1DashboardPkFilterStateKeyResponse200
    | DeleteApiV1DashboardPkFilterStateKeyResponse400
    | DeleteApiV1DashboardPkFilterStateKeyResponse401
    | DeleteApiV1DashboardPkFilterStateKeyResponse404
    | DeleteApiV1DashboardPkFilterStateKeyResponse422
    | DeleteApiV1DashboardPkFilterStateKeyResponse500
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    pk: int,
    key: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    DeleteApiV1DashboardPkFilterStateKeyResponse200
    | DeleteApiV1DashboardPkFilterStateKeyResponse400
    | DeleteApiV1DashboardPkFilterStateKeyResponse401
    | DeleteApiV1DashboardPkFilterStateKeyResponse404
    | DeleteApiV1DashboardPkFilterStateKeyResponse422
    | DeleteApiV1DashboardPkFilterStateKeyResponse500
]:
    """Delete a dashboard's filter state value

    Args:
        pk (int):
        key (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeleteApiV1DashboardPkFilterStateKeyResponse200 | DeleteApiV1DashboardPkFilterStateKeyResponse400 | DeleteApiV1DashboardPkFilterStateKeyResponse401 | DeleteApiV1DashboardPkFilterStateKeyResponse404 | DeleteApiV1DashboardPkFilterStateKeyResponse422 | DeleteApiV1DashboardPkFilterStateKeyResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
        key=key,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    pk: int,
    key: str,
    *,
    client: AuthenticatedClient,
) -> (
    DeleteApiV1DashboardPkFilterStateKeyResponse200
    | DeleteApiV1DashboardPkFilterStateKeyResponse400
    | DeleteApiV1DashboardPkFilterStateKeyResponse401
    | DeleteApiV1DashboardPkFilterStateKeyResponse404
    | DeleteApiV1DashboardPkFilterStateKeyResponse422
    | DeleteApiV1DashboardPkFilterStateKeyResponse500
    | None
):
    """Delete a dashboard's filter state value

    Args:
        pk (int):
        key (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeleteApiV1DashboardPkFilterStateKeyResponse200 | DeleteApiV1DashboardPkFilterStateKeyResponse400 | DeleteApiV1DashboardPkFilterStateKeyResponse401 | DeleteApiV1DashboardPkFilterStateKeyResponse404 | DeleteApiV1DashboardPkFilterStateKeyResponse422 | DeleteApiV1DashboardPkFilterStateKeyResponse500
    """

    return sync_detailed(
        pk=pk,
        key=key,
        client=client,
    ).parsed


async def asyncio_detailed(
    pk: int,
    key: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    DeleteApiV1DashboardPkFilterStateKeyResponse200
    | DeleteApiV1DashboardPkFilterStateKeyResponse400
    | DeleteApiV1DashboardPkFilterStateKeyResponse401
    | DeleteApiV1DashboardPkFilterStateKeyResponse404
    | DeleteApiV1DashboardPkFilterStateKeyResponse422
    | DeleteApiV1DashboardPkFilterStateKeyResponse500
]:
    """Delete a dashboard's filter state value

    Args:
        pk (int):
        key (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeleteApiV1DashboardPkFilterStateKeyResponse200 | DeleteApiV1DashboardPkFilterStateKeyResponse400 | DeleteApiV1DashboardPkFilterStateKeyResponse401 | DeleteApiV1DashboardPkFilterStateKeyResponse404 | DeleteApiV1DashboardPkFilterStateKeyResponse422 | DeleteApiV1DashboardPkFilterStateKeyResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
        key=key,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    pk: int,
    key: str,
    *,
    client: AuthenticatedClient,
) -> (
    DeleteApiV1DashboardPkFilterStateKeyResponse200
    | DeleteApiV1DashboardPkFilterStateKeyResponse400
    | DeleteApiV1DashboardPkFilterStateKeyResponse401
    | DeleteApiV1DashboardPkFilterStateKeyResponse404
    | DeleteApiV1DashboardPkFilterStateKeyResponse422
    | DeleteApiV1DashboardPkFilterStateKeyResponse500
    | None
):
    """Delete a dashboard's filter state value

    Args:
        pk (int):
        key (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeleteApiV1DashboardPkFilterStateKeyResponse200 | DeleteApiV1DashboardPkFilterStateKeyResponse400 | DeleteApiV1DashboardPkFilterStateKeyResponse401 | DeleteApiV1DashboardPkFilterStateKeyResponse404 | DeleteApiV1DashboardPkFilterStateKeyResponse422 | DeleteApiV1DashboardPkFilterStateKeyResponse500
    """

    return (
        await asyncio_detailed(
            pk=pk,
            key=key,
            client=client,
        )
    ).parsed
