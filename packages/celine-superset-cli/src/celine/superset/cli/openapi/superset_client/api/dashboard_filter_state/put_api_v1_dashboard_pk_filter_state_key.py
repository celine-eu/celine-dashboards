from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.put_api_v1_dashboard_pk_filter_state_key_response_200 import PutApiV1DashboardPkFilterStateKeyResponse200
from ...models.put_api_v1_dashboard_pk_filter_state_key_response_400 import PutApiV1DashboardPkFilterStateKeyResponse400
from ...models.put_api_v1_dashboard_pk_filter_state_key_response_401 import PutApiV1DashboardPkFilterStateKeyResponse401
from ...models.put_api_v1_dashboard_pk_filter_state_key_response_404 import PutApiV1DashboardPkFilterStateKeyResponse404
from ...models.put_api_v1_dashboard_pk_filter_state_key_response_422 import PutApiV1DashboardPkFilterStateKeyResponse422
from ...models.put_api_v1_dashboard_pk_filter_state_key_response_500 import PutApiV1DashboardPkFilterStateKeyResponse500
from ...models.temporary_cache_put_schema import TemporaryCachePutSchema
from ...types import UNSET, Response, Unset


def _get_kwargs(
    pk: int,
    key: str,
    *,
    body: TemporaryCachePutSchema,
    tab_id: int | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    params: dict[str, Any] = {}

    params["tab_id"] = tab_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "put",
        "url": "/api/v1/dashboard/{pk}/filter_state/{key}".format(
            pk=quote(str(pk), safe=""),
            key=quote(str(key), safe=""),
        ),
        "params": params,
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    PutApiV1DashboardPkFilterStateKeyResponse200
    | PutApiV1DashboardPkFilterStateKeyResponse400
    | PutApiV1DashboardPkFilterStateKeyResponse401
    | PutApiV1DashboardPkFilterStateKeyResponse404
    | PutApiV1DashboardPkFilterStateKeyResponse422
    | PutApiV1DashboardPkFilterStateKeyResponse500
    | None
):
    if response.status_code == 200:
        response_200 = PutApiV1DashboardPkFilterStateKeyResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = PutApiV1DashboardPkFilterStateKeyResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PutApiV1DashboardPkFilterStateKeyResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = PutApiV1DashboardPkFilterStateKeyResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 422:
        response_422 = PutApiV1DashboardPkFilterStateKeyResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = PutApiV1DashboardPkFilterStateKeyResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PutApiV1DashboardPkFilterStateKeyResponse200
    | PutApiV1DashboardPkFilterStateKeyResponse400
    | PutApiV1DashboardPkFilterStateKeyResponse401
    | PutApiV1DashboardPkFilterStateKeyResponse404
    | PutApiV1DashboardPkFilterStateKeyResponse422
    | PutApiV1DashboardPkFilterStateKeyResponse500
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
    body: TemporaryCachePutSchema,
    tab_id: int | Unset = UNSET,
) -> Response[
    PutApiV1DashboardPkFilterStateKeyResponse200
    | PutApiV1DashboardPkFilterStateKeyResponse400
    | PutApiV1DashboardPkFilterStateKeyResponse401
    | PutApiV1DashboardPkFilterStateKeyResponse404
    | PutApiV1DashboardPkFilterStateKeyResponse422
    | PutApiV1DashboardPkFilterStateKeyResponse500
]:
    """Update a dashboard's filter state value

    Args:
        pk (int):
        key (str):
        tab_id (int | Unset):
        body (TemporaryCachePutSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PutApiV1DashboardPkFilterStateKeyResponse200 | PutApiV1DashboardPkFilterStateKeyResponse400 | PutApiV1DashboardPkFilterStateKeyResponse401 | PutApiV1DashboardPkFilterStateKeyResponse404 | PutApiV1DashboardPkFilterStateKeyResponse422 | PutApiV1DashboardPkFilterStateKeyResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
        key=key,
        body=body,
        tab_id=tab_id,
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
    body: TemporaryCachePutSchema,
    tab_id: int | Unset = UNSET,
) -> (
    PutApiV1DashboardPkFilterStateKeyResponse200
    | PutApiV1DashboardPkFilterStateKeyResponse400
    | PutApiV1DashboardPkFilterStateKeyResponse401
    | PutApiV1DashboardPkFilterStateKeyResponse404
    | PutApiV1DashboardPkFilterStateKeyResponse422
    | PutApiV1DashboardPkFilterStateKeyResponse500
    | None
):
    """Update a dashboard's filter state value

    Args:
        pk (int):
        key (str):
        tab_id (int | Unset):
        body (TemporaryCachePutSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PutApiV1DashboardPkFilterStateKeyResponse200 | PutApiV1DashboardPkFilterStateKeyResponse400 | PutApiV1DashboardPkFilterStateKeyResponse401 | PutApiV1DashboardPkFilterStateKeyResponse404 | PutApiV1DashboardPkFilterStateKeyResponse422 | PutApiV1DashboardPkFilterStateKeyResponse500
    """

    return sync_detailed(
        pk=pk,
        key=key,
        client=client,
        body=body,
        tab_id=tab_id,
    ).parsed


async def asyncio_detailed(
    pk: int,
    key: str,
    *,
    client: AuthenticatedClient,
    body: TemporaryCachePutSchema,
    tab_id: int | Unset = UNSET,
) -> Response[
    PutApiV1DashboardPkFilterStateKeyResponse200
    | PutApiV1DashboardPkFilterStateKeyResponse400
    | PutApiV1DashboardPkFilterStateKeyResponse401
    | PutApiV1DashboardPkFilterStateKeyResponse404
    | PutApiV1DashboardPkFilterStateKeyResponse422
    | PutApiV1DashboardPkFilterStateKeyResponse500
]:
    """Update a dashboard's filter state value

    Args:
        pk (int):
        key (str):
        tab_id (int | Unset):
        body (TemporaryCachePutSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PutApiV1DashboardPkFilterStateKeyResponse200 | PutApiV1DashboardPkFilterStateKeyResponse400 | PutApiV1DashboardPkFilterStateKeyResponse401 | PutApiV1DashboardPkFilterStateKeyResponse404 | PutApiV1DashboardPkFilterStateKeyResponse422 | PutApiV1DashboardPkFilterStateKeyResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
        key=key,
        body=body,
        tab_id=tab_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    pk: int,
    key: str,
    *,
    client: AuthenticatedClient,
    body: TemporaryCachePutSchema,
    tab_id: int | Unset = UNSET,
) -> (
    PutApiV1DashboardPkFilterStateKeyResponse200
    | PutApiV1DashboardPkFilterStateKeyResponse400
    | PutApiV1DashboardPkFilterStateKeyResponse401
    | PutApiV1DashboardPkFilterStateKeyResponse404
    | PutApiV1DashboardPkFilterStateKeyResponse422
    | PutApiV1DashboardPkFilterStateKeyResponse500
    | None
):
    """Update a dashboard's filter state value

    Args:
        pk (int):
        key (str):
        tab_id (int | Unset):
        body (TemporaryCachePutSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PutApiV1DashboardPkFilterStateKeyResponse200 | PutApiV1DashboardPkFilterStateKeyResponse400 | PutApiV1DashboardPkFilterStateKeyResponse401 | PutApiV1DashboardPkFilterStateKeyResponse404 | PutApiV1DashboardPkFilterStateKeyResponse422 | PutApiV1DashboardPkFilterStateKeyResponse500
    """

    return (
        await asyncio_detailed(
            pk=pk,
            key=key,
            client=client,
            body=body,
            tab_id=tab_id,
        )
    ).parsed
