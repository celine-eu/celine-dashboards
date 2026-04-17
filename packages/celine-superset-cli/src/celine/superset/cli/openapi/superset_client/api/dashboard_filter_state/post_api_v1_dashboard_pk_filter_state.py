from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.post_api_v1_dashboard_pk_filter_state_response_201 import PostApiV1DashboardPkFilterStateResponse201
from ...models.post_api_v1_dashboard_pk_filter_state_response_400 import PostApiV1DashboardPkFilterStateResponse400
from ...models.post_api_v1_dashboard_pk_filter_state_response_401 import PostApiV1DashboardPkFilterStateResponse401
from ...models.post_api_v1_dashboard_pk_filter_state_response_422 import PostApiV1DashboardPkFilterStateResponse422
from ...models.post_api_v1_dashboard_pk_filter_state_response_500 import PostApiV1DashboardPkFilterStateResponse500
from ...models.temporary_cache_post_schema import TemporaryCachePostSchema
from ...types import UNSET, Response, Unset


def _get_kwargs(
    pk: int,
    *,
    body: TemporaryCachePostSchema,
    tab_id: int | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    params: dict[str, Any] = {}

    params["tab_id"] = tab_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/dashboard/{pk}/filter_state".format(
            pk=quote(str(pk), safe=""),
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
    PostApiV1DashboardPkFilterStateResponse201
    | PostApiV1DashboardPkFilterStateResponse400
    | PostApiV1DashboardPkFilterStateResponse401
    | PostApiV1DashboardPkFilterStateResponse422
    | PostApiV1DashboardPkFilterStateResponse500
    | None
):
    if response.status_code == 201:
        response_201 = PostApiV1DashboardPkFilterStateResponse201.from_dict(response.json())

        return response_201

    if response.status_code == 400:
        response_400 = PostApiV1DashboardPkFilterStateResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PostApiV1DashboardPkFilterStateResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 422:
        response_422 = PostApiV1DashboardPkFilterStateResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = PostApiV1DashboardPkFilterStateResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PostApiV1DashboardPkFilterStateResponse201
    | PostApiV1DashboardPkFilterStateResponse400
    | PostApiV1DashboardPkFilterStateResponse401
    | PostApiV1DashboardPkFilterStateResponse422
    | PostApiV1DashboardPkFilterStateResponse500
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
    body: TemporaryCachePostSchema,
    tab_id: int | Unset = UNSET,
) -> Response[
    PostApiV1DashboardPkFilterStateResponse201
    | PostApiV1DashboardPkFilterStateResponse400
    | PostApiV1DashboardPkFilterStateResponse401
    | PostApiV1DashboardPkFilterStateResponse422
    | PostApiV1DashboardPkFilterStateResponse500
]:
    """Create a dashboard's filter state

    Args:
        pk (int):
        tab_id (int | Unset):
        body (TemporaryCachePostSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1DashboardPkFilterStateResponse201 | PostApiV1DashboardPkFilterStateResponse400 | PostApiV1DashboardPkFilterStateResponse401 | PostApiV1DashboardPkFilterStateResponse422 | PostApiV1DashboardPkFilterStateResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
        body=body,
        tab_id=tab_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    pk: int,
    *,
    client: AuthenticatedClient,
    body: TemporaryCachePostSchema,
    tab_id: int | Unset = UNSET,
) -> (
    PostApiV1DashboardPkFilterStateResponse201
    | PostApiV1DashboardPkFilterStateResponse400
    | PostApiV1DashboardPkFilterStateResponse401
    | PostApiV1DashboardPkFilterStateResponse422
    | PostApiV1DashboardPkFilterStateResponse500
    | None
):
    """Create a dashboard's filter state

    Args:
        pk (int):
        tab_id (int | Unset):
        body (TemporaryCachePostSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1DashboardPkFilterStateResponse201 | PostApiV1DashboardPkFilterStateResponse400 | PostApiV1DashboardPkFilterStateResponse401 | PostApiV1DashboardPkFilterStateResponse422 | PostApiV1DashboardPkFilterStateResponse500
    """

    return sync_detailed(
        pk=pk,
        client=client,
        body=body,
        tab_id=tab_id,
    ).parsed


async def asyncio_detailed(
    pk: int,
    *,
    client: AuthenticatedClient,
    body: TemporaryCachePostSchema,
    tab_id: int | Unset = UNSET,
) -> Response[
    PostApiV1DashboardPkFilterStateResponse201
    | PostApiV1DashboardPkFilterStateResponse400
    | PostApiV1DashboardPkFilterStateResponse401
    | PostApiV1DashboardPkFilterStateResponse422
    | PostApiV1DashboardPkFilterStateResponse500
]:
    """Create a dashboard's filter state

    Args:
        pk (int):
        tab_id (int | Unset):
        body (TemporaryCachePostSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1DashboardPkFilterStateResponse201 | PostApiV1DashboardPkFilterStateResponse400 | PostApiV1DashboardPkFilterStateResponse401 | PostApiV1DashboardPkFilterStateResponse422 | PostApiV1DashboardPkFilterStateResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
        body=body,
        tab_id=tab_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    pk: int,
    *,
    client: AuthenticatedClient,
    body: TemporaryCachePostSchema,
    tab_id: int | Unset = UNSET,
) -> (
    PostApiV1DashboardPkFilterStateResponse201
    | PostApiV1DashboardPkFilterStateResponse400
    | PostApiV1DashboardPkFilterStateResponse401
    | PostApiV1DashboardPkFilterStateResponse422
    | PostApiV1DashboardPkFilterStateResponse500
    | None
):
    """Create a dashboard's filter state

    Args:
        pk (int):
        tab_id (int | Unset):
        body (TemporaryCachePostSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1DashboardPkFilterStateResponse201 | PostApiV1DashboardPkFilterStateResponse400 | PostApiV1DashboardPkFilterStateResponse401 | PostApiV1DashboardPkFilterStateResponse422 | PostApiV1DashboardPkFilterStateResponse500
    """

    return (
        await asyncio_detailed(
            pk=pk,
            client=client,
            body=body,
            tab_id=tab_id,
        )
    ).parsed
