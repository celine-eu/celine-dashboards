from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.dashboard_permalink_state_schema import DashboardPermalinkStateSchema
from ...models.post_api_v1_dashboard_pk_permalink_response_201 import PostApiV1DashboardPkPermalinkResponse201
from ...models.post_api_v1_dashboard_pk_permalink_response_400 import PostApiV1DashboardPkPermalinkResponse400
from ...models.post_api_v1_dashboard_pk_permalink_response_401 import PostApiV1DashboardPkPermalinkResponse401
from ...models.post_api_v1_dashboard_pk_permalink_response_422 import PostApiV1DashboardPkPermalinkResponse422
from ...models.post_api_v1_dashboard_pk_permalink_response_500 import PostApiV1DashboardPkPermalinkResponse500
from ...types import Response


def _get_kwargs(
    pk: str,
    *,
    body: DashboardPermalinkStateSchema,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/dashboard/{pk}/permalink".format(
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
    PostApiV1DashboardPkPermalinkResponse201
    | PostApiV1DashboardPkPermalinkResponse400
    | PostApiV1DashboardPkPermalinkResponse401
    | PostApiV1DashboardPkPermalinkResponse422
    | PostApiV1DashboardPkPermalinkResponse500
    | None
):
    if response.status_code == 201:
        response_201 = PostApiV1DashboardPkPermalinkResponse201.from_dict(response.json())

        return response_201

    if response.status_code == 400:
        response_400 = PostApiV1DashboardPkPermalinkResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PostApiV1DashboardPkPermalinkResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 422:
        response_422 = PostApiV1DashboardPkPermalinkResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = PostApiV1DashboardPkPermalinkResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PostApiV1DashboardPkPermalinkResponse201
    | PostApiV1DashboardPkPermalinkResponse400
    | PostApiV1DashboardPkPermalinkResponse401
    | PostApiV1DashboardPkPermalinkResponse422
    | PostApiV1DashboardPkPermalinkResponse500
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    pk: str,
    *,
    client: AuthenticatedClient,
    body: DashboardPermalinkStateSchema,
) -> Response[
    PostApiV1DashboardPkPermalinkResponse201
    | PostApiV1DashboardPkPermalinkResponse400
    | PostApiV1DashboardPkPermalinkResponse401
    | PostApiV1DashboardPkPermalinkResponse422
    | PostApiV1DashboardPkPermalinkResponse500
]:
    """Create a new dashboard's permanent link

    Args:
        pk (str):
        body (DashboardPermalinkStateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1DashboardPkPermalinkResponse201 | PostApiV1DashboardPkPermalinkResponse400 | PostApiV1DashboardPkPermalinkResponse401 | PostApiV1DashboardPkPermalinkResponse422 | PostApiV1DashboardPkPermalinkResponse500]
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
    pk: str,
    *,
    client: AuthenticatedClient,
    body: DashboardPermalinkStateSchema,
) -> (
    PostApiV1DashboardPkPermalinkResponse201
    | PostApiV1DashboardPkPermalinkResponse400
    | PostApiV1DashboardPkPermalinkResponse401
    | PostApiV1DashboardPkPermalinkResponse422
    | PostApiV1DashboardPkPermalinkResponse500
    | None
):
    """Create a new dashboard's permanent link

    Args:
        pk (str):
        body (DashboardPermalinkStateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1DashboardPkPermalinkResponse201 | PostApiV1DashboardPkPermalinkResponse400 | PostApiV1DashboardPkPermalinkResponse401 | PostApiV1DashboardPkPermalinkResponse422 | PostApiV1DashboardPkPermalinkResponse500
    """

    return sync_detailed(
        pk=pk,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    pk: str,
    *,
    client: AuthenticatedClient,
    body: DashboardPermalinkStateSchema,
) -> Response[
    PostApiV1DashboardPkPermalinkResponse201
    | PostApiV1DashboardPkPermalinkResponse400
    | PostApiV1DashboardPkPermalinkResponse401
    | PostApiV1DashboardPkPermalinkResponse422
    | PostApiV1DashboardPkPermalinkResponse500
]:
    """Create a new dashboard's permanent link

    Args:
        pk (str):
        body (DashboardPermalinkStateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1DashboardPkPermalinkResponse201 | PostApiV1DashboardPkPermalinkResponse400 | PostApiV1DashboardPkPermalinkResponse401 | PostApiV1DashboardPkPermalinkResponse422 | PostApiV1DashboardPkPermalinkResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    pk: str,
    *,
    client: AuthenticatedClient,
    body: DashboardPermalinkStateSchema,
) -> (
    PostApiV1DashboardPkPermalinkResponse201
    | PostApiV1DashboardPkPermalinkResponse400
    | PostApiV1DashboardPkPermalinkResponse401
    | PostApiV1DashboardPkPermalinkResponse422
    | PostApiV1DashboardPkPermalinkResponse500
    | None
):
    """Create a new dashboard's permanent link

    Args:
        pk (str):
        body (DashboardPermalinkStateSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1DashboardPkPermalinkResponse201 | PostApiV1DashboardPkPermalinkResponse400 | PostApiV1DashboardPkPermalinkResponse401 | PostApiV1DashboardPkPermalinkResponse422 | PostApiV1DashboardPkPermalinkResponse500
    """

    return (
        await asyncio_detailed(
            pk=pk,
            client=client,
            body=body,
        )
    ).parsed
