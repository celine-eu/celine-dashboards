from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.dashboard_copy_schema import DashboardCopySchema
from ...models.post_api_v1_dashboard_id_or_slug_copy_response_200 import PostApiV1DashboardIdOrSlugCopyResponse200
from ...models.post_api_v1_dashboard_id_or_slug_copy_response_400 import PostApiV1DashboardIdOrSlugCopyResponse400
from ...models.post_api_v1_dashboard_id_or_slug_copy_response_401 import PostApiV1DashboardIdOrSlugCopyResponse401
from ...models.post_api_v1_dashboard_id_or_slug_copy_response_403 import PostApiV1DashboardIdOrSlugCopyResponse403
from ...models.post_api_v1_dashboard_id_or_slug_copy_response_404 import PostApiV1DashboardIdOrSlugCopyResponse404
from ...models.post_api_v1_dashboard_id_or_slug_copy_response_500 import PostApiV1DashboardIdOrSlugCopyResponse500
from ...types import Response


def _get_kwargs(
    id_or_slug: str,
    *,
    body: DashboardCopySchema,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/dashboard/{id_or_slug}/copy/".format(
            id_or_slug=quote(str(id_or_slug), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    PostApiV1DashboardIdOrSlugCopyResponse200
    | PostApiV1DashboardIdOrSlugCopyResponse400
    | PostApiV1DashboardIdOrSlugCopyResponse401
    | PostApiV1DashboardIdOrSlugCopyResponse403
    | PostApiV1DashboardIdOrSlugCopyResponse404
    | PostApiV1DashboardIdOrSlugCopyResponse500
    | None
):
    if response.status_code == 200:
        response_200 = PostApiV1DashboardIdOrSlugCopyResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = PostApiV1DashboardIdOrSlugCopyResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PostApiV1DashboardIdOrSlugCopyResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 403:
        response_403 = PostApiV1DashboardIdOrSlugCopyResponse403.from_dict(response.json())

        return response_403

    if response.status_code == 404:
        response_404 = PostApiV1DashboardIdOrSlugCopyResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 500:
        response_500 = PostApiV1DashboardIdOrSlugCopyResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PostApiV1DashboardIdOrSlugCopyResponse200
    | PostApiV1DashboardIdOrSlugCopyResponse400
    | PostApiV1DashboardIdOrSlugCopyResponse401
    | PostApiV1DashboardIdOrSlugCopyResponse403
    | PostApiV1DashboardIdOrSlugCopyResponse404
    | PostApiV1DashboardIdOrSlugCopyResponse500
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    id_or_slug: str,
    *,
    client: AuthenticatedClient,
    body: DashboardCopySchema,
) -> Response[
    PostApiV1DashboardIdOrSlugCopyResponse200
    | PostApiV1DashboardIdOrSlugCopyResponse400
    | PostApiV1DashboardIdOrSlugCopyResponse401
    | PostApiV1DashboardIdOrSlugCopyResponse403
    | PostApiV1DashboardIdOrSlugCopyResponse404
    | PostApiV1DashboardIdOrSlugCopyResponse500
]:
    """Create a copy of an existing dashboard

    Args:
        id_or_slug (str):
        body (DashboardCopySchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1DashboardIdOrSlugCopyResponse200 | PostApiV1DashboardIdOrSlugCopyResponse400 | PostApiV1DashboardIdOrSlugCopyResponse401 | PostApiV1DashboardIdOrSlugCopyResponse403 | PostApiV1DashboardIdOrSlugCopyResponse404 | PostApiV1DashboardIdOrSlugCopyResponse500]
    """

    kwargs = _get_kwargs(
        id_or_slug=id_or_slug,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    id_or_slug: str,
    *,
    client: AuthenticatedClient,
    body: DashboardCopySchema,
) -> (
    PostApiV1DashboardIdOrSlugCopyResponse200
    | PostApiV1DashboardIdOrSlugCopyResponse400
    | PostApiV1DashboardIdOrSlugCopyResponse401
    | PostApiV1DashboardIdOrSlugCopyResponse403
    | PostApiV1DashboardIdOrSlugCopyResponse404
    | PostApiV1DashboardIdOrSlugCopyResponse500
    | None
):
    """Create a copy of an existing dashboard

    Args:
        id_or_slug (str):
        body (DashboardCopySchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1DashboardIdOrSlugCopyResponse200 | PostApiV1DashboardIdOrSlugCopyResponse400 | PostApiV1DashboardIdOrSlugCopyResponse401 | PostApiV1DashboardIdOrSlugCopyResponse403 | PostApiV1DashboardIdOrSlugCopyResponse404 | PostApiV1DashboardIdOrSlugCopyResponse500
    """

    return sync_detailed(
        id_or_slug=id_or_slug,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    id_or_slug: str,
    *,
    client: AuthenticatedClient,
    body: DashboardCopySchema,
) -> Response[
    PostApiV1DashboardIdOrSlugCopyResponse200
    | PostApiV1DashboardIdOrSlugCopyResponse400
    | PostApiV1DashboardIdOrSlugCopyResponse401
    | PostApiV1DashboardIdOrSlugCopyResponse403
    | PostApiV1DashboardIdOrSlugCopyResponse404
    | PostApiV1DashboardIdOrSlugCopyResponse500
]:
    """Create a copy of an existing dashboard

    Args:
        id_or_slug (str):
        body (DashboardCopySchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1DashboardIdOrSlugCopyResponse200 | PostApiV1DashboardIdOrSlugCopyResponse400 | PostApiV1DashboardIdOrSlugCopyResponse401 | PostApiV1DashboardIdOrSlugCopyResponse403 | PostApiV1DashboardIdOrSlugCopyResponse404 | PostApiV1DashboardIdOrSlugCopyResponse500]
    """

    kwargs = _get_kwargs(
        id_or_slug=id_or_slug,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    id_or_slug: str,
    *,
    client: AuthenticatedClient,
    body: DashboardCopySchema,
) -> (
    PostApiV1DashboardIdOrSlugCopyResponse200
    | PostApiV1DashboardIdOrSlugCopyResponse400
    | PostApiV1DashboardIdOrSlugCopyResponse401
    | PostApiV1DashboardIdOrSlugCopyResponse403
    | PostApiV1DashboardIdOrSlugCopyResponse404
    | PostApiV1DashboardIdOrSlugCopyResponse500
    | None
):
    """Create a copy of an existing dashboard

    Args:
        id_or_slug (str):
        body (DashboardCopySchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1DashboardIdOrSlugCopyResponse200 | PostApiV1DashboardIdOrSlugCopyResponse400 | PostApiV1DashboardIdOrSlugCopyResponse401 | PostApiV1DashboardIdOrSlugCopyResponse403 | PostApiV1DashboardIdOrSlugCopyResponse404 | PostApiV1DashboardIdOrSlugCopyResponse500
    """

    return (
        await asyncio_detailed(
            id_or_slug=id_or_slug,
            client=client,
            body=body,
        )
    ).parsed
