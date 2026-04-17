from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_explore_permalink_key_response_200 import GetApiV1ExplorePermalinkKeyResponse200
from ...models.get_api_v1_explore_permalink_key_response_400 import GetApiV1ExplorePermalinkKeyResponse400
from ...models.get_api_v1_explore_permalink_key_response_401 import GetApiV1ExplorePermalinkKeyResponse401
from ...models.get_api_v1_explore_permalink_key_response_404 import GetApiV1ExplorePermalinkKeyResponse404
from ...models.get_api_v1_explore_permalink_key_response_422 import GetApiV1ExplorePermalinkKeyResponse422
from ...models.get_api_v1_explore_permalink_key_response_500 import GetApiV1ExplorePermalinkKeyResponse500
from ...types import Response


def _get_kwargs(
    key: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/explore/permalink/{key}".format(
            key=quote(str(key), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetApiV1ExplorePermalinkKeyResponse200
    | GetApiV1ExplorePermalinkKeyResponse400
    | GetApiV1ExplorePermalinkKeyResponse401
    | GetApiV1ExplorePermalinkKeyResponse404
    | GetApiV1ExplorePermalinkKeyResponse422
    | GetApiV1ExplorePermalinkKeyResponse500
    | None
):
    if response.status_code == 200:
        response_200 = GetApiV1ExplorePermalinkKeyResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = GetApiV1ExplorePermalinkKeyResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = GetApiV1ExplorePermalinkKeyResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = GetApiV1ExplorePermalinkKeyResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 422:
        response_422 = GetApiV1ExplorePermalinkKeyResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = GetApiV1ExplorePermalinkKeyResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    GetApiV1ExplorePermalinkKeyResponse200
    | GetApiV1ExplorePermalinkKeyResponse400
    | GetApiV1ExplorePermalinkKeyResponse401
    | GetApiV1ExplorePermalinkKeyResponse404
    | GetApiV1ExplorePermalinkKeyResponse422
    | GetApiV1ExplorePermalinkKeyResponse500
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    key: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetApiV1ExplorePermalinkKeyResponse200
    | GetApiV1ExplorePermalinkKeyResponse400
    | GetApiV1ExplorePermalinkKeyResponse401
    | GetApiV1ExplorePermalinkKeyResponse404
    | GetApiV1ExplorePermalinkKeyResponse422
    | GetApiV1ExplorePermalinkKeyResponse500
]:
    """Get chart's permanent link state

    Args:
        key (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1ExplorePermalinkKeyResponse200 | GetApiV1ExplorePermalinkKeyResponse400 | GetApiV1ExplorePermalinkKeyResponse401 | GetApiV1ExplorePermalinkKeyResponse404 | GetApiV1ExplorePermalinkKeyResponse422 | GetApiV1ExplorePermalinkKeyResponse500]
    """

    kwargs = _get_kwargs(
        key=key,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    key: str,
    *,
    client: AuthenticatedClient,
) -> (
    GetApiV1ExplorePermalinkKeyResponse200
    | GetApiV1ExplorePermalinkKeyResponse400
    | GetApiV1ExplorePermalinkKeyResponse401
    | GetApiV1ExplorePermalinkKeyResponse404
    | GetApiV1ExplorePermalinkKeyResponse422
    | GetApiV1ExplorePermalinkKeyResponse500
    | None
):
    """Get chart's permanent link state

    Args:
        key (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1ExplorePermalinkKeyResponse200 | GetApiV1ExplorePermalinkKeyResponse400 | GetApiV1ExplorePermalinkKeyResponse401 | GetApiV1ExplorePermalinkKeyResponse404 | GetApiV1ExplorePermalinkKeyResponse422 | GetApiV1ExplorePermalinkKeyResponse500
    """

    return sync_detailed(
        key=key,
        client=client,
    ).parsed


async def asyncio_detailed(
    key: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetApiV1ExplorePermalinkKeyResponse200
    | GetApiV1ExplorePermalinkKeyResponse400
    | GetApiV1ExplorePermalinkKeyResponse401
    | GetApiV1ExplorePermalinkKeyResponse404
    | GetApiV1ExplorePermalinkKeyResponse422
    | GetApiV1ExplorePermalinkKeyResponse500
]:
    """Get chart's permanent link state

    Args:
        key (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1ExplorePermalinkKeyResponse200 | GetApiV1ExplorePermalinkKeyResponse400 | GetApiV1ExplorePermalinkKeyResponse401 | GetApiV1ExplorePermalinkKeyResponse404 | GetApiV1ExplorePermalinkKeyResponse422 | GetApiV1ExplorePermalinkKeyResponse500]
    """

    kwargs = _get_kwargs(
        key=key,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    key: str,
    *,
    client: AuthenticatedClient,
) -> (
    GetApiV1ExplorePermalinkKeyResponse200
    | GetApiV1ExplorePermalinkKeyResponse400
    | GetApiV1ExplorePermalinkKeyResponse401
    | GetApiV1ExplorePermalinkKeyResponse404
    | GetApiV1ExplorePermalinkKeyResponse422
    | GetApiV1ExplorePermalinkKeyResponse500
    | None
):
    """Get chart's permanent link state

    Args:
        key (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1ExplorePermalinkKeyResponse200 | GetApiV1ExplorePermalinkKeyResponse400 | GetApiV1ExplorePermalinkKeyResponse401 | GetApiV1ExplorePermalinkKeyResponse404 | GetApiV1ExplorePermalinkKeyResponse422 | GetApiV1ExplorePermalinkKeyResponse500
    """

    return (
        await asyncio_detailed(
            key=key,
            client=client,
        )
    ).parsed
