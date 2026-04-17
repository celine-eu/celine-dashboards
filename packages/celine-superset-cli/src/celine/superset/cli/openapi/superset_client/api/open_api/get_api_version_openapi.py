from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_version_openapi_response_200 import GetApiVersionOpenapiResponse200
from ...models.get_api_version_openapi_response_404 import GetApiVersionOpenapiResponse404
from ...models.get_api_version_openapi_response_500 import GetApiVersionOpenapiResponse500
from ...types import Response


def _get_kwargs(
    version: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/{version}/_openapi".format(
            version=quote(str(version), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GetApiVersionOpenapiResponse200 | GetApiVersionOpenapiResponse404 | GetApiVersionOpenapiResponse500 | None:
    if response.status_code == 200:
        response_200 = GetApiVersionOpenapiResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 404:
        response_404 = GetApiVersionOpenapiResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 500:
        response_500 = GetApiVersionOpenapiResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[GetApiVersionOpenapiResponse200 | GetApiVersionOpenapiResponse404 | GetApiVersionOpenapiResponse500]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    version: str,
    *,
    client: AuthenticatedClient,
) -> Response[GetApiVersionOpenapiResponse200 | GetApiVersionOpenapiResponse404 | GetApiVersionOpenapiResponse500]:
    """Get the OpenAPI spec for a specific API version

    Args:
        version (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiVersionOpenapiResponse200 | GetApiVersionOpenapiResponse404 | GetApiVersionOpenapiResponse500]
    """

    kwargs = _get_kwargs(
        version=version,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    version: str,
    *,
    client: AuthenticatedClient,
) -> GetApiVersionOpenapiResponse200 | GetApiVersionOpenapiResponse404 | GetApiVersionOpenapiResponse500 | None:
    """Get the OpenAPI spec for a specific API version

    Args:
        version (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiVersionOpenapiResponse200 | GetApiVersionOpenapiResponse404 | GetApiVersionOpenapiResponse500
    """

    return sync_detailed(
        version=version,
        client=client,
    ).parsed


async def asyncio_detailed(
    version: str,
    *,
    client: AuthenticatedClient,
) -> Response[GetApiVersionOpenapiResponse200 | GetApiVersionOpenapiResponse404 | GetApiVersionOpenapiResponse500]:
    """Get the OpenAPI spec for a specific API version

    Args:
        version (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiVersionOpenapiResponse200 | GetApiVersionOpenapiResponse404 | GetApiVersionOpenapiResponse500]
    """

    kwargs = _get_kwargs(
        version=version,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    version: str,
    *,
    client: AuthenticatedClient,
) -> GetApiVersionOpenapiResponse200 | GetApiVersionOpenapiResponse404 | GetApiVersionOpenapiResponse500 | None:
    """Get the OpenAPI spec for a specific API version

    Args:
        version (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiVersionOpenapiResponse200 | GetApiVersionOpenapiResponse404 | GetApiVersionOpenapiResponse500
    """

    return (
        await asyncio_detailed(
            version=version,
            client=client,
        )
    ).parsed
