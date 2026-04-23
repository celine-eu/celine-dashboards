from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_security_roles_search_q import GetApiV1SecurityRolesSearchQ
from ...models.get_api_v1_security_roles_search_response_400 import GetApiV1SecurityRolesSearchResponse400
from ...models.get_api_v1_security_roles_search_response_403 import GetApiV1SecurityRolesSearchResponse403
from ...models.roles_response_schema import RolesResponseSchema
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    q: GetApiV1SecurityRolesSearchQ | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_q: dict[str, Any] | Unset = UNSET
    if not isinstance(q, Unset):
        json_q = q.to_dict()
    if not isinstance(json_q, Unset):
        params.update(json_q)

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/security/roles/search/",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GetApiV1SecurityRolesSearchResponse400 | GetApiV1SecurityRolesSearchResponse403 | RolesResponseSchema | None:
    if response.status_code == 200:
        response_200 = RolesResponseSchema.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = GetApiV1SecurityRolesSearchResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 403:
        response_403 = GetApiV1SecurityRolesSearchResponse403.from_dict(response.json())

        return response_403

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[GetApiV1SecurityRolesSearchResponse400 | GetApiV1SecurityRolesSearchResponse403 | RolesResponseSchema]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    q: GetApiV1SecurityRolesSearchQ | Unset = UNSET,
) -> Response[GetApiV1SecurityRolesSearchResponse400 | GetApiV1SecurityRolesSearchResponse403 | RolesResponseSchema]:
    """List roles

     Fetch a paginated list of roles with user and permission IDs.

    Args:
        q (GetApiV1SecurityRolesSearchQ | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1SecurityRolesSearchResponse400 | GetApiV1SecurityRolesSearchResponse403 | RolesResponseSchema]
    """

    kwargs = _get_kwargs(
        q=q,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    q: GetApiV1SecurityRolesSearchQ | Unset = UNSET,
) -> GetApiV1SecurityRolesSearchResponse400 | GetApiV1SecurityRolesSearchResponse403 | RolesResponseSchema | None:
    """List roles

     Fetch a paginated list of roles with user and permission IDs.

    Args:
        q (GetApiV1SecurityRolesSearchQ | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1SecurityRolesSearchResponse400 | GetApiV1SecurityRolesSearchResponse403 | RolesResponseSchema
    """

    return sync_detailed(
        client=client,
        q=q,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    q: GetApiV1SecurityRolesSearchQ | Unset = UNSET,
) -> Response[GetApiV1SecurityRolesSearchResponse400 | GetApiV1SecurityRolesSearchResponse403 | RolesResponseSchema]:
    """List roles

     Fetch a paginated list of roles with user and permission IDs.

    Args:
        q (GetApiV1SecurityRolesSearchQ | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1SecurityRolesSearchResponse400 | GetApiV1SecurityRolesSearchResponse403 | RolesResponseSchema]
    """

    kwargs = _get_kwargs(
        q=q,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    q: GetApiV1SecurityRolesSearchQ | Unset = UNSET,
) -> GetApiV1SecurityRolesSearchResponse400 | GetApiV1SecurityRolesSearchResponse403 | RolesResponseSchema | None:
    """List roles

     Fetch a paginated list of roles with user and permission IDs.

    Args:
        q (GetApiV1SecurityRolesSearchQ | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1SecurityRolesSearchResponse400 | GetApiV1SecurityRolesSearchResponse403 | RolesResponseSchema
    """

    return (
        await asyncio_detailed(
            client=client,
            q=q,
        )
    ).parsed
