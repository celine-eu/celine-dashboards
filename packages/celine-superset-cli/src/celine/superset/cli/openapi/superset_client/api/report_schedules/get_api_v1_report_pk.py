from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_report_pk_response_200 import GetApiV1ReportPkResponse200
from ...models.get_api_v1_report_pk_response_400 import GetApiV1ReportPkResponse400
from ...models.get_api_v1_report_pk_response_401 import GetApiV1ReportPkResponse401
from ...models.get_api_v1_report_pk_response_404 import GetApiV1ReportPkResponse404
from ...models.get_api_v1_report_pk_response_422 import GetApiV1ReportPkResponse422
from ...models.get_api_v1_report_pk_response_500 import GetApiV1ReportPkResponse500
from ...types import Response


def _get_kwargs(
    pk: int,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/report/{pk}".format(
            pk=quote(str(pk), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetApiV1ReportPkResponse200
    | GetApiV1ReportPkResponse400
    | GetApiV1ReportPkResponse401
    | GetApiV1ReportPkResponse404
    | GetApiV1ReportPkResponse422
    | GetApiV1ReportPkResponse500
    | None
):
    if response.status_code == 200:
        response_200 = GetApiV1ReportPkResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = GetApiV1ReportPkResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = GetApiV1ReportPkResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = GetApiV1ReportPkResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 422:
        response_422 = GetApiV1ReportPkResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = GetApiV1ReportPkResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    GetApiV1ReportPkResponse200
    | GetApiV1ReportPkResponse400
    | GetApiV1ReportPkResponse401
    | GetApiV1ReportPkResponse404
    | GetApiV1ReportPkResponse422
    | GetApiV1ReportPkResponse500
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
) -> Response[
    GetApiV1ReportPkResponse200
    | GetApiV1ReportPkResponse400
    | GetApiV1ReportPkResponse401
    | GetApiV1ReportPkResponse404
    | GetApiV1ReportPkResponse422
    | GetApiV1ReportPkResponse500
]:
    """Get a report schedule

     Get an item model

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1ReportPkResponse200 | GetApiV1ReportPkResponse400 | GetApiV1ReportPkResponse401 | GetApiV1ReportPkResponse404 | GetApiV1ReportPkResponse422 | GetApiV1ReportPkResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    pk: int,
    *,
    client: AuthenticatedClient,
) -> (
    GetApiV1ReportPkResponse200
    | GetApiV1ReportPkResponse400
    | GetApiV1ReportPkResponse401
    | GetApiV1ReportPkResponse404
    | GetApiV1ReportPkResponse422
    | GetApiV1ReportPkResponse500
    | None
):
    """Get a report schedule

     Get an item model

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1ReportPkResponse200 | GetApiV1ReportPkResponse400 | GetApiV1ReportPkResponse401 | GetApiV1ReportPkResponse404 | GetApiV1ReportPkResponse422 | GetApiV1ReportPkResponse500
    """

    return sync_detailed(
        pk=pk,
        client=client,
    ).parsed


async def asyncio_detailed(
    pk: int,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetApiV1ReportPkResponse200
    | GetApiV1ReportPkResponse400
    | GetApiV1ReportPkResponse401
    | GetApiV1ReportPkResponse404
    | GetApiV1ReportPkResponse422
    | GetApiV1ReportPkResponse500
]:
    """Get a report schedule

     Get an item model

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1ReportPkResponse200 | GetApiV1ReportPkResponse400 | GetApiV1ReportPkResponse401 | GetApiV1ReportPkResponse404 | GetApiV1ReportPkResponse422 | GetApiV1ReportPkResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    pk: int,
    *,
    client: AuthenticatedClient,
) -> (
    GetApiV1ReportPkResponse200
    | GetApiV1ReportPkResponse400
    | GetApiV1ReportPkResponse401
    | GetApiV1ReportPkResponse404
    | GetApiV1ReportPkResponse422
    | GetApiV1ReportPkResponse500
    | None
):
    """Get a report schedule

     Get an item model

    Args:
        pk (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1ReportPkResponse200 | GetApiV1ReportPkResponse400 | GetApiV1ReportPkResponse401 | GetApiV1ReportPkResponse404 | GetApiV1ReportPkResponse422 | GetApiV1ReportPkResponse500
    """

    return (
        await asyncio_detailed(
            pk=pk,
            client=client,
        )
    ).parsed
