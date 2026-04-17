from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_report_pk_log_log_id_response_200 import GetApiV1ReportPkLogLogIdResponse200
from ...models.get_api_v1_report_pk_log_log_id_response_400 import GetApiV1ReportPkLogLogIdResponse400
from ...models.get_api_v1_report_pk_log_log_id_response_401 import GetApiV1ReportPkLogLogIdResponse401
from ...models.get_api_v1_report_pk_log_log_id_response_404 import GetApiV1ReportPkLogLogIdResponse404
from ...models.get_api_v1_report_pk_log_log_id_response_422 import GetApiV1ReportPkLogLogIdResponse422
from ...models.get_api_v1_report_pk_log_log_id_response_500 import GetApiV1ReportPkLogLogIdResponse500
from ...types import Response


def _get_kwargs(
    pk: int,
    log_id: int,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/report/{pk}/log/{log_id}".format(
            pk=quote(str(pk), safe=""),
            log_id=quote(str(log_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetApiV1ReportPkLogLogIdResponse200
    | GetApiV1ReportPkLogLogIdResponse400
    | GetApiV1ReportPkLogLogIdResponse401
    | GetApiV1ReportPkLogLogIdResponse404
    | GetApiV1ReportPkLogLogIdResponse422
    | GetApiV1ReportPkLogLogIdResponse500
    | None
):
    if response.status_code == 200:
        response_200 = GetApiV1ReportPkLogLogIdResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = GetApiV1ReportPkLogLogIdResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = GetApiV1ReportPkLogLogIdResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = GetApiV1ReportPkLogLogIdResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 422:
        response_422 = GetApiV1ReportPkLogLogIdResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = GetApiV1ReportPkLogLogIdResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    GetApiV1ReportPkLogLogIdResponse200
    | GetApiV1ReportPkLogLogIdResponse400
    | GetApiV1ReportPkLogLogIdResponse401
    | GetApiV1ReportPkLogLogIdResponse404
    | GetApiV1ReportPkLogLogIdResponse422
    | GetApiV1ReportPkLogLogIdResponse500
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    pk: int,
    log_id: int,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetApiV1ReportPkLogLogIdResponse200
    | GetApiV1ReportPkLogLogIdResponse400
    | GetApiV1ReportPkLogLogIdResponse401
    | GetApiV1ReportPkLogLogIdResponse404
    | GetApiV1ReportPkLogLogIdResponse422
    | GetApiV1ReportPkLogLogIdResponse500
]:
    """Get a report schedule log

    Args:
        pk (int):
        log_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1ReportPkLogLogIdResponse200 | GetApiV1ReportPkLogLogIdResponse400 | GetApiV1ReportPkLogLogIdResponse401 | GetApiV1ReportPkLogLogIdResponse404 | GetApiV1ReportPkLogLogIdResponse422 | GetApiV1ReportPkLogLogIdResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
        log_id=log_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    pk: int,
    log_id: int,
    *,
    client: AuthenticatedClient,
) -> (
    GetApiV1ReportPkLogLogIdResponse200
    | GetApiV1ReportPkLogLogIdResponse400
    | GetApiV1ReportPkLogLogIdResponse401
    | GetApiV1ReportPkLogLogIdResponse404
    | GetApiV1ReportPkLogLogIdResponse422
    | GetApiV1ReportPkLogLogIdResponse500
    | None
):
    """Get a report schedule log

    Args:
        pk (int):
        log_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1ReportPkLogLogIdResponse200 | GetApiV1ReportPkLogLogIdResponse400 | GetApiV1ReportPkLogLogIdResponse401 | GetApiV1ReportPkLogLogIdResponse404 | GetApiV1ReportPkLogLogIdResponse422 | GetApiV1ReportPkLogLogIdResponse500
    """

    return sync_detailed(
        pk=pk,
        log_id=log_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    pk: int,
    log_id: int,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetApiV1ReportPkLogLogIdResponse200
    | GetApiV1ReportPkLogLogIdResponse400
    | GetApiV1ReportPkLogLogIdResponse401
    | GetApiV1ReportPkLogLogIdResponse404
    | GetApiV1ReportPkLogLogIdResponse422
    | GetApiV1ReportPkLogLogIdResponse500
]:
    """Get a report schedule log

    Args:
        pk (int):
        log_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1ReportPkLogLogIdResponse200 | GetApiV1ReportPkLogLogIdResponse400 | GetApiV1ReportPkLogLogIdResponse401 | GetApiV1ReportPkLogLogIdResponse404 | GetApiV1ReportPkLogLogIdResponse422 | GetApiV1ReportPkLogLogIdResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
        log_id=log_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    pk: int,
    log_id: int,
    *,
    client: AuthenticatedClient,
) -> (
    GetApiV1ReportPkLogLogIdResponse200
    | GetApiV1ReportPkLogLogIdResponse400
    | GetApiV1ReportPkLogLogIdResponse401
    | GetApiV1ReportPkLogLogIdResponse404
    | GetApiV1ReportPkLogLogIdResponse422
    | GetApiV1ReportPkLogLogIdResponse500
    | None
):
    """Get a report schedule log

    Args:
        pk (int):
        log_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1ReportPkLogLogIdResponse200 | GetApiV1ReportPkLogLogIdResponse400 | GetApiV1ReportPkLogLogIdResponse401 | GetApiV1ReportPkLogLogIdResponse404 | GetApiV1ReportPkLogLogIdResponse422 | GetApiV1ReportPkLogLogIdResponse500
    """

    return (
        await asyncio_detailed(
            pk=pk,
            log_id=log_id,
            client=client,
        )
    ).parsed
