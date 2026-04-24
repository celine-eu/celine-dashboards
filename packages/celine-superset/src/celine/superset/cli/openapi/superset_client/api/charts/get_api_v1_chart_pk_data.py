from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.chart_data_async_response_schema import ChartDataAsyncResponseSchema
from ...models.chart_data_response_schema import ChartDataResponseSchema
from ...models.get_api_v1_chart_pk_data_response_400 import GetApiV1ChartPkDataResponse400
from ...models.get_api_v1_chart_pk_data_response_401 import GetApiV1ChartPkDataResponse401
from ...models.get_api_v1_chart_pk_data_response_500 import GetApiV1ChartPkDataResponse500
from ...types import UNSET, Response, Unset


def _get_kwargs(
    pk: int,
    *,
    format_: str | Unset = UNSET,
    type_: str | Unset = UNSET,
    force: bool | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["format"] = format_

    params["type"] = type_

    params["force"] = force

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/chart/{pk}/data/".format(
            pk=quote(str(pk), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    ChartDataAsyncResponseSchema
    | ChartDataResponseSchema
    | GetApiV1ChartPkDataResponse400
    | GetApiV1ChartPkDataResponse401
    | GetApiV1ChartPkDataResponse500
    | None
):
    if response.status_code == 200:
        response_200 = ChartDataResponseSchema.from_dict(response.json())

        return response_200

    if response.status_code == 202:
        response_202 = ChartDataAsyncResponseSchema.from_dict(response.json())

        return response_202

    if response.status_code == 400:
        response_400 = GetApiV1ChartPkDataResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = GetApiV1ChartPkDataResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 500:
        response_500 = GetApiV1ChartPkDataResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    ChartDataAsyncResponseSchema
    | ChartDataResponseSchema
    | GetApiV1ChartPkDataResponse400
    | GetApiV1ChartPkDataResponse401
    | GetApiV1ChartPkDataResponse500
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
    format_: str | Unset = UNSET,
    type_: str | Unset = UNSET,
    force: bool | Unset = UNSET,
) -> Response[
    ChartDataAsyncResponseSchema
    | ChartDataResponseSchema
    | GetApiV1ChartPkDataResponse400
    | GetApiV1ChartPkDataResponse401
    | GetApiV1ChartPkDataResponse500
]:
    """Return payload data response for a chart

     Takes a chart ID and uses the query context stored when the chart was saved to return payload data
    response.

    Args:
        pk (int):
        format_ (str | Unset):
        type_ (str | Unset):
        force (bool | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ChartDataAsyncResponseSchema | ChartDataResponseSchema | GetApiV1ChartPkDataResponse400 | GetApiV1ChartPkDataResponse401 | GetApiV1ChartPkDataResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
        format_=format_,
        type_=type_,
        force=force,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    pk: int,
    *,
    client: AuthenticatedClient,
    format_: str | Unset = UNSET,
    type_: str | Unset = UNSET,
    force: bool | Unset = UNSET,
) -> (
    ChartDataAsyncResponseSchema
    | ChartDataResponseSchema
    | GetApiV1ChartPkDataResponse400
    | GetApiV1ChartPkDataResponse401
    | GetApiV1ChartPkDataResponse500
    | None
):
    """Return payload data response for a chart

     Takes a chart ID and uses the query context stored when the chart was saved to return payload data
    response.

    Args:
        pk (int):
        format_ (str | Unset):
        type_ (str | Unset):
        force (bool | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ChartDataAsyncResponseSchema | ChartDataResponseSchema | GetApiV1ChartPkDataResponse400 | GetApiV1ChartPkDataResponse401 | GetApiV1ChartPkDataResponse500
    """

    return sync_detailed(
        pk=pk,
        client=client,
        format_=format_,
        type_=type_,
        force=force,
    ).parsed


async def asyncio_detailed(
    pk: int,
    *,
    client: AuthenticatedClient,
    format_: str | Unset = UNSET,
    type_: str | Unset = UNSET,
    force: bool | Unset = UNSET,
) -> Response[
    ChartDataAsyncResponseSchema
    | ChartDataResponseSchema
    | GetApiV1ChartPkDataResponse400
    | GetApiV1ChartPkDataResponse401
    | GetApiV1ChartPkDataResponse500
]:
    """Return payload data response for a chart

     Takes a chart ID and uses the query context stored when the chart was saved to return payload data
    response.

    Args:
        pk (int):
        format_ (str | Unset):
        type_ (str | Unset):
        force (bool | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ChartDataAsyncResponseSchema | ChartDataResponseSchema | GetApiV1ChartPkDataResponse400 | GetApiV1ChartPkDataResponse401 | GetApiV1ChartPkDataResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
        format_=format_,
        type_=type_,
        force=force,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    pk: int,
    *,
    client: AuthenticatedClient,
    format_: str | Unset = UNSET,
    type_: str | Unset = UNSET,
    force: bool | Unset = UNSET,
) -> (
    ChartDataAsyncResponseSchema
    | ChartDataResponseSchema
    | GetApiV1ChartPkDataResponse400
    | GetApiV1ChartPkDataResponse401
    | GetApiV1ChartPkDataResponse500
    | None
):
    """Return payload data response for a chart

     Takes a chart ID and uses the query context stored when the chart was saved to return payload data
    response.

    Args:
        pk (int):
        format_ (str | Unset):
        type_ (str | Unset):
        force (bool | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ChartDataAsyncResponseSchema | ChartDataResponseSchema | GetApiV1ChartPkDataResponse400 | GetApiV1ChartPkDataResponse401 | GetApiV1ChartPkDataResponse500
    """

    return (
        await asyncio_detailed(
            pk=pk,
            client=client,
            format_=format_,
            type_=type_,
            force=force,
        )
    ).parsed
