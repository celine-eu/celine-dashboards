from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_report_slack_channels_response_200 import GetApiV1ReportSlackChannelsResponse200
from ...models.get_api_v1_report_slack_channels_response_401 import GetApiV1ReportSlackChannelsResponse401
from ...models.get_api_v1_report_slack_channels_response_403 import GetApiV1ReportSlackChannelsResponse403
from ...models.get_api_v1_report_slack_channels_response_404 import GetApiV1ReportSlackChannelsResponse404
from ...models.get_api_v1_report_slack_channels_response_422 import GetApiV1ReportSlackChannelsResponse422
from ...models.get_api_v1_report_slack_channels_response_500 import GetApiV1ReportSlackChannelsResponse500
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/report/slack_channels/",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetApiV1ReportSlackChannelsResponse200
    | GetApiV1ReportSlackChannelsResponse401
    | GetApiV1ReportSlackChannelsResponse403
    | GetApiV1ReportSlackChannelsResponse404
    | GetApiV1ReportSlackChannelsResponse422
    | GetApiV1ReportSlackChannelsResponse500
    | None
):
    if response.status_code == 200:
        response_200 = GetApiV1ReportSlackChannelsResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 401:
        response_401 = GetApiV1ReportSlackChannelsResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 403:
        response_403 = GetApiV1ReportSlackChannelsResponse403.from_dict(response.json())

        return response_403

    if response.status_code == 404:
        response_404 = GetApiV1ReportSlackChannelsResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 422:
        response_422 = GetApiV1ReportSlackChannelsResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = GetApiV1ReportSlackChannelsResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    GetApiV1ReportSlackChannelsResponse200
    | GetApiV1ReportSlackChannelsResponse401
    | GetApiV1ReportSlackChannelsResponse403
    | GetApiV1ReportSlackChannelsResponse404
    | GetApiV1ReportSlackChannelsResponse422
    | GetApiV1ReportSlackChannelsResponse500
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[
    GetApiV1ReportSlackChannelsResponse200
    | GetApiV1ReportSlackChannelsResponse401
    | GetApiV1ReportSlackChannelsResponse403
    | GetApiV1ReportSlackChannelsResponse404
    | GetApiV1ReportSlackChannelsResponse422
    | GetApiV1ReportSlackChannelsResponse500
]:
    """Get slack channels

     Get slack channels

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1ReportSlackChannelsResponse200 | GetApiV1ReportSlackChannelsResponse401 | GetApiV1ReportSlackChannelsResponse403 | GetApiV1ReportSlackChannelsResponse404 | GetApiV1ReportSlackChannelsResponse422 | GetApiV1ReportSlackChannelsResponse500]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> (
    GetApiV1ReportSlackChannelsResponse200
    | GetApiV1ReportSlackChannelsResponse401
    | GetApiV1ReportSlackChannelsResponse403
    | GetApiV1ReportSlackChannelsResponse404
    | GetApiV1ReportSlackChannelsResponse422
    | GetApiV1ReportSlackChannelsResponse500
    | None
):
    """Get slack channels

     Get slack channels

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1ReportSlackChannelsResponse200 | GetApiV1ReportSlackChannelsResponse401 | GetApiV1ReportSlackChannelsResponse403 | GetApiV1ReportSlackChannelsResponse404 | GetApiV1ReportSlackChannelsResponse422 | GetApiV1ReportSlackChannelsResponse500
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[
    GetApiV1ReportSlackChannelsResponse200
    | GetApiV1ReportSlackChannelsResponse401
    | GetApiV1ReportSlackChannelsResponse403
    | GetApiV1ReportSlackChannelsResponse404
    | GetApiV1ReportSlackChannelsResponse422
    | GetApiV1ReportSlackChannelsResponse500
]:
    """Get slack channels

     Get slack channels

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1ReportSlackChannelsResponse200 | GetApiV1ReportSlackChannelsResponse401 | GetApiV1ReportSlackChannelsResponse403 | GetApiV1ReportSlackChannelsResponse404 | GetApiV1ReportSlackChannelsResponse422 | GetApiV1ReportSlackChannelsResponse500]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> (
    GetApiV1ReportSlackChannelsResponse200
    | GetApiV1ReportSlackChannelsResponse401
    | GetApiV1ReportSlackChannelsResponse403
    | GetApiV1ReportSlackChannelsResponse404
    | GetApiV1ReportSlackChannelsResponse422
    | GetApiV1ReportSlackChannelsResponse500
    | None
):
    """Get slack channels

     Get slack channels

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1ReportSlackChannelsResponse200 | GetApiV1ReportSlackChannelsResponse401 | GetApiV1ReportSlackChannelsResponse403 | GetApiV1ReportSlackChannelsResponse404 | GetApiV1ReportSlackChannelsResponse422 | GetApiV1ReportSlackChannelsResponse500
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
