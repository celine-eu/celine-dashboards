from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.post_api_v1_report_response_201 import PostApiV1ReportResponse201
from ...models.post_api_v1_report_response_400 import PostApiV1ReportResponse400
from ...models.post_api_v1_report_response_401 import PostApiV1ReportResponse401
from ...models.post_api_v1_report_response_404 import PostApiV1ReportResponse404
from ...models.post_api_v1_report_response_422 import PostApiV1ReportResponse422
from ...models.post_api_v1_report_response_500 import PostApiV1ReportResponse500
from ...models.report_schedule_rest_api_post import ReportScheduleRestApiPost
from ...types import Response


def _get_kwargs(
    *,
    body: ReportScheduleRestApiPost,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/report/",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    PostApiV1ReportResponse201
    | PostApiV1ReportResponse400
    | PostApiV1ReportResponse401
    | PostApiV1ReportResponse404
    | PostApiV1ReportResponse422
    | PostApiV1ReportResponse500
    | None
):
    if response.status_code == 201:
        response_201 = PostApiV1ReportResponse201.from_dict(response.json())

        return response_201

    if response.status_code == 400:
        response_400 = PostApiV1ReportResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PostApiV1ReportResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = PostApiV1ReportResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 422:
        response_422 = PostApiV1ReportResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = PostApiV1ReportResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PostApiV1ReportResponse201
    | PostApiV1ReportResponse400
    | PostApiV1ReportResponse401
    | PostApiV1ReportResponse404
    | PostApiV1ReportResponse422
    | PostApiV1ReportResponse500
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
    body: ReportScheduleRestApiPost,
) -> Response[
    PostApiV1ReportResponse201
    | PostApiV1ReportResponse400
    | PostApiV1ReportResponse401
    | PostApiV1ReportResponse404
    | PostApiV1ReportResponse422
    | PostApiV1ReportResponse500
]:
    """Create a report schedule

    Args:
        body (ReportScheduleRestApiPost):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1ReportResponse201 | PostApiV1ReportResponse400 | PostApiV1ReportResponse401 | PostApiV1ReportResponse404 | PostApiV1ReportResponse422 | PostApiV1ReportResponse500]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: ReportScheduleRestApiPost,
) -> (
    PostApiV1ReportResponse201
    | PostApiV1ReportResponse400
    | PostApiV1ReportResponse401
    | PostApiV1ReportResponse404
    | PostApiV1ReportResponse422
    | PostApiV1ReportResponse500
    | None
):
    """Create a report schedule

    Args:
        body (ReportScheduleRestApiPost):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1ReportResponse201 | PostApiV1ReportResponse400 | PostApiV1ReportResponse401 | PostApiV1ReportResponse404 | PostApiV1ReportResponse422 | PostApiV1ReportResponse500
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: ReportScheduleRestApiPost,
) -> Response[
    PostApiV1ReportResponse201
    | PostApiV1ReportResponse400
    | PostApiV1ReportResponse401
    | PostApiV1ReportResponse404
    | PostApiV1ReportResponse422
    | PostApiV1ReportResponse500
]:
    """Create a report schedule

    Args:
        body (ReportScheduleRestApiPost):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1ReportResponse201 | PostApiV1ReportResponse400 | PostApiV1ReportResponse401 | PostApiV1ReportResponse404 | PostApiV1ReportResponse422 | PostApiV1ReportResponse500]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: ReportScheduleRestApiPost,
) -> (
    PostApiV1ReportResponse201
    | PostApiV1ReportResponse400
    | PostApiV1ReportResponse401
    | PostApiV1ReportResponse404
    | PostApiV1ReportResponse422
    | PostApiV1ReportResponse500
    | None
):
    """Create a report schedule

    Args:
        body (ReportScheduleRestApiPost):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1ReportResponse201 | PostApiV1ReportResponse400 | PostApiV1ReportResponse401 | PostApiV1ReportResponse404 | PostApiV1ReportResponse422 | PostApiV1ReportResponse500
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
