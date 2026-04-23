from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.estimate_query_cost_schema import EstimateQueryCostSchema
from ...models.post_api_v1_sqllab_estimate_response_200 import PostApiV1SqllabEstimateResponse200
from ...models.post_api_v1_sqllab_estimate_response_400 import PostApiV1SqllabEstimateResponse400
from ...models.post_api_v1_sqllab_estimate_response_401 import PostApiV1SqllabEstimateResponse401
from ...models.post_api_v1_sqllab_estimate_response_403 import PostApiV1SqllabEstimateResponse403
from ...models.post_api_v1_sqllab_estimate_response_500 import PostApiV1SqllabEstimateResponse500
from ...types import Response


def _get_kwargs(
    *,
    body: EstimateQueryCostSchema,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/sqllab/estimate/",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    PostApiV1SqllabEstimateResponse200
    | PostApiV1SqllabEstimateResponse400
    | PostApiV1SqllabEstimateResponse401
    | PostApiV1SqllabEstimateResponse403
    | PostApiV1SqllabEstimateResponse500
    | None
):
    if response.status_code == 200:
        response_200 = PostApiV1SqllabEstimateResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = PostApiV1SqllabEstimateResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PostApiV1SqllabEstimateResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 403:
        response_403 = PostApiV1SqllabEstimateResponse403.from_dict(response.json())

        return response_403

    if response.status_code == 500:
        response_500 = PostApiV1SqllabEstimateResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PostApiV1SqllabEstimateResponse200
    | PostApiV1SqllabEstimateResponse400
    | PostApiV1SqllabEstimateResponse401
    | PostApiV1SqllabEstimateResponse403
    | PostApiV1SqllabEstimateResponse500
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
    body: EstimateQueryCostSchema,
) -> Response[
    PostApiV1SqllabEstimateResponse200
    | PostApiV1SqllabEstimateResponse400
    | PostApiV1SqllabEstimateResponse401
    | PostApiV1SqllabEstimateResponse403
    | PostApiV1SqllabEstimateResponse500
]:
    """Estimate the SQL query execution cost

    Args:
        body (EstimateQueryCostSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1SqllabEstimateResponse200 | PostApiV1SqllabEstimateResponse400 | PostApiV1SqllabEstimateResponse401 | PostApiV1SqllabEstimateResponse403 | PostApiV1SqllabEstimateResponse500]
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
    body: EstimateQueryCostSchema,
) -> (
    PostApiV1SqllabEstimateResponse200
    | PostApiV1SqllabEstimateResponse400
    | PostApiV1SqllabEstimateResponse401
    | PostApiV1SqllabEstimateResponse403
    | PostApiV1SqllabEstimateResponse500
    | None
):
    """Estimate the SQL query execution cost

    Args:
        body (EstimateQueryCostSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1SqllabEstimateResponse200 | PostApiV1SqllabEstimateResponse400 | PostApiV1SqllabEstimateResponse401 | PostApiV1SqllabEstimateResponse403 | PostApiV1SqllabEstimateResponse500
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: EstimateQueryCostSchema,
) -> Response[
    PostApiV1SqllabEstimateResponse200
    | PostApiV1SqllabEstimateResponse400
    | PostApiV1SqllabEstimateResponse401
    | PostApiV1SqllabEstimateResponse403
    | PostApiV1SqllabEstimateResponse500
]:
    """Estimate the SQL query execution cost

    Args:
        body (EstimateQueryCostSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1SqllabEstimateResponse200 | PostApiV1SqllabEstimateResponse400 | PostApiV1SqllabEstimateResponse401 | PostApiV1SqllabEstimateResponse403 | PostApiV1SqllabEstimateResponse500]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: EstimateQueryCostSchema,
) -> (
    PostApiV1SqllabEstimateResponse200
    | PostApiV1SqllabEstimateResponse400
    | PostApiV1SqllabEstimateResponse401
    | PostApiV1SqllabEstimateResponse403
    | PostApiV1SqllabEstimateResponse500
    | None
):
    """Estimate the SQL query execution cost

    Args:
        body (EstimateQueryCostSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1SqllabEstimateResponse200 | PostApiV1SqllabEstimateResponse400 | PostApiV1SqllabEstimateResponse401 | PostApiV1SqllabEstimateResponse403 | PostApiV1SqllabEstimateResponse500
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
