from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.form_data_post_schema import FormDataPostSchema
from ...models.post_api_v1_explore_form_data_response_201 import PostApiV1ExploreFormDataResponse201
from ...models.post_api_v1_explore_form_data_response_400 import PostApiV1ExploreFormDataResponse400
from ...models.post_api_v1_explore_form_data_response_401 import PostApiV1ExploreFormDataResponse401
from ...models.post_api_v1_explore_form_data_response_422 import PostApiV1ExploreFormDataResponse422
from ...models.post_api_v1_explore_form_data_response_500 import PostApiV1ExploreFormDataResponse500
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    body: FormDataPostSchema,
    tab_id: int | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    params: dict[str, Any] = {}

    params["tab_id"] = tab_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/explore/form_data",
        "params": params,
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    PostApiV1ExploreFormDataResponse201
    | PostApiV1ExploreFormDataResponse400
    | PostApiV1ExploreFormDataResponse401
    | PostApiV1ExploreFormDataResponse422
    | PostApiV1ExploreFormDataResponse500
    | None
):
    if response.status_code == 201:
        response_201 = PostApiV1ExploreFormDataResponse201.from_dict(response.json())

        return response_201

    if response.status_code == 400:
        response_400 = PostApiV1ExploreFormDataResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PostApiV1ExploreFormDataResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 422:
        response_422 = PostApiV1ExploreFormDataResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = PostApiV1ExploreFormDataResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PostApiV1ExploreFormDataResponse201
    | PostApiV1ExploreFormDataResponse400
    | PostApiV1ExploreFormDataResponse401
    | PostApiV1ExploreFormDataResponse422
    | PostApiV1ExploreFormDataResponse500
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
    body: FormDataPostSchema,
    tab_id: int | Unset = UNSET,
) -> Response[
    PostApiV1ExploreFormDataResponse201
    | PostApiV1ExploreFormDataResponse400
    | PostApiV1ExploreFormDataResponse401
    | PostApiV1ExploreFormDataResponse422
    | PostApiV1ExploreFormDataResponse500
]:
    """Create a new form_data

    Args:
        tab_id (int | Unset):
        body (FormDataPostSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1ExploreFormDataResponse201 | PostApiV1ExploreFormDataResponse400 | PostApiV1ExploreFormDataResponse401 | PostApiV1ExploreFormDataResponse422 | PostApiV1ExploreFormDataResponse500]
    """

    kwargs = _get_kwargs(
        body=body,
        tab_id=tab_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: FormDataPostSchema,
    tab_id: int | Unset = UNSET,
) -> (
    PostApiV1ExploreFormDataResponse201
    | PostApiV1ExploreFormDataResponse400
    | PostApiV1ExploreFormDataResponse401
    | PostApiV1ExploreFormDataResponse422
    | PostApiV1ExploreFormDataResponse500
    | None
):
    """Create a new form_data

    Args:
        tab_id (int | Unset):
        body (FormDataPostSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1ExploreFormDataResponse201 | PostApiV1ExploreFormDataResponse400 | PostApiV1ExploreFormDataResponse401 | PostApiV1ExploreFormDataResponse422 | PostApiV1ExploreFormDataResponse500
    """

    return sync_detailed(
        client=client,
        body=body,
        tab_id=tab_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: FormDataPostSchema,
    tab_id: int | Unset = UNSET,
) -> Response[
    PostApiV1ExploreFormDataResponse201
    | PostApiV1ExploreFormDataResponse400
    | PostApiV1ExploreFormDataResponse401
    | PostApiV1ExploreFormDataResponse422
    | PostApiV1ExploreFormDataResponse500
]:
    """Create a new form_data

    Args:
        tab_id (int | Unset):
        body (FormDataPostSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostApiV1ExploreFormDataResponse201 | PostApiV1ExploreFormDataResponse400 | PostApiV1ExploreFormDataResponse401 | PostApiV1ExploreFormDataResponse422 | PostApiV1ExploreFormDataResponse500]
    """

    kwargs = _get_kwargs(
        body=body,
        tab_id=tab_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: FormDataPostSchema,
    tab_id: int | Unset = UNSET,
) -> (
    PostApiV1ExploreFormDataResponse201
    | PostApiV1ExploreFormDataResponse400
    | PostApiV1ExploreFormDataResponse401
    | PostApiV1ExploreFormDataResponse422
    | PostApiV1ExploreFormDataResponse500
    | None
):
    """Create a new form_data

    Args:
        tab_id (int | Unset):
        body (FormDataPostSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostApiV1ExploreFormDataResponse201 | PostApiV1ExploreFormDataResponse400 | PostApiV1ExploreFormDataResponse401 | PostApiV1ExploreFormDataResponse422 | PostApiV1ExploreFormDataResponse500
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
            tab_id=tab_id,
        )
    ).parsed
