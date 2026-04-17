from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.form_data_put_schema import FormDataPutSchema
from ...models.put_api_v1_explore_form_data_key_response_200 import PutApiV1ExploreFormDataKeyResponse200
from ...models.put_api_v1_explore_form_data_key_response_400 import PutApiV1ExploreFormDataKeyResponse400
from ...models.put_api_v1_explore_form_data_key_response_401 import PutApiV1ExploreFormDataKeyResponse401
from ...models.put_api_v1_explore_form_data_key_response_404 import PutApiV1ExploreFormDataKeyResponse404
from ...models.put_api_v1_explore_form_data_key_response_422 import PutApiV1ExploreFormDataKeyResponse422
from ...models.put_api_v1_explore_form_data_key_response_500 import PutApiV1ExploreFormDataKeyResponse500
from ...types import UNSET, Response, Unset


def _get_kwargs(
    key: str,
    *,
    body: FormDataPutSchema,
    tab_id: int | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    params: dict[str, Any] = {}

    params["tab_id"] = tab_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "put",
        "url": "/api/v1/explore/form_data/{key}".format(
            key=quote(str(key), safe=""),
        ),
        "params": params,
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    PutApiV1ExploreFormDataKeyResponse200
    | PutApiV1ExploreFormDataKeyResponse400
    | PutApiV1ExploreFormDataKeyResponse401
    | PutApiV1ExploreFormDataKeyResponse404
    | PutApiV1ExploreFormDataKeyResponse422
    | PutApiV1ExploreFormDataKeyResponse500
    | None
):
    if response.status_code == 200:
        response_200 = PutApiV1ExploreFormDataKeyResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = PutApiV1ExploreFormDataKeyResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = PutApiV1ExploreFormDataKeyResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = PutApiV1ExploreFormDataKeyResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 422:
        response_422 = PutApiV1ExploreFormDataKeyResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = PutApiV1ExploreFormDataKeyResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    PutApiV1ExploreFormDataKeyResponse200
    | PutApiV1ExploreFormDataKeyResponse400
    | PutApiV1ExploreFormDataKeyResponse401
    | PutApiV1ExploreFormDataKeyResponse404
    | PutApiV1ExploreFormDataKeyResponse422
    | PutApiV1ExploreFormDataKeyResponse500
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
    body: FormDataPutSchema,
    tab_id: int | Unset = UNSET,
) -> Response[
    PutApiV1ExploreFormDataKeyResponse200
    | PutApiV1ExploreFormDataKeyResponse400
    | PutApiV1ExploreFormDataKeyResponse401
    | PutApiV1ExploreFormDataKeyResponse404
    | PutApiV1ExploreFormDataKeyResponse422
    | PutApiV1ExploreFormDataKeyResponse500
]:
    """Update an existing form_data

    Args:
        key (str):
        tab_id (int | Unset):
        body (FormDataPutSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PutApiV1ExploreFormDataKeyResponse200 | PutApiV1ExploreFormDataKeyResponse400 | PutApiV1ExploreFormDataKeyResponse401 | PutApiV1ExploreFormDataKeyResponse404 | PutApiV1ExploreFormDataKeyResponse422 | PutApiV1ExploreFormDataKeyResponse500]
    """

    kwargs = _get_kwargs(
        key=key,
        body=body,
        tab_id=tab_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    key: str,
    *,
    client: AuthenticatedClient,
    body: FormDataPutSchema,
    tab_id: int | Unset = UNSET,
) -> (
    PutApiV1ExploreFormDataKeyResponse200
    | PutApiV1ExploreFormDataKeyResponse400
    | PutApiV1ExploreFormDataKeyResponse401
    | PutApiV1ExploreFormDataKeyResponse404
    | PutApiV1ExploreFormDataKeyResponse422
    | PutApiV1ExploreFormDataKeyResponse500
    | None
):
    """Update an existing form_data

    Args:
        key (str):
        tab_id (int | Unset):
        body (FormDataPutSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PutApiV1ExploreFormDataKeyResponse200 | PutApiV1ExploreFormDataKeyResponse400 | PutApiV1ExploreFormDataKeyResponse401 | PutApiV1ExploreFormDataKeyResponse404 | PutApiV1ExploreFormDataKeyResponse422 | PutApiV1ExploreFormDataKeyResponse500
    """

    return sync_detailed(
        key=key,
        client=client,
        body=body,
        tab_id=tab_id,
    ).parsed


async def asyncio_detailed(
    key: str,
    *,
    client: AuthenticatedClient,
    body: FormDataPutSchema,
    tab_id: int | Unset = UNSET,
) -> Response[
    PutApiV1ExploreFormDataKeyResponse200
    | PutApiV1ExploreFormDataKeyResponse400
    | PutApiV1ExploreFormDataKeyResponse401
    | PutApiV1ExploreFormDataKeyResponse404
    | PutApiV1ExploreFormDataKeyResponse422
    | PutApiV1ExploreFormDataKeyResponse500
]:
    """Update an existing form_data

    Args:
        key (str):
        tab_id (int | Unset):
        body (FormDataPutSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PutApiV1ExploreFormDataKeyResponse200 | PutApiV1ExploreFormDataKeyResponse400 | PutApiV1ExploreFormDataKeyResponse401 | PutApiV1ExploreFormDataKeyResponse404 | PutApiV1ExploreFormDataKeyResponse422 | PutApiV1ExploreFormDataKeyResponse500]
    """

    kwargs = _get_kwargs(
        key=key,
        body=body,
        tab_id=tab_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    key: str,
    *,
    client: AuthenticatedClient,
    body: FormDataPutSchema,
    tab_id: int | Unset = UNSET,
) -> (
    PutApiV1ExploreFormDataKeyResponse200
    | PutApiV1ExploreFormDataKeyResponse400
    | PutApiV1ExploreFormDataKeyResponse401
    | PutApiV1ExploreFormDataKeyResponse404
    | PutApiV1ExploreFormDataKeyResponse422
    | PutApiV1ExploreFormDataKeyResponse500
    | None
):
    """Update an existing form_data

    Args:
        key (str):
        tab_id (int | Unset):
        body (FormDataPutSchema):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PutApiV1ExploreFormDataKeyResponse200 | PutApiV1ExploreFormDataKeyResponse400 | PutApiV1ExploreFormDataKeyResponse401 | PutApiV1ExploreFormDataKeyResponse404 | PutApiV1ExploreFormDataKeyResponse422 | PutApiV1ExploreFormDataKeyResponse500
    """

    return (
        await asyncio_detailed(
            key=key,
            client=client,
            body=body,
            tab_id=tab_id,
        )
    ).parsed
