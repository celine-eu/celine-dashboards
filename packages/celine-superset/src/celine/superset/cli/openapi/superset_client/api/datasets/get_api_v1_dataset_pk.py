from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_api_v1_dataset_pk_response_200 import GetApiV1DatasetPkResponse200
from ...models.get_api_v1_dataset_pk_response_400 import GetApiV1DatasetPkResponse400
from ...models.get_api_v1_dataset_pk_response_401 import GetApiV1DatasetPkResponse401
from ...models.get_api_v1_dataset_pk_response_422 import GetApiV1DatasetPkResponse422
from ...models.get_api_v1_dataset_pk_response_500 import GetApiV1DatasetPkResponse500
from ...types import UNSET, Response, Unset


def _get_kwargs(
    pk: int,
    *,
    include_rendered_sql: bool | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["include_rendered_sql"] = include_rendered_sql

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/dataset/{pk}".format(
            pk=quote(str(pk), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetApiV1DatasetPkResponse200
    | GetApiV1DatasetPkResponse400
    | GetApiV1DatasetPkResponse401
    | GetApiV1DatasetPkResponse422
    | GetApiV1DatasetPkResponse500
    | None
):
    if response.status_code == 200:
        response_200 = GetApiV1DatasetPkResponse200.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = GetApiV1DatasetPkResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = GetApiV1DatasetPkResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 422:
        response_422 = GetApiV1DatasetPkResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = GetApiV1DatasetPkResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    GetApiV1DatasetPkResponse200
    | GetApiV1DatasetPkResponse400
    | GetApiV1DatasetPkResponse401
    | GetApiV1DatasetPkResponse422
    | GetApiV1DatasetPkResponse500
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
    include_rendered_sql: bool | Unset = UNSET,
) -> Response[
    GetApiV1DatasetPkResponse200
    | GetApiV1DatasetPkResponse400
    | GetApiV1DatasetPkResponse401
    | GetApiV1DatasetPkResponse422
    | GetApiV1DatasetPkResponse500
]:
    """Get a dataset

     Get a dataset by ID

    Args:
        pk (int):
        include_rendered_sql (bool | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1DatasetPkResponse200 | GetApiV1DatasetPkResponse400 | GetApiV1DatasetPkResponse401 | GetApiV1DatasetPkResponse422 | GetApiV1DatasetPkResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
        include_rendered_sql=include_rendered_sql,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    pk: int,
    *,
    client: AuthenticatedClient,
    include_rendered_sql: bool | Unset = UNSET,
) -> (
    GetApiV1DatasetPkResponse200
    | GetApiV1DatasetPkResponse400
    | GetApiV1DatasetPkResponse401
    | GetApiV1DatasetPkResponse422
    | GetApiV1DatasetPkResponse500
    | None
):
    """Get a dataset

     Get a dataset by ID

    Args:
        pk (int):
        include_rendered_sql (bool | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1DatasetPkResponse200 | GetApiV1DatasetPkResponse400 | GetApiV1DatasetPkResponse401 | GetApiV1DatasetPkResponse422 | GetApiV1DatasetPkResponse500
    """

    return sync_detailed(
        pk=pk,
        client=client,
        include_rendered_sql=include_rendered_sql,
    ).parsed


async def asyncio_detailed(
    pk: int,
    *,
    client: AuthenticatedClient,
    include_rendered_sql: bool | Unset = UNSET,
) -> Response[
    GetApiV1DatasetPkResponse200
    | GetApiV1DatasetPkResponse400
    | GetApiV1DatasetPkResponse401
    | GetApiV1DatasetPkResponse422
    | GetApiV1DatasetPkResponse500
]:
    """Get a dataset

     Get a dataset by ID

    Args:
        pk (int):
        include_rendered_sql (bool | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetApiV1DatasetPkResponse200 | GetApiV1DatasetPkResponse400 | GetApiV1DatasetPkResponse401 | GetApiV1DatasetPkResponse422 | GetApiV1DatasetPkResponse500]
    """

    kwargs = _get_kwargs(
        pk=pk,
        include_rendered_sql=include_rendered_sql,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    pk: int,
    *,
    client: AuthenticatedClient,
    include_rendered_sql: bool | Unset = UNSET,
) -> (
    GetApiV1DatasetPkResponse200
    | GetApiV1DatasetPkResponse400
    | GetApiV1DatasetPkResponse401
    | GetApiV1DatasetPkResponse422
    | GetApiV1DatasetPkResponse500
    | None
):
    """Get a dataset

     Get a dataset by ID

    Args:
        pk (int):
        include_rendered_sql (bool | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetApiV1DatasetPkResponse200 | GetApiV1DatasetPkResponse400 | GetApiV1DatasetPkResponse401 | GetApiV1DatasetPkResponse422 | GetApiV1DatasetPkResponse500
    """

    return (
        await asyncio_detailed(
            pk=pk,
            client=client,
            include_rendered_sql=include_rendered_sql,
        )
    ).parsed
