from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.explore_context_schema import ExploreContextSchema
from ...models.get_api_v1_explore_response_400 import GetApiV1ExploreResponse400
from ...models.get_api_v1_explore_response_401 import GetApiV1ExploreResponse401
from ...models.get_api_v1_explore_response_404 import GetApiV1ExploreResponse404
from ...models.get_api_v1_explore_response_422 import GetApiV1ExploreResponse422
from ...models.get_api_v1_explore_response_500 import GetApiV1ExploreResponse500
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    form_data_key: str | Unset = UNSET,
    permalink_key: str | Unset = UNSET,
    slice_id: int | Unset = UNSET,
    datasource_id: int | Unset = UNSET,
    datasource_type: str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["form_data_key"] = form_data_key

    params["permalink_key"] = permalink_key

    params["slice_id"] = slice_id

    params["datasource_id"] = datasource_id

    params["datasource_type"] = datasource_type

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/explore/",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    ExploreContextSchema
    | GetApiV1ExploreResponse400
    | GetApiV1ExploreResponse401
    | GetApiV1ExploreResponse404
    | GetApiV1ExploreResponse422
    | GetApiV1ExploreResponse500
    | None
):
    if response.status_code == 200:
        response_200 = ExploreContextSchema.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = GetApiV1ExploreResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = GetApiV1ExploreResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 404:
        response_404 = GetApiV1ExploreResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 422:
        response_422 = GetApiV1ExploreResponse422.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = GetApiV1ExploreResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    ExploreContextSchema
    | GetApiV1ExploreResponse400
    | GetApiV1ExploreResponse401
    | GetApiV1ExploreResponse404
    | GetApiV1ExploreResponse422
    | GetApiV1ExploreResponse500
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
    form_data_key: str | Unset = UNSET,
    permalink_key: str | Unset = UNSET,
    slice_id: int | Unset = UNSET,
    datasource_id: int | Unset = UNSET,
    datasource_type: str | Unset = UNSET,
) -> Response[
    ExploreContextSchema
    | GetApiV1ExploreResponse400
    | GetApiV1ExploreResponse401
    | GetApiV1ExploreResponse404
    | GetApiV1ExploreResponse422
    | GetApiV1ExploreResponse500
]:
    """Assemble Explore related information in a single endpoint

     Assembles Explore related information (form_data, slice, dataset) in a single endpoint.<br/><br/>
    The information can be assembled from:<br/> - The cache using a form_data_key<br/> - The metadata
    database using a permalink_key<br/> - Build from scratch using dataset or slice identifiers.

    Args:
        form_data_key (str | Unset):
        permalink_key (str | Unset):
        slice_id (int | Unset):
        datasource_id (int | Unset):
        datasource_type (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ExploreContextSchema | GetApiV1ExploreResponse400 | GetApiV1ExploreResponse401 | GetApiV1ExploreResponse404 | GetApiV1ExploreResponse422 | GetApiV1ExploreResponse500]
    """

    kwargs = _get_kwargs(
        form_data_key=form_data_key,
        permalink_key=permalink_key,
        slice_id=slice_id,
        datasource_id=datasource_id,
        datasource_type=datasource_type,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    form_data_key: str | Unset = UNSET,
    permalink_key: str | Unset = UNSET,
    slice_id: int | Unset = UNSET,
    datasource_id: int | Unset = UNSET,
    datasource_type: str | Unset = UNSET,
) -> (
    ExploreContextSchema
    | GetApiV1ExploreResponse400
    | GetApiV1ExploreResponse401
    | GetApiV1ExploreResponse404
    | GetApiV1ExploreResponse422
    | GetApiV1ExploreResponse500
    | None
):
    """Assemble Explore related information in a single endpoint

     Assembles Explore related information (form_data, slice, dataset) in a single endpoint.<br/><br/>
    The information can be assembled from:<br/> - The cache using a form_data_key<br/> - The metadata
    database using a permalink_key<br/> - Build from scratch using dataset or slice identifiers.

    Args:
        form_data_key (str | Unset):
        permalink_key (str | Unset):
        slice_id (int | Unset):
        datasource_id (int | Unset):
        datasource_type (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ExploreContextSchema | GetApiV1ExploreResponse400 | GetApiV1ExploreResponse401 | GetApiV1ExploreResponse404 | GetApiV1ExploreResponse422 | GetApiV1ExploreResponse500
    """

    return sync_detailed(
        client=client,
        form_data_key=form_data_key,
        permalink_key=permalink_key,
        slice_id=slice_id,
        datasource_id=datasource_id,
        datasource_type=datasource_type,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    form_data_key: str | Unset = UNSET,
    permalink_key: str | Unset = UNSET,
    slice_id: int | Unset = UNSET,
    datasource_id: int | Unset = UNSET,
    datasource_type: str | Unset = UNSET,
) -> Response[
    ExploreContextSchema
    | GetApiV1ExploreResponse400
    | GetApiV1ExploreResponse401
    | GetApiV1ExploreResponse404
    | GetApiV1ExploreResponse422
    | GetApiV1ExploreResponse500
]:
    """Assemble Explore related information in a single endpoint

     Assembles Explore related information (form_data, slice, dataset) in a single endpoint.<br/><br/>
    The information can be assembled from:<br/> - The cache using a form_data_key<br/> - The metadata
    database using a permalink_key<br/> - Build from scratch using dataset or slice identifiers.

    Args:
        form_data_key (str | Unset):
        permalink_key (str | Unset):
        slice_id (int | Unset):
        datasource_id (int | Unset):
        datasource_type (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ExploreContextSchema | GetApiV1ExploreResponse400 | GetApiV1ExploreResponse401 | GetApiV1ExploreResponse404 | GetApiV1ExploreResponse422 | GetApiV1ExploreResponse500]
    """

    kwargs = _get_kwargs(
        form_data_key=form_data_key,
        permalink_key=permalink_key,
        slice_id=slice_id,
        datasource_id=datasource_id,
        datasource_type=datasource_type,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    form_data_key: str | Unset = UNSET,
    permalink_key: str | Unset = UNSET,
    slice_id: int | Unset = UNSET,
    datasource_id: int | Unset = UNSET,
    datasource_type: str | Unset = UNSET,
) -> (
    ExploreContextSchema
    | GetApiV1ExploreResponse400
    | GetApiV1ExploreResponse401
    | GetApiV1ExploreResponse404
    | GetApiV1ExploreResponse422
    | GetApiV1ExploreResponse500
    | None
):
    """Assemble Explore related information in a single endpoint

     Assembles Explore related information (form_data, slice, dataset) in a single endpoint.<br/><br/>
    The information can be assembled from:<br/> - The cache using a form_data_key<br/> - The metadata
    database using a permalink_key<br/> - Build from scratch using dataset or slice identifiers.

    Args:
        form_data_key (str | Unset):
        permalink_key (str | Unset):
        slice_id (int | Unset):
        datasource_id (int | Unset):
        datasource_type (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ExploreContextSchema | GetApiV1ExploreResponse400 | GetApiV1ExploreResponse401 | GetApiV1ExploreResponse404 | GetApiV1ExploreResponse422 | GetApiV1ExploreResponse500
    """

    return (
        await asyncio_detailed(
            client=client,
            form_data_key=form_data_key,
            permalink_key=permalink_key,
            slice_id=slice_id,
            datasource_id=datasource_id,
            datasource_type=datasource_type,
        )
    ).parsed
