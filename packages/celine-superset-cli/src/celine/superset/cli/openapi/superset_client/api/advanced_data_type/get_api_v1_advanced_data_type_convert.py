from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.advanced_data_type_schema import AdvancedDataTypeSchema
from ...models.get_api_v1_advanced_data_type_convert_response_400 import GetApiV1AdvancedDataTypeConvertResponse400
from ...models.get_api_v1_advanced_data_type_convert_response_401 import GetApiV1AdvancedDataTypeConvertResponse401
from ...models.get_api_v1_advanced_data_type_convert_response_403 import GetApiV1AdvancedDataTypeConvertResponse403
from ...models.get_api_v1_advanced_data_type_convert_response_404 import GetApiV1AdvancedDataTypeConvertResponse404
from ...models.get_api_v1_advanced_data_type_convert_response_500 import GetApiV1AdvancedDataTypeConvertResponse500
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/advanced_data_type/convert",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    AdvancedDataTypeSchema
    | GetApiV1AdvancedDataTypeConvertResponse400
    | GetApiV1AdvancedDataTypeConvertResponse401
    | GetApiV1AdvancedDataTypeConvertResponse403
    | GetApiV1AdvancedDataTypeConvertResponse404
    | GetApiV1AdvancedDataTypeConvertResponse500
    | None
):
    if response.status_code == 200:
        response_200 = AdvancedDataTypeSchema.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = GetApiV1AdvancedDataTypeConvertResponse400.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = GetApiV1AdvancedDataTypeConvertResponse401.from_dict(response.json())

        return response_401

    if response.status_code == 403:
        response_403 = GetApiV1AdvancedDataTypeConvertResponse403.from_dict(response.json())

        return response_403

    if response.status_code == 404:
        response_404 = GetApiV1AdvancedDataTypeConvertResponse404.from_dict(response.json())

        return response_404

    if response.status_code == 500:
        response_500 = GetApiV1AdvancedDataTypeConvertResponse500.from_dict(response.json())

        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[
    AdvancedDataTypeSchema
    | GetApiV1AdvancedDataTypeConvertResponse400
    | GetApiV1AdvancedDataTypeConvertResponse401
    | GetApiV1AdvancedDataTypeConvertResponse403
    | GetApiV1AdvancedDataTypeConvertResponse404
    | GetApiV1AdvancedDataTypeConvertResponse500
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
    AdvancedDataTypeSchema
    | GetApiV1AdvancedDataTypeConvertResponse400
    | GetApiV1AdvancedDataTypeConvertResponse401
    | GetApiV1AdvancedDataTypeConvertResponse403
    | GetApiV1AdvancedDataTypeConvertResponse404
    | GetApiV1AdvancedDataTypeConvertResponse500
]:
    """Return an AdvancedDataTypeResponse

     Returns an AdvancedDataTypeResponse object populated with the passed in args.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AdvancedDataTypeSchema | GetApiV1AdvancedDataTypeConvertResponse400 | GetApiV1AdvancedDataTypeConvertResponse401 | GetApiV1AdvancedDataTypeConvertResponse403 | GetApiV1AdvancedDataTypeConvertResponse404 | GetApiV1AdvancedDataTypeConvertResponse500]
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
    AdvancedDataTypeSchema
    | GetApiV1AdvancedDataTypeConvertResponse400
    | GetApiV1AdvancedDataTypeConvertResponse401
    | GetApiV1AdvancedDataTypeConvertResponse403
    | GetApiV1AdvancedDataTypeConvertResponse404
    | GetApiV1AdvancedDataTypeConvertResponse500
    | None
):
    """Return an AdvancedDataTypeResponse

     Returns an AdvancedDataTypeResponse object populated with the passed in args.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AdvancedDataTypeSchema | GetApiV1AdvancedDataTypeConvertResponse400 | GetApiV1AdvancedDataTypeConvertResponse401 | GetApiV1AdvancedDataTypeConvertResponse403 | GetApiV1AdvancedDataTypeConvertResponse404 | GetApiV1AdvancedDataTypeConvertResponse500
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[
    AdvancedDataTypeSchema
    | GetApiV1AdvancedDataTypeConvertResponse400
    | GetApiV1AdvancedDataTypeConvertResponse401
    | GetApiV1AdvancedDataTypeConvertResponse403
    | GetApiV1AdvancedDataTypeConvertResponse404
    | GetApiV1AdvancedDataTypeConvertResponse500
]:
    """Return an AdvancedDataTypeResponse

     Returns an AdvancedDataTypeResponse object populated with the passed in args.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AdvancedDataTypeSchema | GetApiV1AdvancedDataTypeConvertResponse400 | GetApiV1AdvancedDataTypeConvertResponse401 | GetApiV1AdvancedDataTypeConvertResponse403 | GetApiV1AdvancedDataTypeConvertResponse404 | GetApiV1AdvancedDataTypeConvertResponse500]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> (
    AdvancedDataTypeSchema
    | GetApiV1AdvancedDataTypeConvertResponse400
    | GetApiV1AdvancedDataTypeConvertResponse401
    | GetApiV1AdvancedDataTypeConvertResponse403
    | GetApiV1AdvancedDataTypeConvertResponse404
    | GetApiV1AdvancedDataTypeConvertResponse500
    | None
):
    """Return an AdvancedDataTypeResponse

     Returns an AdvancedDataTypeResponse object populated with the passed in args.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AdvancedDataTypeSchema | GetApiV1AdvancedDataTypeConvertResponse400 | GetApiV1AdvancedDataTypeConvertResponse401 | GetApiV1AdvancedDataTypeConvertResponse403 | GetApiV1AdvancedDataTypeConvertResponse404 | GetApiV1AdvancedDataTypeConvertResponse500
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
