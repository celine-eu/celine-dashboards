from typing import Literal, cast

RLSRestApiPutFilterType = Literal["Base", "Regular"]

RLS_REST_API_PUT_FILTER_TYPE_VALUES: set[RLSRestApiPutFilterType] = {
    "Base",
    "Regular",
}


def check_rls_rest_api_put_filter_type(value: str) -> RLSRestApiPutFilterType:
    if value in RLS_REST_API_PUT_FILTER_TYPE_VALUES:
        return cast(RLSRestApiPutFilterType, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {RLS_REST_API_PUT_FILTER_TYPE_VALUES!r}")
