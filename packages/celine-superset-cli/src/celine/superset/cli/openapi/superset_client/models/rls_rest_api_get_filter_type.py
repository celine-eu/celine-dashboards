from typing import Literal, cast

RLSRestApiGetFilterType = Literal["Base", "Regular"]

RLS_REST_API_GET_FILTER_TYPE_VALUES: set[RLSRestApiGetFilterType] = {
    "Base",
    "Regular",
}


def check_rls_rest_api_get_filter_type(value: str) -> RLSRestApiGetFilterType:
    if value in RLS_REST_API_GET_FILTER_TYPE_VALUES:
        return cast(RLSRestApiGetFilterType, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {RLS_REST_API_GET_FILTER_TYPE_VALUES!r}")
