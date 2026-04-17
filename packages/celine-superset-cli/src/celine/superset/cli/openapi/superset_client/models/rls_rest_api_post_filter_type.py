from typing import Literal, cast

RLSRestApiPostFilterType = Literal["Base", "Regular"]

RLS_REST_API_POST_FILTER_TYPE_VALUES: set[RLSRestApiPostFilterType] = {
    "Base",
    "Regular",
}


def check_rls_rest_api_post_filter_type(value: str) -> RLSRestApiPostFilterType:
    if value in RLS_REST_API_POST_FILTER_TYPE_VALUES:
        return cast(RLSRestApiPostFilterType, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {RLS_REST_API_POST_FILTER_TYPE_VALUES!r}")
