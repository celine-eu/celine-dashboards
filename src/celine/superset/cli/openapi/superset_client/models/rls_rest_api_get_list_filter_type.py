from typing import Literal, cast

RLSRestApiGetListFilterType = Literal["Base", "Regular"]

RLS_REST_API_GET_LIST_FILTER_TYPE_VALUES: set[RLSRestApiGetListFilterType] = {
    "Base",
    "Regular",
}


def check_rls_rest_api_get_list_filter_type(value: str) -> RLSRestApiGetListFilterType:
    if value in RLS_REST_API_GET_LIST_FILTER_TYPE_VALUES:
        return cast(RLSRestApiGetListFilterType, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {RLS_REST_API_GET_LIST_FILTER_TYPE_VALUES!r}")
