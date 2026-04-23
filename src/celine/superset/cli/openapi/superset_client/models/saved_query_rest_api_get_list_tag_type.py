from typing import Literal, cast

SavedQueryRestApiGetListTagType = Literal[1, 2, 3, 4]

SAVED_QUERY_REST_API_GET_LIST_TAG_TYPE_VALUES: set[SavedQueryRestApiGetListTagType] = {
    1,
    2,
    3,
    4,
}


def check_saved_query_rest_api_get_list_tag_type(value: int) -> SavedQueryRestApiGetListTagType:
    if value in SAVED_QUERY_REST_API_GET_LIST_TAG_TYPE_VALUES:
        return cast(SavedQueryRestApiGetListTagType, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {SAVED_QUERY_REST_API_GET_LIST_TAG_TYPE_VALUES!r}")
