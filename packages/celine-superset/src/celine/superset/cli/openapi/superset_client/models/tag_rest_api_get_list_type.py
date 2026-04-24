from typing import Literal, cast

TagRestApiGetListType = Literal[1, 2, 3, 4]

TAG_REST_API_GET_LIST_TYPE_VALUES: set[TagRestApiGetListType] = {
    1,
    2,
    3,
    4,
}


def check_tag_rest_api_get_list_type(value: int) -> TagRestApiGetListType:
    if value in TAG_REST_API_GET_LIST_TYPE_VALUES:
        return cast(TagRestApiGetListType, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {TAG_REST_API_GET_LIST_TYPE_VALUES!r}")
