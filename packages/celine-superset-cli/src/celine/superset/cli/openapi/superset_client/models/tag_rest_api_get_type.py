from typing import Literal, cast

TagRestApiGetType = Literal[1, 2, 3, 4]

TAG_REST_API_GET_TYPE_VALUES: set[TagRestApiGetType] = {
    1,
    2,
    3,
    4,
}


def check_tag_rest_api_get_type(value: int) -> TagRestApiGetType:
    if value in TAG_REST_API_GET_TYPE_VALUES:
        return cast(TagRestApiGetType, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {TAG_REST_API_GET_TYPE_VALUES!r}")
