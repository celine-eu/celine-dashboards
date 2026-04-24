from typing import Literal, cast

Tag1Type = Literal[1, 2, 3, 4]

TAG_1_TYPE_VALUES: set[Tag1Type] = {
    1,
    2,
    3,
    4,
}


def check_tag_1_type(value: int) -> Tag1Type:
    if value in TAG_1_TYPE_VALUES:
        return cast(Tag1Type, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {TAG_1_TYPE_VALUES!r}")
