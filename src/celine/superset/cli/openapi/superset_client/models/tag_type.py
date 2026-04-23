from typing import Literal, cast

TagType = Literal[1, 2, 3, 4]

TAG_TYPE_VALUES: set[TagType] = {
    1,
    2,
    3,
    4,
}


def check_tag_type(value: int) -> TagType:
    if value in TAG_TYPE_VALUES:
        return cast(TagType, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {TAG_TYPE_VALUES!r}")
