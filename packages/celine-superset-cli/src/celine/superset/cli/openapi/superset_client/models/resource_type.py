from typing import Literal, cast

ResourceType = Literal["dashboard"]

RESOURCE_TYPE_VALUES: set[ResourceType] = {
    "dashboard",
}


def check_resource_type(value: str) -> ResourceType:
    if value in RESOURCE_TYPE_VALUES:
        return cast(ResourceType, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {RESOURCE_TYPE_VALUES!r}")
