from typing import Literal, cast

GetListSchemaOrderDirection = Literal["asc", "desc"]

GET_LIST_SCHEMA_ORDER_DIRECTION_VALUES: set[GetListSchemaOrderDirection] = {
    "asc",
    "desc",
}


def check_get_list_schema_order_direction(value: str) -> GetListSchemaOrderDirection:
    if value in GET_LIST_SCHEMA_ORDER_DIRECTION_VALUES:
        return cast(GetListSchemaOrderDirection, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {GET_LIST_SCHEMA_ORDER_DIRECTION_VALUES!r}")
