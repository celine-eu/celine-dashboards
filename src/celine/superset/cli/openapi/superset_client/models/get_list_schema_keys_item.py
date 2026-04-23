from typing import Literal, cast

GetListSchemaKeysItem = Literal[
    "description_columns", "label_columns", "list_columns", "list_title", "none", "order_columns"
]

GET_LIST_SCHEMA_KEYS_ITEM_VALUES: set[GetListSchemaKeysItem] = {
    "description_columns",
    "label_columns",
    "list_columns",
    "list_title",
    "none",
    "order_columns",
}


def check_get_list_schema_keys_item(value: str) -> GetListSchemaKeysItem:
    if value in GET_LIST_SCHEMA_KEYS_ITEM_VALUES:
        return cast(GetListSchemaKeysItem, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {GET_LIST_SCHEMA_KEYS_ITEM_VALUES!r}")
