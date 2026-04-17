from typing import Literal, cast

GetInfoSchemaKeysItem = Literal[
    "add_columns", "add_title", "edit_columns", "edit_title", "filters", "none", "permissions"
]

GET_INFO_SCHEMA_KEYS_ITEM_VALUES: set[GetInfoSchemaKeysItem] = {
    "add_columns",
    "add_title",
    "edit_columns",
    "edit_title",
    "filters",
    "none",
    "permissions",
}


def check_get_info_schema_keys_item(value: str) -> GetInfoSchemaKeysItem:
    if value in GET_INFO_SCHEMA_KEYS_ITEM_VALUES:
        return cast(GetInfoSchemaKeysItem, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {GET_INFO_SCHEMA_KEYS_ITEM_VALUES!r}")
