from typing import Literal, cast

GetItemSchemaKeysItem = Literal["description_columns", "label_columns", "none", "show_columns", "show_title"]

GET_ITEM_SCHEMA_KEYS_ITEM_VALUES: set[GetItemSchemaKeysItem] = {
    "description_columns",
    "label_columns",
    "none",
    "show_columns",
    "show_title",
}


def check_get_item_schema_keys_item(value: str) -> GetItemSchemaKeysItem:
    if value in GET_ITEM_SCHEMA_KEYS_ITEM_VALUES:
        return cast(GetItemSchemaKeysItem, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {GET_ITEM_SCHEMA_KEYS_ITEM_VALUES!r}")
