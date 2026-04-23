from typing import Literal, cast

FormDataPostSchemaDatasourceType = Literal["dataset", "query", "saved_query", "table", "view"]

FORM_DATA_POST_SCHEMA_DATASOURCE_TYPE_VALUES: set[FormDataPostSchemaDatasourceType] = {
    "dataset",
    "query",
    "saved_query",
    "table",
    "view",
}


def check_form_data_post_schema_datasource_type(value: str) -> FormDataPostSchemaDatasourceType:
    if value in FORM_DATA_POST_SCHEMA_DATASOURCE_TYPE_VALUES:
        return cast(FormDataPostSchemaDatasourceType, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {FORM_DATA_POST_SCHEMA_DATASOURCE_TYPE_VALUES!r}")
