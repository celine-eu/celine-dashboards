from typing import Literal, cast

FormDataPutSchemaDatasourceType = Literal["dataset", "query", "saved_query", "table", "view"]

FORM_DATA_PUT_SCHEMA_DATASOURCE_TYPE_VALUES: set[FormDataPutSchemaDatasourceType] = {
    "dataset",
    "query",
    "saved_query",
    "table",
    "view",
}


def check_form_data_put_schema_datasource_type(value: str) -> FormDataPutSchemaDatasourceType:
    if value in FORM_DATA_PUT_SCHEMA_DATASOURCE_TYPE_VALUES:
        return cast(FormDataPutSchemaDatasourceType, value)
    raise TypeError(f"Unexpected value {value!r}. Expected one of {FORM_DATA_PUT_SCHEMA_DATASOURCE_TYPE_VALUES!r}")
